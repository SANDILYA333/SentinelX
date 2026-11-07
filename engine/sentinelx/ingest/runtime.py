"""SentinelX Ingestion Runtime.

Wires async file tailers -> format adapters -> normalizer/enricher -> batch DB writer -> event broadcaster.
Supports live streaming and chronological deterministic replay modes.
"""

import asyncio
import inspect
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Literal

from sentinelx.ingest.adapters.base import get_adapter
from sentinelx.ingest.tailer import AsyncFileTailer, CheckpointManager, SourceContext
from sentinelx.normalize.enricher import EventEnricher
from sentinelx.schemas.common import SourceTool
from sentinelx.schemas.event import Event
from sentinelx.store.sqlite import (
    get_event_by_id,
    get_stats,
    init_db,
    insert_events_batch,
    list_events,
)

logger = logging.getLogger(__name__)


@dataclass
class SourceConfig:
    """Configuration mapping a relative file path under log_root to an adapter."""

    source_key: str
    source_tool: str
    relative_path: str
    adapter_name: str
    zone: str | None = None
    expected_active: bool = False


DEFAULT_SOURCES: list[SourceConfig] = [
    SourceConfig(
        source_key="wazuh",
        source_tool=SourceTool.wazuh.value,
        relative_path="wazuh/archives.json",
        adapter_name="wazuh_archives",
        expected_active=True,
    ),
    SourceConfig(
        source_key="zeek_it_conn",
        source_tool=SourceTool.zeek.value,
        relative_path="zeek-it/conn.log",
        adapter_name="zeek_conn",
        zone="it",
        expected_active=True,
    ),
    SourceConfig(
        source_key="zeek_it_dns",
        source_tool=SourceTool.zeek.value,
        relative_path="zeek-it/dns.log",
        adapter_name="zeek_dns",
        zone="it",
        expected_active=False,
    ),
    SourceConfig(
        source_key="zeek_dmz_conn",
        source_tool=SourceTool.zeek.value,
        relative_path="zeek-dmz/conn.log",
        adapter_name="zeek_conn",
        zone="dmz",
        expected_active=False,
    ),
    SourceConfig(
        source_key="zeek_dmz_dns",
        source_tool=SourceTool.zeek.value,
        relative_path="zeek-dmz/dns.log",
        adapter_name="zeek_dns",
        zone="dmz",
        expected_active=False,
    ),
    SourceConfig(
        source_key="zeek_ot_conn",
        source_tool=SourceTool.zeek.value,
        relative_path="zeek-ot/conn.log",
        adapter_name="zeek_conn",
        zone="ot",
        expected_active=True,
    ),
    SourceConfig(
        source_key="zeek_ot_dns",
        source_tool=SourceTool.zeek.value,
        relative_path="zeek-ot/dns.log",
        adapter_name="zeek_dns",
        zone="ot",
        expected_active=False,
    ),
    SourceConfig(
        source_key="zeek_ot_modbus",
        source_tool=SourceTool.zeek.value,
        relative_path="zeek-ot/modbus.log",
        adapter_name="zeek_modbus",
        zone="ot",
        expected_active=True,
    ),
    SourceConfig(
        source_key="cowrie",
        source_tool=SourceTool.cowrie.value,
        relative_path="cowrie/cowrie.json",
        adapter_name="cowrie",
        zone="dmz",
        expected_active=False,
    ),
    SourceConfig(
        source_key="opencanary",
        source_tool=SourceTool.opencanary.value,
        relative_path="opencanary/opencanary.log",
        adapter_name="opencanary",
        zone="dmz",
        expected_active=False,
    ),
    SourceConfig(
        source_key="plc_sim_writes",
        source_tool=SourceTool.modbus.value,
        relative_path="plc/plc-sim-writes.jsonl",
        adapter_name="plc_writes",
        zone="ot",
        expected_active=True,
    ),
    SourceConfig(
        source_key="plc_sim_state",
        source_tool=SourceTool.modbus.value,
        relative_path="plc/plc-sim-state.jsonl",
        adapter_name="plc_state",
        zone="ot",
        expected_active=True,
    ),
    SourceConfig(
        source_key="decoy_plc",
        source_tool=SourceTool.modbus.value,
        relative_path="plc/decoy-plc.jsonl",
        adapter_name="decoy_plc",
        zone="ot",
        expected_active=False,
    ),
]


@dataclass
class SourceMetrics:
    """Tracks per-source ingestion counters, errors, and health state."""

    source_key: str
    source_tool: str
    relative_path: str
    expected_active: bool = False
    lines_read: int = 0
    events_emitted: int = 0
    ignored: dict[str, int] = field(default_factory=dict)
    unparsed: int = 0
    errors: int = 0
    last_event_ts: datetime | None = None
    last_error: str | None = None

    def record_ignored(self, reason: str) -> None:
        self.ignored[reason] = self.ignored.get(reason, 0) + 1

    def compute_status(self, now: datetime, file_exists: bool) -> str:
        if self.errors > 0 and self.last_error:
            return "error"

        if not file_exists and not self.last_event_ts:
            return "stale" if self.expected_active else "idle"

        if self.last_event_ts:
            age = (now - self.last_event_ts).total_seconds()
            if age <= 30.0:
                return "live"
            if self.expected_active and age > 300.0:
                return "stale"
            return "idle"

        return "stale" if self.expected_active else "idle"

    def to_dict(self, now: datetime, file_exists: bool) -> dict[str, Any]:
        status = self.compute_status(now, file_exists)
        last_event_age = (
            round((now - self.last_event_ts).total_seconds(), 1) if self.last_event_ts else None
        )
        return {
            "source_key": self.source_key,
            "source_tool": self.source_tool,
            "relative_path": self.relative_path,
            "status": status,
            "expected_active": self.expected_active,
            "lines_read": self.lines_read,
            "events_emitted": self.events_emitted,
            "ignored": self.ignored,
            "unparsed": self.unparsed,
            "errors": self.errors,
            "last_event_ts": self.last_event_ts.isoformat() if self.last_event_ts else None,
            "last_event_age_sec": last_event_age,
            "last_error": self.last_error,
        }


class UnparsedLogger:
    """Maintains a capped circular buffer (last 200) of unparsed lines on disk."""

    def __init__(self, file_path: Path, max_lines: int = 200):
        self.file_path = file_path
        self.max_lines = max_lines
        self._buffer: list[dict[str, Any]] = []

    def record(self, source_key: str, line: str, reason: str) -> None:
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "source_key": source_key,
            "reason": reason,
            "line": line[:1000],
        }
        self._buffer.append(entry)
        if len(self._buffer) > self.max_lines:
            self._buffer.pop(0)

        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.file_path, "w", encoding="utf-8") as f:
                for item in self._buffer:
                    f.write(json.dumps(item) + "\n")
        except OSError:
            pass


class Ingestor:
    """Telemetry pipeline coordinator running either live tailing or replay."""

    def __init__(
        self,
        log_root: str | Path = "./data/logs",
        db: sqlite3.Connection | str | Path = "./data/sentinelx.db",
        mode: Literal["live", "replay", "off"] = "off",
        on_event: Callable[[Event], Any] | None = None,
        speed: float | str = 1.0,
        sources: list[SourceConfig] | None = None,
    ):
        self.log_root = Path(log_root).resolve()
        if isinstance(db, sqlite3.Connection):
            self.db = db
            self._owns_db = False
            self.db_path = Path("./data/sentinelx.db")
        else:
            self.db_path = Path(db).resolve()
            self.db = init_db(self.db_path)
            self._owns_db = True

        self.mode = mode
        self.on_event = on_event
        self.speed = float(speed) if str(speed).lower() != "max" else 999999.0
        self.is_max_speed = str(speed).lower() == "max"
        self.sources = sources or DEFAULT_SOURCES

        self.enricher = EventEnricher()
        self.checkpoint_mgr = CheckpointManager(self.db_path)
        self.unparsed_logger = UnparsedLogger(self.log_root.parent / "ingest_unparsed.jsonl")

        self.metrics: dict[str, SourceMetrics] = {}
        for cfg in self.sources:
            self.metrics[cfg.source_key] = SourceMetrics(
                source_key=cfg.source_key,
                source_tool=cfg.source_tool,
                relative_path=cfg.relative_path,
                expected_active=cfg.expected_active,
            )

        self.running: bool = False
        self._tasks: list[asyncio.Task] = []
        self._batch_queue: asyncio.Queue[Event] = asyncio.Queue()
        self._writer_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the ingestion pipeline according to configured mode."""
        if self.mode == "off":
            logger.info("Ingestor mode is 'off'; standing by.")
            return

        self.running = True
        self._writer_task = asyncio.create_task(self._batch_writer_loop())

        if self.mode == "live":
            logger.info("Starting Ingestor in LIVE tailing mode...")
            for cfg in self.sources:
                file_path = self.log_root / cfg.relative_path
                tailer = AsyncFileTailer(
                    file_path=file_path,
                    source_key=cfg.source_key,
                    source_tool=cfg.source_tool,
                    mode="from_start",
                    zone=cfg.zone,
                    checkpoint_mgr=self.checkpoint_mgr,
                    poll_interval=0.5,
                )
                task = asyncio.create_task(self._tail_source_loop(cfg, tailer))
                self._tasks.append(task)
        elif self.mode == "replay":
            logger.info(f"Starting Ingestor in REPLAY mode at speed {self.speed}x...")
            task = asyncio.create_task(self._run_replay())
            self._tasks.append(task)

    async def stop(self) -> None:
        """Gracefully stop tailing, wait for pending batch write, and flush."""
        self.running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        if self._writer_task:
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass
            self._writer_task = None

        # Final drain of remaining queue items
        await self._flush_queue_drain()

        if self._owns_db:
            try:
                self.db.close()
            except Exception:
                pass

    async def _tail_source_loop(self, cfg: SourceConfig, tailer: AsyncFileTailer) -> None:
        """Async tailing loop for a single source file."""
        adapter = get_adapter(cfg.adapter_name)
        metric = self.metrics[cfg.source_key]

        try:
            async for line, ctx in tailer.tail_lines():
                if not self.running:
                    break

                metric.lines_read += 1
                try:
                    events = adapter.parse(line, ctx)
                except Exception as exc:
                    metric.unparsed += 1
                    self.unparsed_logger.record(cfg.source_key, line, f"adapter_exception: {exc}")
                    continue

                if events is None:
                    reason = (
                        getattr(adapter, "last_ignore_reason", None)
                        or ctx.ignore_reason
                        or "ignored"
                    )
                    metric.record_ignored(reason)
                    continue

                for raw_ev in events:
                    try:
                        enriched_ev = self.enricher.enrich(raw_ev)
                        metric.events_emitted += 1
                        metric.last_event_ts = datetime.now(UTC)
                        await self._batch_queue.put(enriched_ev)
                    except Exception as exc:
                        metric.errors += 1
                        metric.last_error = f"enrich_error: {exc}"
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            metric.errors += 1
            metric.last_error = f"tailer_fatal: {exc}"
            logger.error(f"Fatal tailer error on {cfg.source_key}: {exc}", exc_info=True)

    async def _batch_writer_loop(self) -> None:
        """Batches inserts (100 events or 200ms timeout) into SQLite and invokes broadcaster."""
        batch: list[Event] = []
        last_flush = time.monotonic()

        while self.running:
            try:
                timeout = max(0.01, 0.2 - (time.monotonic() - last_flush))
                try:
                    ev = await asyncio.wait_for(self._batch_queue.get(), timeout=timeout)
                    batch.append(ev)
                    self._batch_queue.task_done()
                except asyncio.TimeoutError:
                    pass

                # Flush condition: 100 items or 200 ms elapsed
                if batch and (len(batch) >= 100 or (time.monotonic() - last_flush) >= 0.2):
                    self._flush_batch(batch)
                    batch = []
                    last_flush = time.monotonic()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"Error in batch writer loop: {exc}", exc_info=True)
                await asyncio.sleep(0.1)

        if batch:
            self._flush_batch(batch)

    def _flush_batch(self, batch: list[Event]) -> None:
        """Synchronously execute SQLite batch insert and invoke event broadcast callback."""
        if not batch:
            return
        insert_events_batch(self.db, batch)

        if self.on_event:
            for ev in batch:
                try:
                    res = self.on_event(ev)
                    if inspect.iscoroutine(res):
                        asyncio.create_task(res)
                except Exception as exc:
                    logger.warning(f"Broadcast callback error: {exc}", exc_info=True)

    async def _flush_queue_drain(self) -> None:
        """Drains any leftover events from the queue into the DB."""
        leftovers: list[Event] = []
        while not self._batch_queue.empty():
            try:
                leftovers.append(self._batch_queue.get_nowait())
                self._batch_queue.task_done()
            except asyncio.QueueEmpty:
                break
        if leftovers:
            self._flush_batch(leftovers)

    async def _run_replay(self) -> None:
        """Chronologically replays existing log files from log_root."""
        all_events: list[tuple[datetime, Event]] = []

        logger.info(f"Collecting events across all sources from root {self.log_root}...")
        for cfg in self.sources:
            file_path = self.log_root / cfg.relative_path
            if not file_path.exists():
                continue

            adapter = get_adapter(cfg.adapter_name)
            metric = self.metrics[cfg.source_key]

            try:
                with open(file_path, "rb") as f:
                    offset = 0
                    line_no = 0
                    for raw_bytes in f:
                        line_offset = offset
                        offset += len(raw_bytes)
                        line_no += 1
                        metric.lines_read += 1

                        line = raw_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
                        if not line:
                            continue

                        ctx = SourceContext(
                            source_key=cfg.source_key,
                            source_tool=cfg.source_tool,
                            file_path=file_path,
                            offset=line_offset,
                            line_number=line_no,
                            zone=cfg.zone,
                        )

                        try:
                            evs = adapter.parse(line, ctx)
                        except Exception as exc:
                            metric.unparsed += 1
                            self.unparsed_logger.record(
                                cfg.source_key,
                                line,
                                f"adapter_exception: {exc}",
                            )
                            continue

                        if evs is None:
                            reason = (
                                getattr(adapter, "last_ignore_reason", None)
                                or ctx.ignore_reason
                                or "ignored"
                            )
                            metric.record_ignored(reason)
                            continue

                        for ev in evs:
                            enriched = self.enricher.enrich(ev)
                            all_events.append((enriched.ts, enriched))
            except Exception as exc:
                metric.errors += 1
                metric.last_error = f"replay_read_error: {exc}"
                logger.error(
                    f"Replay read error on {cfg.source_key}: {exc}",
                    exc_info=True,
                )

        # Sort chronologically by timestamp
        all_events.sort(key=lambda item: item[0])
        total_replay = len(all_events)
        logger.info(f"Collected {total_replay} events. Replaying with speed factor {self.speed}...")

        for i, (_ts, ev) in enumerate(all_events):
            if not self.running:
                break

            metric = self.metrics.get(ev.source_tool.value) or next(iter(self.metrics.values()))
            metric.events_emitted += 1
            metric.last_event_ts = datetime.now(UTC)

            if not self.is_max_speed and i > 0:
                prev_ts = all_events[i - 1][0]
                delta = (_ts - prev_ts).total_seconds()
                if delta > 0:
                    sleep_sec = min(5.0, delta / self.speed)
                    if sleep_sec > 0.001:
                        await asyncio.sleep(sleep_sec)

            await self._batch_queue.put(ev)

        logger.info(f"Replay completed ({total_replay} events dispatched).")

    def get_sources_health(self) -> list[dict[str, Any]]:
        """Return snapshot of per-source health status and ingestion metrics."""
        now = datetime.now(UTC)
        health_list = []
        for cfg in self.sources:
            metric = self.metrics[cfg.source_key]
            file_path = self.log_root / cfg.relative_path
            file_exists = file_path.exists() and file_path.stat().st_size > 0
            health_list.append(metric.to_dict(now, file_exists))
        return health_list

    def get_stats(self, window_seconds: int = 300) -> dict[str, Any]:
        """Query aggregate event statistics from SQLite."""
        return get_stats(self.db, window_seconds=window_seconds)

    def query_events(
        self,
        limit: int = 50,
        before: str | None = None,
        since: str | None = None,
        source_tool: str | None = None,
        domain: str | None = None,
        category: str | None = None,
        host: str | None = None,
        user: str | None = None,
        ip: str | None = None,
    ) -> list[Event]:
        """Query events with filtering options."""
        return list_events(
            self.db,
            limit=limit,
            before=before,
            since=since,
            source_tool=source_tool,
            domain=domain,
            category=category,
            host=host,
            user=user,
            ip=ip,
        )

    def get_event(self, event_id: str) -> Event | None:
        """Fetch single event by its deterministic event_id."""
        return get_event_by_id(self.db, event_id)
