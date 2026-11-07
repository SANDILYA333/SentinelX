"""Tests for pipeline idempotency, checkpoint resume, and end-to-end Ingestor runtime."""

import asyncio
import json
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sentinelx.ingest.runtime import Ingestor, SourceConfig
from sentinelx.ingest.tailer import AsyncFileTailer, CheckpointManager
from sentinelx.schemas.common import Domain, Outcome, SourceTool
from sentinelx.schemas.event import Event
from sentinelx.store.sqlite import init_db, insert_events_batch, list_events


def make_dummy_event(event_id: str, ts: datetime, host: str = "jump-host") -> Event:
    return Event(
        event_id=event_id,
        ts=ts,
        ingested_at=ts,
        source_tool=SourceTool.wazuh,
        domain=Domain.it,
        category="authentication",
        action="ssh_login",
        outcome=Outcome.success,
        host=host,
        src_ip="10.10.1.50",
        raw_ref={"source": "test"},
        raw={"host": host},
        tags=["test"],
    )


def test_idempotency_duplicate_inserts():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_idempotent.db"
        db = init_db(db_path)

        now = datetime.now(UTC)
        ev1 = make_dummy_event("evt_0000000000000001", now)
        ev2 = make_dummy_event("evt_0000000000000002", now)

        # First insert
        inserted_1 = insert_events_batch(db, [ev1, ev2])
        assert inserted_1 == 2
        assert len(list_events(db, limit=100)) == 2

        # Second insert with identical IDs -> exactly 0 new rows
        inserted_2 = insert_events_batch(db, [ev1, ev2])
        assert inserted_2 == 0
        assert len(list_events(db, limit=100)) == 2

        db.close()


@pytest.mark.anyio
async def test_tailer_partial_line_and_rotation():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        log_file = tmp_path / "test_tail.log"
        cp_db = tmp_path / "checkpoints.db"
        cp_mgr = CheckpointManager(cp_db)

        # Write initial partial line
        log_file.write_text('{"msg": "part1", ')

        tailer = AsyncFileTailer(
            file_path=log_file,
            source_key="test_src",
            source_tool="test",
            mode="from_start",
            checkpoint_mgr=cp_mgr,
            poll_interval=0.05,
        )

        lines_read = []

        async def reader():
            async for line, ctx in tailer.tail_lines():
                lines_read.append(line)
                if len(lines_read) == 2:
                    tailer.running = False
                    break

        reader_task = asyncio.create_task(reader())
        await asyncio.sleep(0.1)
        assert len(lines_read) == 0  # Partial line must not be emitted

        # Complete the line
        with open(log_file, "a") as f:
            f.write('"status": "ok"}\n{"msg": "line2"}\n')

        await asyncio.wait_for(reader_task, timeout=2.0)
        assert len(lines_read) == 2
        assert json.loads(lines_read[0]) == {"msg": "part1", "status": "ok"}
        assert json.loads(lines_read[1]) == {"msg": "line2"}


@pytest.mark.anyio
async def test_pipeline_integration_with_temp_files():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        log_root = tmp_path / "logs"
        log_root.mkdir()
        db_path = tmp_path / "pipeline.db"

        # Create dummy source log files
        cowrie_dir = log_root / "cowrie"
        cowrie_dir.mkdir()
        cowrie_file = cowrie_dir / "cowrie.json"

        # Write 2 Cowrie events
        cowrie_data = [
            {
                "session": "s1",
                "protocol": "ssh",
                "src_ip": "10.10.1.5",
                "dst_ip": "10.10.2.20",
                "username": "svc_dbadmin",
                "password": "pwd",
                "eventid": "cowrie.login.success",
                "timestamp": "2026-11-07T12:00:00.000000Z",
            },
            {
                "session": "s1",
                "protocol": "ssh",
                "src_ip": "10.10.1.5",
                "dst_ip": "10.10.2.20",
                "input": "uname -a",
                "eventid": "cowrie.command.input",
                "timestamp": "2026-11-07T12:00:05.000000Z",
            },
        ]
        with open(cowrie_file, "w") as f:
            for item in cowrie_data:
                f.write(json.dumps(item) + "\n")

        broadcasted = []

        async def fake_broadcast(ev: Event):
            broadcasted.append(ev)

        sources = [
            SourceConfig(
                source_key="cowrie",
                source_tool="cowrie",
                relative_path="cowrie/cowrie.json",
                adapter_name="cowrie",
                zone="dmz",
            )
        ]

        # Start Ingestor in live mode
        ingestor = Ingestor(
            log_root=log_root,
            db=db_path,
            mode="live",
            on_event=fake_broadcast,
            sources=sources,
        )

        await ingestor.start()
        # Wait for tailer and batch writer to process
        await asyncio.sleep(0.6)
        await ingestor.stop()

        # Verify SQLite received all events
        db = sqlite3.connect(str(db_path))
        events = list_events(db, limit=10)
        assert len(events) == 2
        assert len(broadcasted) == 2

        # Verify honey_user tag was added
        login_ev = next(e for e in events if e.action == "ssh_login_success")
        assert "honey_user" in (login_ev.tags or [])
        assert login_ev.user == "svc_dbadmin"

        # Verify checkpoint was persisted
        cp_mgr = CheckpointManager(db_path)
        cp = cp_mgr.get_checkpoint("cowrie")
        assert cp is not None
        assert cp[1] == cowrie_file.stat().st_size

        # Restart Ingestor: verify ZERO duplicate events added
        ingestor_restart = Ingestor(
            log_root=log_root,
            db=db_path,
            mode="live",
            on_event=fake_broadcast,
            sources=sources,
        )
        await ingestor_restart.start()
        await asyncio.sleep(0.4)
        await ingestor_restart.stop()

        events_after_restart = list_events(db, limit=10)
        assert len(events_after_restart) == 2  # No duplicate rows!
        db.close()
