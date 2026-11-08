"""Learns known benign interaction edges from benign telemetry captures."""

import asyncio
import ipaddress
import json
import logging
import shutil
import tempfile
from pathlib import Path

from sentinelx.detect.graph.model import GraphModel
from sentinelx.ingest.runtime import Ingestor
from sentinelx.schemas.event import Event

logger = logging.getLogger("graph_trainer")


def is_valid_unicast(ip_str: str | None) -> bool:
    """Filter out multicast, link-local, loopback, and broadcast IP noise."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_multicast or ip.is_loopback or ip.is_unspecified or ip.is_link_local)
    except Exception:
        return False


async def load_capture_events(capture_dir: Path) -> list[Event]:
    """Ingest capture directory into a temporary SQLite database and return sorted Events."""
    temp_dir = Path(tempfile.mkdtemp(prefix="sx_graph_"))
    try:
        temp_db = temp_dir / "temp.db"
        ingestor = Ingestor(log_root=capture_dir, db=temp_db, mode="replay", speed="max")
        await ingestor.start()
        while ingestor._tasks and not all(t.done() for t in ingestor._tasks):
            await asyncio.sleep(0.02)
        await ingestor.stop()

        import sqlite3

        conn = sqlite3.connect(temp_db)
        rows = conn.execute("SELECT json FROM events ORDER BY ts ASC").fetchall()
        return [Event.model_validate_json(r[0]) for r in rows]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def train_graph_model(
    capture_dirs: list[Path | str],
    exclude_startup_sim_hours: float = 1.0,
) -> GraphModel:
    """Extract all legitimate entity-to-entity interaction edges from benign captures."""
    known_edges: set[tuple[str, str]] = set()

    for cap_path in capture_dirs:
        p = Path(cap_path)
        if not p.is_dir():
            continue

        events = asyncio.run(load_capture_events(p))
        if not events:
            continue

        t0 = events[0].ts
        sim_speed = 300.0
        manifest_file = p / "manifest.json"
        if manifest_file.exists():
            try:
                with open(manifest_file, "r", encoding="utf-8") as mf:
                    mdata = json.load(mf)
                    sim_speed = float(mdata.get("sim_speed", 300.0))
            except Exception:
                pass

        cutoff_sec = (3600.0 * exclude_startup_sim_hours) / sim_speed

        for e in events:
            if (e.ts - t0).total_seconds() < cutoff_sec:
                continue

            u = e.user
            h = e.host
            src = e.src_ip
            dst = e.dst_ip

            # User -> Host authentication edge
            if u and h:
                known_edges.add((f"user:{u}", f"host:{h}"))

            # Host/IP -> Host/IP network communication edge
            if is_valid_unicast(src) and is_valid_unicast(dst):
                known_edges.add((f"ip:{src}", f"ip:{dst}"))

            # Host -> Device OT edge
            if e.ot and e.ot.device_id and h:
                known_edges.add((f"host:{h}", f"device:{e.ot.device_id}"))

    sorted_edges = [list(e) for e in sorted(known_edges)]
    return GraphModel(
        known_edges=sorted_edges,
        metadata={
            "trained_on_captures": [str(Path(c).name) for c in capture_dirs],
            "startup_burst_excluded": True,
            "total_known_edges": len(sorted_edges),
        },
    )
