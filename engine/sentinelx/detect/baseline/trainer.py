"""Baseline profile trainer extracting behavioral baselines from benign captures."""

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any

from sentinelx.detect.baseline.model import BaselineModel, EntityProfile
from sentinelx.ingest.runtime import Ingestor
from sentinelx.schemas.event import Event

logger = logging.getLogger("baseline_trainer")


async def load_capture_events(capture_dir: Path) -> list[Event]:
    """Ingest capture directory into a temporary SQLite database and return sorted Events."""
    temp_dir = Path(tempfile.mkdtemp(prefix="sx_baseline_"))
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


def train_baseline_model(
    capture_dirs: list[Path | str],
    exclude_startup_sim_hours: float = 1.0,
) -> BaselineModel:
    """Train per-entity baseline behavioral profiles across given benign capture directories.

    Per spec and docs/telemetry-plan.md, benign captures show a startup-burst artifact
    in their first simulated hour due to synchronized actor initialization.
    Events in the first simulated hour (default 1.0 hour, equivalent to 12.0 wall seconds at 300x)
    are excluded from training to ensure pristine baselines.
    """
    profiles: dict[str, dict[str, Any]] = {}
    known_users: set[str] = set()
    known_hosts: set[str] = set()
    known_zones: set[str] = set()

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

        # Exclude first simulated hour
        cutoff_sec = (3600.0 * exclude_startup_sim_hours) / sim_speed

        for e in events:
            elapsed = (e.ts - t0).total_seconds()
            if elapsed < cutoff_sec:
                # Skip startup burst
                continue

            # Record global sets
            if e.user:
                known_users.add(e.user)
            if e.host:
                known_hosts.add(e.host)
            if e.domain:
                known_zones.add(e.domain.value)

            # Record user profile
            if e.user:
                u_key = f"user:{e.user}"
                u_prof = profiles.setdefault(
                    u_key,
                    {
                        "entity_id": u_key,
                        "entity_type": "user",
                        "active_hours": set(),
                        "allowed_hosts": set(),
                        "allowed_zones": set(),
                        "allowed_commands": set(),
                        "total_observations": 0,
                    },
                )
                u_prof["active_hours"].add(e.ts.hour)
                u_prof["allowed_zones"].add(e.domain.value)
                if e.host:
                    u_prof["allowed_hosts"].add(e.host)
                cmd = e.cmdline or e.process
                if cmd:
                    u_prof["allowed_commands"].add(cmd.strip())
                u_prof["total_observations"] += 1

            # Record host profile
            if e.host:
                h_key = f"host:{e.host}"
                h_prof = profiles.setdefault(
                    h_key,
                    {
                        "entity_id": h_key,
                        "entity_type": "host",
                        "active_hours": set(),
                        "allowed_hosts": set(),
                        "allowed_zones": set(),
                        "allowed_commands": set(),
                        "total_observations": 0,
                    },
                )
                h_prof["active_hours"].add(e.ts.hour)
                h_prof["allowed_zones"].add(e.domain.value)
                h_prof["total_observations"] += 1

    # Convert sets to sorted lists for serialization
    final_profiles: dict[str, EntityProfile] = {}
    for k, v in profiles.items():
        final_profiles[k] = EntityProfile(
            entity_id=v["entity_id"],
            entity_type=v["entity_type"],
            active_hours=sorted(v["active_hours"]),
            allowed_hosts=sorted(v["allowed_hosts"]),
            allowed_zones=sorted(v["allowed_zones"]),
            allowed_commands=sorted(v["allowed_commands"]),
            total_observations=v["total_observations"],
        )

    return BaselineModel(
        profiles=final_profiles,
        known_users=sorted(known_users),
        known_hosts=sorted(known_hosts),
        known_zones=sorted(known_zones),
        metadata={
            "trained_on_captures": [str(Path(c).name) for c in capture_dirs],
            "startup_burst_excluded": True,
            "exclude_startup_sim_hours": exclude_startup_sim_hours,
        },
    )
