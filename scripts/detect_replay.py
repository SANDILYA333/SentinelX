#!/usr/bin/env python3
"""Replays a capture through ingestion and detection together and prints a signal summary."""

import argparse
import asyncio
import logging
import shutil
import sqlite3
import sys
import tempfile
from collections import Counter
from pathlib import Path

# Add engine to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.detect.runtime import DetectorPipeline  # noqa: E402
from sentinelx.ingest.runtime import Ingestor  # noqa: E402
from sentinelx.schemas.event import Event  # noqa: E402
from sentinelx.schemas.signal import Signal  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("detect_replay")


async def run_detect_replay(
    capture_dir: Path, speed: str = "max", db_path: Path | None = None
) -> dict:
    """Run capture through Ingestor + DetectorPipeline and return summary stats."""
    temp_dir = None
    if db_path is None:
        temp_dir = Path(tempfile.mkdtemp(prefix="sx_detect_replay_"))
        target_db = temp_dir / "replay.db"
    else:
        target_db = Path(db_path)

    try:
        pipeline = DetectorPipeline(db=target_db)
        pipeline.reset_state()

        async def on_event(ev: Event) -> None:
            pipeline.process_event(ev)

        ingestor = Ingestor(
            log_root=capture_dir,
            db=target_db,
            mode="replay",
            speed=speed,
            on_event=on_event,
        )

        logger.info(f"Starting detect-replay for {capture_dir} at speed {speed}...")
        await ingestor.start()
        while ingestor._tasks and not all(t.done() for t in ingestor._tasks):
            await asyncio.sleep(0.02)
        await ingestor.stop()

        conn = sqlite3.connect(target_db)
        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        sig_rows = conn.execute("SELECT json FROM signals").fetchall()
        signals = [Signal.model_validate_json(r[0]) for r in sig_rows]

        by_detector = Counter(s.detector for s in signals)
        by_technique = Counter()
        for s in signals:
            for t in s.techniques:
                by_technique[f"{t.technique_id} - {t.name}"] += 1

        honey_count = sum(
            1
            for s in signals
            if s.metadata.get("confirmed_honeytoken")
            or "confirmed_honeytoken" in s.metadata.get("tags", [])
        )

        return {
            "capture": capture_dir.name,
            "total_events": total_events,
            "total_signals": len(signals),
            "by_detector": dict(by_detector),
            "by_technique": dict(by_technique),
            "confirmed_honeytokens": honey_count,
            "signals": signals,
        }
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Run telemetry replay + detection on capture.")
    parser.add_argument("capture_dir", type=Path, help="Directory of capture to replay")
    parser.add_argument(
        "--speed", type=str, default="max", help="Replay speed factor (default: max)"
    )
    parser.add_argument("--db", type=Path, default=None, help="Optional persistent DB path")
    args = parser.parse_args()

    if not args.capture_dir.is_dir():
        logger.error(f"Capture directory not found: {args.capture_dir}")
        sys.exit(1)

    result = asyncio.run(run_detect_replay(args.capture_dir, speed=args.speed, db_path=args.db))

    print("\n" + "=" * 60)
    print(f"SENTINELX DETECT REPLAY SUMMARY: {result['capture']}")
    print("=" * 60)
    print(f"Total Telemetry Events Ingested: {result['total_events']}")
    print(f"Total Detection Signals Emitted: {result['total_signals']}")
    print(f"Confirmed Honeytoken Signals:   {result['confirmed_honeytokens']}")
    print("-" * 60)
    print("Signals by Detection Engine:")
    for det, cnt in sorted(result["by_detector"].items()):
        print(f"  - {det:12s}: {cnt:4d}")
    print("-" * 60)
    print("Signals by MITRE Technique:")
    for tech, cnt in sorted(result["by_technique"].items()):
        print(f"  - {tech:45s}: {cnt:4d}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
