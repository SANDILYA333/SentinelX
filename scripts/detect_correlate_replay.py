#!/usr/bin/env python3
"""Run full ingestion, multi-engine detection, and incident correlation replay.

Usage:
  python scripts/detect_correlate_replay.py --dir eval/captures/attack/demo_baseline --speed max
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Add engine to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.correlate.pipeline import CorrelationPipeline  # noqa: E402
from sentinelx.detect.runtime import DetectorPipeline  # noqa: E402
from sentinelx.guard.evaluator import GuardEvaluator  # noqa: E402
from sentinelx.ingest.runtime import Ingestor  # noqa: E402
from sentinelx.schemas.event import Event  # noqa: E402
from sentinelx.schemas.signal import Signal  # noqa: E402
from sentinelx.store.sqlite import (  # noqa: E402
    init_db,
    list_guard_decisions,
    list_incidents,
)


async def replay_pipeline(capture_dir: Path, db_path: Path, speed: str = "max"):
    """Run capture through DetectorPipeline and CorrelationPipeline, persisting to SQLite."""
    conn = init_db(db_path)
    detector_pipe = DetectorPipeline(db=conn)
    correlation_pipe = CorrelationPipeline(db=conn, budget_threshold=0.50)
    guard = GuardEvaluator(db=conn)

    captured_signals: list[Signal] = []

    async def on_event(ev: Event) -> None:
        sigs = detector_pipe.process_event(ev)
        for s in sigs:
            captured_signals.append(s)
            await correlation_pipe.process_signal(s)

    ingestor = Ingestor(
        log_root=capture_dir,
        db=conn,
        mode="replay",
        speed=speed,  # type: ignore[arg-type]
        on_event=on_event,
    )

    print(f"\n[REPLAY] Ingesting {capture_dir} (speed={speed}) into {db_path}...")
    await ingestor.start()
    while ingestor._tasks and not all(t.done() for t in ingestor._tasks):
        await asyncio.sleep(0.01)
    await ingestor.stop()

    incidents = correlation_pipe.get_active_incidents()
    print(
        f"[REPLAY] Finished. Emitted {len(captured_signals)} signals, {len(incidents)} active incidents."
    )

    for inc in incidents:
        print("\n" + "=" * 90)
        print(
            f"INCIDENT: {inc.incident_id} | Score: {inc.score:.2f} ({inc.severity.value.upper()}) | Status: {inc.status}"
        )
        print("=" * 90)
        print(f"  * First Signal TS:       {inc.first_signal_ts.isoformat()}")
        print(
            f"  * Meaningful Alert TS:   {inc.first_meaningful_alert_ts.isoformat() if inc.first_meaningful_alert_ts else 'None'}"
        )
        print(f"  * TTFMA:                 {inc.ttfma_seconds} seconds")
        print(f"  * Kill Chain Stages:     {' -> '.join(inc.kill_chain_stages)}")
        print(f"  * Decoy Touched:         {inc.decoy_touched}")
        print(f"  * OT Process Touched:    {inc.ot_touched}")
        print(f"  * Signals Attached:      {len(inc.signal_ids)}")
        print(f"  * Evidence Events:       {len(inc.event_ids)}")
        print(
            f"  * Entities ({len(inc.entities)}):          {', '.join(f'{e.type.value}:{e.value}' for e in inc.entities[:6])}"
        )
        print(
            f"  * MITRE Techniques ({len(inc.techniques)}):    {', '.join(t.technique_id for t in inc.techniques)}"
        )
        print("\n  Forensic Narrative Highlights:")
        for line in inc.explanation[:4]:
            print(f"    - {line}")

        # Guard Decision Demonstration for this incident
        print("\n  Response Safety Guard Policy Test:")
        # 1. Block attacker IP (safe)
        dec_allow = guard.evaluate(
            action="block_ip", target="10.10.1.5", incident_id=inc.incident_id
        )
        print(
            f"    - Action: block_ip (10.10.1.5)  => {dec_allow.decision.upper()} [{dec_allow.rule_ids[0]}]"
        )
        # 2. Isolate PLC while manipulated (safety denied)
        dec_deny = guard.evaluate(
            action="isolate_host",
            target="plc-sim",
            incident_id=inc.incident_id,
            plc_state={"flag": "manipulated"},
        )
        print(
            f"    - Action: isolate_host (plc-sim) => {dec_deny.decision.upper()} [{dec_deny.rule_ids[0]}]"
        )
        if dec_deny.decision == "deny" and len(dec_deny.reasons) > 2:
            print(f"      {dec_deny.reasons[2]}")

    return incidents


def main():
    parser = argparse.ArgumentParser(
        description="SentinelX Telemetry Ingestion, Detection, and Correlation Replayer."
    )
    parser.add_argument("--dir", "-d", type=Path, required=True, help="Capture directory path")
    parser.add_argument(
        "--speed", "-s", type=str, default="max", help="Replay speed (max, 10x, 1x)"
    )
    parser.add_argument("--db", type=Path, default=Path("data/sentinelx.db"), help="Database path")
    parser.add_argument(
        "--check-idempotency", action="store_true", help="Re-run to test idempotency"
    )
    args = parser.parse_args()

    if not args.dir.is_dir():
        print(f"Error: Capture directory '{args.dir}' not found.")
        sys.exit(1)

    # First replay run
    asyncio.run(replay_pipeline(args.dir, args.db, speed=args.speed))

    conn = init_db(args.db)
    incs_run1 = list_incidents(conn)
    guards_run1 = list_guard_decisions(conn)

    print("\n[IDEMPOTENCY CHECK] Re-running replay against the same database...")
    asyncio.run(replay_pipeline(args.dir, args.db, speed=args.speed))

    incs_run2 = list_incidents(conn)
    guards_run2 = list_guard_decisions(conn)

    print(
        f"\n[IDEMPOTENCY RESULTS] Incidents count run 1: {len(incs_run1)} -> run 2: {len(incs_run2)}"
    )
    print(
        f"[IDEMPOTENCY RESULTS] Guard decisions count run 1: {len(guards_run1)} -> run 2: {len(guards_run2)}"
    )

    assert len(incs_run1) == len(incs_run2), "Duplicate incidents created on second replay!"
    assert len(guards_run1) == len(guards_run2), (
        "Duplicate guard decisions created on second replay!"
    )
    print("IDEMPOTENCY VERIFICATION PASSED: No duplicate records inserted.\n")


if __name__ == "__main__":
    main()
