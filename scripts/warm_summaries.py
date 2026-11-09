#!/usr/bin/env python3
"""Pre-generate and cache verified analyst summaries for the 3 attack incidents.

Ensures that during live demonstrations or offline evaluation rehearsals,
analyst summaries are instantly accessible with zero latency.
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Add engine to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

# Load untracked local environment if present
from dotenv import load_dotenv  # noqa: E402

for env_candidate in [
    REPO_ROOT / "services/api/.env.local",
    REPO_ROOT / ".env.local",
    REPO_ROOT / "services/api/.env",
]:
    if env_candidate.is_file():
        load_dotenv(env_candidate)

from sentinelx.correlate.pipeline import CorrelationPipeline  # noqa: E402
from sentinelx.detect.runtime import DetectorPipeline  # noqa: E402
from sentinelx.ingest.runtime import Ingestor  # noqa: E402
from sentinelx.llm.summarizer import summarize_incident  # noqa: E402
from sentinelx.schemas.event import Event  # noqa: E402
from sentinelx.store.sqlite import (  # noqa: E402
    get_event_by_id,
    get_latest_incident_summary,
    init_db,
)

ATTACK_CAPTURES = [
    ("demo_baseline", REPO_ROOT / "eval/captures/attack/demo_baseline"),
    ("reordered", REPO_ROOT / "eval/captures/attack/reordered"),
    ("slow_burn", REPO_ROOT / "eval/captures/attack/slow_burn"),
]


async def warm_capture_summaries(capture_name: str, capture_path: Path, db_conn):
    """Replay capture events, correlate incidents, and pre-warm analyst summaries."""
    print(f"\n{'=' * 80}")
    print(f"[*] Processing Attack Capture: {capture_name} ({capture_path})")
    print(f"{'=' * 80}")

    detector_pipe = DetectorPipeline(db=db_conn)
    correlation_pipe = CorrelationPipeline(db=db_conn, budget_threshold=0.50)

    async def on_event(ev: Event) -> None:
        sigs = detector_pipe.process_event(ev)
        for s in sigs:
            await correlation_pipe.process_signal(s)

    ingestor = Ingestor(
        log_root=capture_path,
        db=db_conn,
        mode="replay",
        speed="max",
        on_event=on_event,
    )

    await ingestor.start()
    while ingestor._tasks and not all(t.done() for t in ingestor._tasks):
        await asyncio.sleep(0.01)
    await ingestor.stop()

    active_incidents = correlation_pipe.get_active_incidents()
    print(f"[+] Replay complete. Active incidents: {len(active_incidents)}")

    results = []
    for inc in active_incidents:
        # Collect cited evidence events from store
        events: list[Event] = []
        for eid in inc.event_ids:
            ev = get_event_by_id(db_conn, eid)
            if ev:
                events.append(ev)

        print(
            f"[*] Generating summary for incident {inc.incident_id} (Score: {inc.score:.2f}, {len(events)} events)..."
        )
        summary_resp = summarize_incident(
            incident=inc,
            events=events,
            db=db_conn,
            refresh=True,
            timeout=25.0,
        )

        cached_row = get_latest_incident_summary(db_conn, inc.incident_id)
        assert cached_row is not None, f"Failed to cache summary for {inc.incident_id}"

        print(
            f"    -> Mode: {summary_resp.mode} | Model: {summary_resp.model} | "
            f"Verified: {summary_resp.verified_count}/{summary_resp.total_count} (Dropped: {summary_resp.dropped_count})"
        )
        print(f"    -> Headline: {summary_resp.headline}")

        results.append(
            {
                "capture": capture_name,
                "incident_id": inc.incident_id,
                "score": inc.score,
                "mode": summary_resp.mode,
                "verified": f"{summary_resp.verified_count}/{summary_resp.total_count}",
                "dropped": summary_resp.dropped_count,
                "model": summary_resp.model,
                "headline": summary_resp.headline,
            }
        )

    return results


async def main_async(db_path: Path):
    db_conn = init_db(db_path)
    all_results = []

    for name, path in ATTACK_CAPTURES:
        if not path.is_dir():
            print(f"[!] Warning: capture path {path} not found, skipping.")
            continue
        res = await warm_capture_summaries(name, path, db_conn)
        all_results.extend(res)

    print(f"\n{'=' * 95}")
    print("DEMO WARM SUMMARIES CACHE MATRIX")
    print(f"{'=' * 95}")
    print(
        f"{'Capture':<16} | {'Incident ID':<22} | {'Score':<6} | {'Mode':<8} | {'Verified':<10} | {'Model':<22} | Headline"
    )
    print("-" * 95)
    for r in all_results:
        print(
            f"{r['capture']:<16} | {r['incident_id']:<22} | {r['score']:<6.2f} | {r['mode']:<8} | {r['verified']:<10} | {r['model']:<22} | {r['headline'][:30]}..."
        )
    print("-" * 95)
    print(f"[OK] Total warmed incident summaries: {len(all_results)} cached in {db_path}\n")


def main():
    parser = argparse.ArgumentParser(description="Pre-generate and cache demo analyst summaries.")
    parser.add_argument(
        "--db-path",
        type=Path,
        default=REPO_ROOT / "data/sentinelx.db",
        help="Path to SQLite database to warm",
    )
    args = parser.parse_args()
    asyncio.run(main_async(args.db_path))


if __name__ == "__main__":
    main()
