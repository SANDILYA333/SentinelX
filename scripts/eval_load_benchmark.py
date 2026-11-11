#!/usr/bin/env python3
"""SentinelX System Performance & Telemetry Load Benchmark.

Evaluates:
1. Ingestion, detection, correlation, and end-to-end processing latencies.
2. Quantile distributions: P50, P90, P95, P99, mean, max.
3. Sustained throughput (events per second, signals per second).
4. SQLite database growth and performance under sustained telemetry load.
"""

import argparse
import asyncio
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# Add repo root and engine to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.correlate.pipeline import CorrelationPipeline
from sentinelx.detect.runtime import DetectorPipeline
from sentinelx.eval.engine import compute_percentiles
from sentinelx.schemas.common import Entity, Technique
from sentinelx.schemas.event import Event, EventCategory
from sentinelx.schemas.signal import Signal
from sentinelx.store.sqlite import init_db


def generate_synthetic_events(count: int) -> list[Event]:
    """Generate synthetic telemetry events across IT and OT domains for stress testing."""
    events = []
    now = datetime.now(timezone.utc)
    for i in range(count):
        is_ot = (i % 5 == 0)
        is_attack = (i % 50 == 0)

        ev = Event(
            event_id=f"bench-ev-{i:06d}",
            ts=now,
            ingested_at=now,
            source_tool="zeek" if not is_ot else "modbus",
            domain="ot" if is_ot else "it",
            category="ot_command" if is_ot else "network",
            action="write" if (is_ot and is_attack) else "read" if is_ot else "flow",
            outcome="success",
            src_ip="10.10.1.5" if is_attack else f"10.10.1.{10 + (i % 20)}",
            src_port=40000 + (i % 10000),
            dst_ip="10.10.3.50" if is_ot else "10.10.1.20",
            dst_port=502 if is_ot else 80,
            protocol="tcp",
            tags=["unauthorized_ot_write"] if (is_ot and is_attack) else ["routine"],
            ot={"is_write": True, "register": 40001, "value": 9999} if (is_ot and is_attack) else None,
            raw_ref={"source": "bench", "offset": i},
            raw={"synthetic": True},
        )
        events.append(ev)
    return events


async def run_benchmark(event_count: int = 1000, batch_size: int = 100):
    """Execute load test and report comprehensive latency quantiles and throughput."""
    print("=" * 90)
    print(f"SENTINELX PERFORMANCE BENCHMARK: {event_count} EVENTS (BATCH SIZE {batch_size})")
    print("=" * 90)

    events = generate_synthetic_events(event_count)

    with tempfile.TemporaryDirectory(prefix="sx_bench_") as tmpdir:
        db_path = Path(tmpdir) / "bench.db"
        init_db(db_path)

        detector_pipe = DetectorPipeline(db=db_path)
        corr_pipe = CorrelationPipeline(db=db_path, budget_threshold=0.50)

        l_detect: list[float] = []
        l_corr: list[float] = []
        l_e2e: list[float] = []
        total_signals = 0

        t0_total = time.perf_counter()

        for ev in events:
            t_start = time.perf_counter()

            # Detection
            t_det_start = time.perf_counter()
            sigs = detector_pipe.process_event(ev)
            t_det_end = time.perf_counter()
            l_detect.append((t_det_end - t_det_start) * 1000.0)

            # Correlation
            for s in sigs:
                total_signals += 1
                t_c_start = time.perf_counter()
                await corr_pipe.process_signal(s)
                t_c_end = time.perf_counter()
                l_corr.append((t_c_end - t_c_start) * 1000.0)

            t_end = time.perf_counter()
            l_e2e.append((t_end - t_start) * 1000.0)

        t_total = time.perf_counter() - t0_total
        db_size_kb = os.path.getsize(db_path) / 1024.0

    p_det = compute_percentiles(l_detect)
    p_corr = compute_percentiles(l_corr)
    p_e2e = compute_percentiles(l_e2e)
    throughput_eps = event_count / t_total if t_total > 0 else 0.0

    print(f"Total Time:             {t_total:.4f}s")
    print(f"Throughput:             {throughput_eps:.1f} events/sec")
    print(f"Total Signals Emitted:  {total_signals}")
    print(f"SQLite DB Final Size:   {db_size_kb:.2f} KB")
    print("-" * 90)
    print(f"{'Metric':<25} | {'Mean (ms)':<10} | {'P50 (ms)':<10} | {'P90 (ms)':<10} | {'P95 (ms)':<10} | {'P99 (ms)':<10} | {'Max (ms)':<10}")
    print("-" * 90)
    print(f"{'Detector Execution':<25} | {p_det.mean_ms:<10.3f} | {p_det.p50:<10.3f} | {p_det.p90:<10.3f} | {p_det.p95:<10.3f} | {p_det.p99:<10.3f} | {p_det.max_ms:<10.3f}")
    if p_corr.count > 0:
        print(f"{'Correlator Execution':<25} | {p_corr.mean_ms:<10.3f} | {p_corr.p50:<10.3f} | {p_corr.p90:<10.3f} | {p_corr.p95:<10.3f} | {p_corr.p99:<10.3f} | {p_corr.max_ms:<10.3f}")
    print(f"{'End-to-End Latency':<25} | {p_e2e.mean_ms:<10.3f} | {p_e2e.p50:<10.3f} | {p_e2e.p90:<10.3f} | {p_e2e.p95:<10.3f} | {p_e2e.p99:<10.3f} | {p_e2e.max_ms:<10.3f}")
    print("=" * 90)

    # Invariants verification
    assert throughput_eps > 100.0, f"Throughput {throughput_eps} EPS is below minimum 100 EPS requirement"
    assert p_e2e.p95 < 50.0, f"End-to-end P95 latency {p_e2e.p95}ms exceeds 50ms limit"
    print("SUCCESS: Performance invariants verified.")


def main():
    parser = argparse.ArgumentParser(description="Run SentinelX Performance Load Benchmark.")
    parser.add_argument("--count", type=int, default=1000, help="Number of events to benchmark (default 1000)")
    args = parser.parse_args()
    asyncio.run(run_benchmark(event_count=args.count))


if __name__ == "__main__":
    main()
