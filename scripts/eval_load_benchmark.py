#!/usr/bin/env python3
"""SentinelX System Performance & Telemetry Load Benchmark.

Evaluates:
1. Ingestion, detection, correlation, and end-to-end processing latencies.
2. Quantile distributions: P50, P90, P95, P99, mean, max.
3. Sustained throughput (events per second, signals per second).
4. SQLite database growth and performance under sustained telemetry load.
5. Workload testing at multiple scales: normal, moderate, high, burst, sustained.
"""

from __future__ import annotations

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

from sentinelx.correlate.pipeline import CorrelationPipeline  # noqa: E402
from sentinelx.detect.runtime import DetectorPipeline  # noqa: E402
from sentinelx.eval.engine import compute_percentiles  # noqa: E402
from sentinelx.schemas.event import Event  # noqa: E402
from sentinelx.store.sqlite import init_db  # noqa: E402

WORKLOAD_PRESETS = {
    "normal": 300,
    "moderate": 600,
    "high": 1500,
    "burst": 1000,
    "sustained": 3000,
}


def generate_synthetic_events(count: int, burst: bool = False) -> list[Event]:
    """Generate representative synthetic telemetry events across IT, DMZ, Deception, and OT domains."""
    events: list[Event] = []
    now = datetime.now(timezone.utc)
    for i in range(count):
        mod = i % 10
        is_ot = mod in (0, 5)
        is_decoy = mod == 3
        is_attack = i % 25 == 0

        domain = "ot" if is_ot else "decoy" if is_decoy else "it"
        source_tool = (
            "modbus" if is_ot else "cowrie" if is_decoy else "zeek" if (i % 2 == 0) else "wazuh"
        )
        category = (
            "ot_command"
            if is_ot
            else "authentication"
            if is_decoy
            else "network"
            if (i % 2 == 0)
            else "process"
        )

        action = (
            "write"
            if (is_ot and is_attack)
            else "read"
            if is_ot
            else "login"
            if is_decoy
            else "flow"
            if (i % 2 == 0)
            else "exec"
        )

        src_ip = "10.10.1.5" if is_attack else f"10.10.1.{10 + (i % 30)}"
        dst_ip = "10.10.3.50" if is_ot else "10.10.2.20" if is_decoy else "10.10.1.20"
        dst_port = 502 if is_ot else 2222 if is_decoy else 80 if (i % 2 == 0) else 0

        ot_payload = (
            {"is_write": True, "register": 40001, "value": 9999}
            if (is_ot and is_attack)
            else {"is_write": False, "register": 40001}
            if is_ot
            else None
        )

        tags = (
            ["unauthorized_ot_write"]
            if (is_ot and is_attack)
            else ["decoy_interaction"]
            if is_decoy
            else ["routine"]
        )

        ev = Event(
            event_id=f"bench-ev-{i:06d}",
            ts=now,
            ingested_at=now,
            source_tool=source_tool,
            domain=domain,
            category=category,
            action=action,
            outcome="success",
            src_ip=src_ip,
            src_port=40000 + (i % 10000),
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="tcp",
            tags=tags,
            ot=ot_payload,
            raw_ref={"source": "bench", "offset": i},
            raw={"synthetic": True, "burst": burst},
        )
        events.append(ev)
    return events


async def run_benchmark(
    event_count: int = 1000,
    workload_name: str = "moderate",
    is_burst: bool = False,
) -> dict[str, float]:
    """Execute load test and report comprehensive latency quantiles and throughput."""
    print("=" * 90)
    print(
        f"SENTINELX PERFORMANCE BENCHMARK: WORKLOAD='{workload_name.upper()}' ({event_count} EVENTS)"
    )
    print("=" * 90)

    events = generate_synthetic_events(event_count, burst=is_burst)

    with tempfile.TemporaryDirectory(prefix="sx_bench_") as tmpdir:
        db_path = Path(tmpdir) / "bench.db"
        init_db(db_path)

        detector_pipe = DetectorPipeline(db=db_path)
        corr_pipe = CorrelationPipeline(db=db_path, budget_threshold=0.50)

        l_detect: list[float] = []
        l_corr: list[float] = []
        l_e2e: list[float] = []
        total_signals = 0
        error_count = 0

        t0_total = time.perf_counter()

        for ev in events:
            t_start = time.perf_counter()

            # Detection
            t_det_start = time.perf_counter()
            try:
                sigs = detector_pipe.process_event(ev)
            except Exception:
                error_count += 1
                sigs = []
            t_det_end = time.perf_counter()
            l_detect.append((t_det_end - t_det_start) * 1000.0)

            # Correlation
            for s in sigs:
                total_signals += 1
                t_c_start = time.perf_counter()
                try:
                    await corr_pipe.process_signal(s)
                except Exception:
                    error_count += 1
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

    print(f"Workload Profile:       {workload_name.upper()}")
    print(f"Total Events Submitted: {event_count}")
    print(f"Total Duration:         {t_total:.4f}s")
    print(f"Processing Throughput:  {throughput_eps:.1f} events/sec")
    print("Queueing Delay:         0.000 ms (synchronous sequential submission)")
    print("Backlog at Completion:  0 events (100% completed)")
    print(f"Total Signals Emitted:  {total_signals}")
    print(f"Errors Encountered:     {error_count}")
    print(f"SQLite DB Final Size:   {db_size_kb:.2f} KB")
    print("-" * 90)
    print(
        f"{'Metric':<25} | {'Mean (ms)':<10} | {'P50 (ms)':<10} | {'P90 (ms)':<10} | {'P95 (ms)':<10} | {'P99 (ms)':<10} | {'Max (ms)':<10}"
    )
    print("-" * 90)
    print(
        f"{'Detector Execution':<25} | {p_det.mean_ms:<10.3f} | {p_det.p50:<10.3f} | {p_det.p90:<10.3f} | {p_det.p95:<10.3f} | {p_det.p99:<10.3f} | {p_det.max_ms:<10.3f}"
    )
    if p_corr.count > 0:
        print(
            f"{'Correlator Execution':<25} | {p_corr.mean_ms:<10.3f} | {p_corr.p50:<10.3f} | {p_corr.p90:<10.3f} | {p_corr.p95:<10.3f} | {p_corr.p99:<10.3f} | {p_corr.max_ms:<10.3f}"
        )
    print(
        f"{'End-to-End Latency':<25} | {p_e2e.mean_ms:<10.3f} | {p_e2e.p50:<10.3f} | {p_e2e.p90:<10.3f} | {p_e2e.p95:<10.3f} | {p_e2e.p99:<10.3f} | {p_e2e.max_ms:<10.3f}"
    )
    print("=" * 90)

    # Invariants verification
    assert throughput_eps > 100.0, (
        f"Throughput {throughput_eps} EPS is below minimum 100 EPS requirement"
    )
    assert p_e2e.p95 < 50.0, f"End-to-end P95 latency {p_e2e.p95}ms exceeds 50ms limit"
    assert error_count == 0, f"Errors were encountered during benchmark: {error_count}"
    print("SUCCESS: Performance invariants verified.")

    return {
        "throughput_eps": throughput_eps,
        "p50_e2e_ms": p_e2e.p50,
        "p95_e2e_ms": p_e2e.p95,
        "p99_e2e_ms": p_e2e.p99,
        "total_signals": total_signals,
    }


def main():
    parser = argparse.ArgumentParser(description="Run SentinelX Performance Load Benchmark.")
    parser.add_argument(
        "--workload",
        type=str,
        default="moderate",
        choices=["normal", "moderate", "high", "burst", "sustained"],
        help="Workload scale profile (default: moderate)",
    )
    parser.add_argument("--count", type=int, default=None, help="Override event count")
    args = parser.parse_args()

    count = args.count or WORKLOAD_PRESETS[args.workload]
    is_burst = args.workload == "burst"
    asyncio.run(run_benchmark(event_count=count, workload_name=args.workload, is_burst=is_burst))


if __name__ == "__main__":
    main()
