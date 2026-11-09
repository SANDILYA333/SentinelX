#!/usr/bin/env python3
"""Measure SentinelX replay throughput and live end-to-end processing latency.

Part (a): Offline replay throughput: events/s and ingest-to-incident wall-time for each attack capture.
Part (b): Live end-to-end latency: wall-clock from attacker's first action to incident threshold crossing.
"""

import argparse
import asyncio
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# Add engine to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.correlate.pipeline import CorrelationPipeline  # noqa: E402
from sentinelx.detect.runtime import DetectorPipeline  # noqa: E402
from sentinelx.ingest.runtime import Ingestor  # noqa: E402
from sentinelx.schemas.event import Event  # noqa: E402
from sentinelx.store.sqlite import init_db  # noqa: E402

ATTACK_CAPTURES = [
    ("demo_baseline", REPO_ROOT / "eval/captures/attack/demo_baseline"),
    ("reordered", REPO_ROOT / "eval/captures/attack/reordered"),
    ("slow_burn", REPO_ROOT / "eval/captures/attack/slow_burn"),
]


async def measure_capture_replay(capture_name: str, capture_path: Path):
    """Measure replay wall-time latency and throughput for an attack capture."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "latency.db"
        conn = init_db(db_path)
        detector_pipe = DetectorPipeline(db=conn)
        correlation_pipe = CorrelationPipeline(db=conn, budget_threshold=0.50)

        event_count = 0
        t_start = 0.0
        t_threshold_cross: float | None = None
        first_incident_id: str | None = None
        top_score = 0.0

        async def on_event(ev: Event) -> None:
            nonlocal event_count, t_threshold_cross, first_incident_id, top_score
            event_count += 1
            sigs = detector_pipe.process_event(ev)
            for s in sigs:
                await correlation_pipe.process_signal(s)

            if t_threshold_cross is None:
                incidents = correlation_pipe.get_active_incidents()
                for inc in incidents:
                    if inc.score >= 0.50:
                        t_threshold_cross = time.perf_counter()
                        first_incident_id = inc.incident_id
                        top_score = inc.score
                        break

        ingestor = Ingestor(
            log_root=capture_path,
            db=conn,
            mode="replay",
            speed="max",
            on_event=on_event,
        )

        t_start = time.perf_counter()
        await ingestor.start()
        while ingestor._tasks and not all(t.done() for t in ingestor._tasks):
            await asyncio.sleep(0.005)
        await ingestor.stop()
        t_end = time.perf_counter()

        conn.close()

    total_wall_sec = t_end - t_start
    throughput = event_count / total_wall_sec if total_wall_sec > 0 else 0.0
    thresh_latency_sec = (
        (t_threshold_cross - t_start) if t_threshold_cross is not None else total_wall_sec
    )

    # Update top score if not captured at crossing
    if top_score == 0.0:
        active = correlation_pipe.get_active_incidents()
        if active:
            top_score = active[0].score

    return {
        "capture": capture_name,
        "events": event_count,
        "total_wall_sec": total_wall_sec,
        "threshold_latency_sec": thresh_latency_sec,
        "throughput_eps": throughput,
        "top_score": top_score,
        "first_incident_id": first_incident_id or "--",
    }


def run_live_measurement(api_url: str = "http://localhost:8000"):
    """Measure live end-to-end latency during make demo-attack across 3 runs.

    Measures wall-clock from attacker's first action to incident score >= threshold.
    """
    import json
    import statistics
    import subprocess

    # Check health first
    try:
        req = urllib.request.Request(f"{api_url}/api/v1/health", method="GET")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            if resp.status != 200:
                print(
                    f"NOT RUN: API /api/v1/health returned status {resp.status}. Start API via 'make api'."
                )
                return
    except Exception as exc:
        print(f"NOT RUN: Live API not reachable at {api_url} ({exc}).")
        print("Exact commands to start environment and run live measurement:")
        print("  make lab-up")
        print("  make api  # In terminal 1")
        print("  uv run python scripts/measure_latency.py --live  # In terminal 2")
        return

    # Check lab container health before triggering demo-attack
    try:
        chk = subprocess.run(
            ["docker", "ps", "--filter", "name=sentinelx", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        if not chk.stdout.strip():
            print("NOT RUN: Lab containers not running. Start testbed via 'make lab-up'.")
            print("Exact commands to start environment and run live measurement:")
            print("  make lab-up")
            print("  make api  # In terminal 1")
            print("  uv run python scripts/measure_latency.py --live  # In terminal 2")
            return
    except Exception as exc:
        print(f"NOT RUN: Docker check failed ({exc}). Start testbed via 'make lab-up'.")
        print("Exact commands to start environment and run live measurement:")
        print("  make lab-up")
        print("  make api  # In terminal 1")
        print("  uv run python scripts/measure_latency.py --live  # In terminal 2")
        return

    print("[*] Connected to live API and verified lab containers. Executing 3 benchmark runs...")
    latencies: list[float] = []

    for run_idx in range(1, 4):
        print(f"\n[*] Run {run_idx}/3: Resetting state via 'make demo-reset'...")
        subprocess.run(["make", "demo-reset"], check=True, capture_output=True)
        time.sleep(1.0)

        print(f"[*] Run {run_idx}/3: Launching 'make demo-attack' and recording t0...")
        t0 = time.perf_counter()
        attack_proc = subprocess.Popen(
            ["make", "demo-attack"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        crossing_latency: float | None = None
        deadline = time.perf_counter() + 60.0

        while time.perf_counter() < deadline:
            try:
                poll_req = urllib.request.Request(f"{api_url}/api/v1/incidents", method="GET")
                with urllib.request.urlopen(poll_req, timeout=1.0) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        for inc in data:
                            if inc.get("score", 0.0) >= 0.50:
                                crossing_latency = time.perf_counter() - t0
                                break
                if crossing_latency is not None:
                    break
            except Exception:
                pass
            time.sleep(0.25)

        attack_proc.kill()
        attack_proc.wait()

        if crossing_latency is not None:
            print(f"[+] Run {run_idx}/3: Incident crossed threshold in {crossing_latency:.4f}s")
            latencies.append(crossing_latency)
        else:
            print(f"[!] Run {run_idx}/3: Timed out waiting for incident to cross threshold")

    if latencies:
        p50 = statistics.median(latencies)
        max_lat = max(latencies)
        print("\n" + "=" * 85)
        print(f"LIVE END-TO-END BENCHMARK (3 runs): p50 = {p50:.4f}s | max = {max_lat:.4f}s")
        print("=" * 85)


async def main_async(run_live: bool, api_url: str):
    print("=" * 85)
    print("SENTINELX PROCESSING LATENCY & THROUGHPUT BENCHMARK (Phase 8)")
    print("=" * 85)

    print("\n--- Part (a): Replay Throughput & Ingest-to-Incident Wall-Time ---")
    print("(offline replay compute at max speed, in-process, no live pipeline latency)")
    results = []
    for name, path in ATTACK_CAPTURES:
        if not path.is_dir():
            print(f"[!] Warning: capture {name} not found at {path}")
            continue
        print(f"[*] Replaying capture '{name}' (speed=max)...")
        res = await measure_capture_replay(name, path)
        results.append(res)

    print("\n" + "=" * 85)
    print("OFFLINE REPLAY LATENCY & THROUGHPUT MATRIX")
    print("(offline replay compute at max speed, in-process, no live pipeline latency)")
    print("=" * 85)
    print(
        f"{'Capture':<16} | {'Events':<7} | {'Total Wall Time':<16} | {'To Threshold (>=0.50)':<22} | Throughput"
    )
    print("-" * 85)
    for r in results:
        print(
            f"{r['capture']:<16} | {r['events']:<7} | {r['total_wall_sec']:.4f}s          | "
            f"{r['threshold_latency_sec']:.4f}s ({r['top_score']:.2f})       | {r['throughput_eps']:.1f} events/s"
        )
    print("-" * 85)

    mean_throughput = sum(r["throughput_eps"] for r in results) / len(results) if results else 0
    mean_threshold_latency = (
        sum(r["threshold_latency_sec"] for r in results) / len(results) if results else 0
    )
    print(
        f"[SUMMARY] Mean Ingestion Throughput (offline replay compute at max speed, in-process, no live pipeline latency): {mean_throughput:.1f} events/s"
    )
    print(
        f"[SUMMARY] Mean Ingest-to-Incident Wall-Clock Latency (offline replay compute at max speed, in-process, no live pipeline latency): {mean_threshold_latency:.4f}s"
    )

    print("\n--- Part (b): Live End-to-End Latency Measurement ---")
    if run_live:
        run_live_measurement(api_url)
    else:
        print(
            "Part (b) NOT RUN: requires running lab environment and active API server.\n"
            "Exact command to execute live test:\n"
            "  make lab-up\n"
            "  make api  # In terminal 1\n"
            "  uv run python scripts/measure_latency.py --live  # In terminal 2"
        )


def main():
    parser = argparse.ArgumentParser(description="Measure SentinelX replay throughput and latency.")
    parser.add_argument(
        "--live", action="store_true", help="Run live end-to-end benchmark against active lab"
    )
    parser.add_argument("--api-url", default="http://localhost:8000", help="API server base URL")
    args = parser.parse_args()

    asyncio.run(main_async(args.live, args.api_url))


if __name__ == "__main__":
    main()
