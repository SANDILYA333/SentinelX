#!/usr/bin/env python3
"""Generates the full set of 8 telemetry captures for Phase 3:
- 5 independent BENIGN captures (different random seeds, simulated day)
- 1 'demo' ATTACK capture: baseline.yaml with concurrent benign
- 1 ATTACK capture: reordered.yaml with concurrent benign
- 1 ATTACK capture: slow_burn.yaml with concurrent benign
Enforces disk space checks between runs.
"""

import logging
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "eval"))

from capture import check_free_disk, run_capture  # noqa: E402

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CAPTURES-ALL] %(message)s")
logger = logging.getLogger("captures_all")

BENIGN_SEEDS = [101, 102, 103, 104, 105]


def main():
    print("\n" + "#" * 80)
    print("STARTING FULL CAPTURE GENERATION PIPELINE (TASK 4: 8 CAPTURES)")
    print("  - 5 Benign Days (Seeds 101-105)")
    print("  - 1 Attack Demo Baseline (concurrent benign)")
    print("  - 1 Attack Reordered Variant (concurrent benign)")
    print("  - 1 Attack Slow-Burn Variant (concurrent benign)")
    print("#" * 80 + "\n")

    start_all = time.time()
    free_start = check_free_disk()
    print(f"Initial available disk space: {free_start:.2f} GB\n")

    # 1. Generate 5 Benign captures
    # Tradeoff note: duration=60s at SIM_SPEED=96 (1.6 simulated hours per day run)
    for idx, seed in enumerate(BENIGN_SEEDS, 1):
        print("\n" + "-" * 80)
        print(f"[{idx}/8] GENERATING BENIGN DAY CAPTURE (Seed: {seed})...")
        print("-" * 80)
        check_free_disk()

        run_capture(
            category="benign",
            name=f"day_{seed}",
            mode="benign",
            duration=60.0,
            sim_speed=96.0,
            seed=seed,
            skip_reset=False,
        )

    # 2. Generate Demo Baseline attack capture (with concurrent benign)
    print("\n" + "-" * 80)
    print("[6/8] GENERATING ATTACK CAPTURE: attack/demo_baseline (baseline.yaml + benign)...")
    print("-" * 80)
    check_free_disk()

    run_capture(
        category="attack",
        name="demo_baseline",
        mode="hybrid",
        scenario_name="baseline",
        duration=90.0,
        sim_speed=96.0,
        seed=201,
        skip_reset=False,
    )

    # 3. Generate Reordered attack capture (with concurrent benign)
    print("\n" + "-" * 80)
    print("[7/8] GENERATING ATTACK CAPTURE: attack/reordered (reordered.yaml + benign)...")
    print("-" * 80)
    check_free_disk()

    run_capture(
        category="attack",
        name="reordered",
        mode="hybrid",
        scenario_name="reordered",
        duration=95.0,
        sim_speed=96.0,
        seed=202,
        skip_reset=False,
    )

    # 4. Generate Slow-Burn attack capture (with concurrent benign)
    print("\n" + "-" * 80)
    print("[8/8] GENERATING ATTACK CAPTURE: attack/slow_burn (slow_burn.yaml + benign)...")
    print("-" * 80)
    check_free_disk()

    run_capture(
        category="attack",
        name="slow_burn",
        mode="hybrid",
        scenario_name="slow_burn",
        duration=180.0,
        sim_speed=96.0,
        seed=203,
        skip_reset=False,
    )

    total_time = time.time() - start_all
    mins, secs = divmod(int(total_time), 60)
    free_end = check_free_disk()

    print("\n" + "#" * 80)
    print("ALL 8 TELEMETRY CAPTURES GENERATED SUCCESSFULLY!")
    print(f"Total Wall Clock Time : {mins:02d}:{secs:02d} ({total_time:.2f}s)")
    print(
        f"Disk Space Start/End  : {free_start:.2f} GB -> {free_end:.2f} GB (Delta: {free_start - free_end:.2f} GB)"
    )
    print("#" * 80 + "\n")


if __name__ == "__main__":
    main()
