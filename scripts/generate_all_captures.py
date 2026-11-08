#!/usr/bin/env python3
"""Generates the full set of 8 telemetry captures for Phase 3:
- 5 independent BENIGN captures (different random seeds, simulated day)
- 1 'demo' ATTACK capture: baseline.yaml with concurrent benign
- 1 ATTACK capture: reordered.yaml with concurrent benign
- 1 ATTACK capture: slow_burn.yaml with concurrent benign
Enforces disk space checks between runs.
"""

import argparse
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

BENIGN_CONFIGS = [
    {
        "seed": 101,
        "start_hour": 0,
        "name": "day_101",
        "desc": "Night / Low Baseline (00:00-05:00)",
    },
    {
        "seed": 102,
        "start_hour": 5,
        "name": "day_102",
        "desc": "Morning Ramp to Peak (05:00-10:00)",
    },
    {
        "seed": 103,
        "start_hour": 10,
        "name": "day_103",
        "desc": "Midday Peak & Lunch Dip (10:00-15:00)",
    },
    {
        "seed": 104,
        "start_hour": 15,
        "name": "day_104",
        "desc": "Afternoon Peak to Wind-Down (15:00-20:00)",
    },
    {
        "seed": 105,
        "start_hour": 20,
        "name": "day_105",
        "desc": "Evening to Night Low (20:00-01:00)",
    },
]


def main():
    parser = argparse.ArgumentParser(description="Generate SentinelX Telemetry Captures")
    parser.add_argument(
        "--only",
        choices=["all", "benign", "slow_burn"],
        default="all",
        help="Filter which captures to generate (all, benign, slow_burn)",
    )
    args = parser.parse_args()

    print("\n" + "#" * 80)
    print(f"STARTING TELEMETRY CAPTURE PIPELINE (Filter: {args.only.upper()})")
    if args.only in ("all", "benign"):
        print("  - 5 Benign Days (Staggered start hours: 0, 5, 10, 15, 20)")
    if args.only == "all":
        print("  - 1 Attack Demo Baseline (concurrent benign)")
        print("  - 1 Attack Reordered Variant (concurrent benign)")
    if args.only in ("all", "slow_burn"):
        print("  - 1 Attack Slow-Burn Variant (duration ~1020s, 10-15x baseline)")
    print("#" * 80 + "\n")

    start_all = time.time()
    free_start = check_free_disk()
    print(f"Initial available disk space: {free_start:.2f} GB\n")

    # 1. Generate 5 Staggered Benign captures
    if args.only in ("all", "benign"):
        for idx, cfg in enumerate(BENIGN_CONFIGS, 1):
            seed = cfg["seed"]
            sh = cfg["start_hour"]
            desc = cfg["desc"]
            name = cfg["name"]

            print("\n" + "-" * 80)
            print(
                f"[{idx}/5 BENIGN] GENERATING {name.upper()} (Seed: {seed}, Start: {sh:02d}:00, {desc})..."
            )
            print("-" * 80)
            check_free_disk()

            run_capture(
                category="benign",
                name=name,
                mode="benign",
                duration=60.0,
                sim_speed=300.0,  # 60s * 300 = 18,000s = 5.0 simulated hours
                seed=seed,
                skip_reset=False,
                start_hour=sh,
            )

    # 2. Generate Demo Baseline attack capture (with concurrent benign)
    if args.only == "all":
        print("\n" + "-" * 80)
        print("GENERATING ATTACK CAPTURE: attack/demo_baseline (baseline.yaml + benign)...")
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
        print("GENERATING ATTACK CAPTURE: attack/reordered (reordered.yaml + benign)...")
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
    if args.only in ("all", "slow_burn"):
        print("\n" + "-" * 80)
        print(
            "GENERATING ATTACK CAPTURE: attack/slow_burn (slow_burn.yaml ~1020s, 10-15x baseline)..."
        )
        print("-" * 80)
        check_free_disk()

        run_capture(
            category="attack",
            name="slow_burn",
            mode="hybrid",
            scenario_name="slow_burn",
            duration=1050.0,
            sim_speed=96.0,
            seed=203,
            skip_reset=False,
            start_hour=0,  # Starts at 00:00 and spans >24 simulated hours
        )

    total_time = time.time() - start_all
    mins, secs = divmod(int(total_time), 60)
    free_end = check_free_disk()

    print("\n" + "#" * 80)
    print(f"CAPTURE GENERATION PIPELINE COMPLETED (Filter: {args.only.upper()})!")
    print(f"Total Wall Clock Time : {mins:02d}:{secs:02d} ({total_time:.2f}s)")
    print(
        f"Disk Space Start/End  : {free_start:.2f} GB -> {free_end:.2f} GB (Delta: {free_start - free_end:.2f} GB)"
    )
    print("#" * 80 + "\n")


if __name__ == "__main__":
    main()
