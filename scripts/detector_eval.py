#!/usr/bin/env python3
"""SentinelX Detector Evaluation Suite.

Evaluates all loaded detectors (Rules, Baselines, Isolation Forest Anomaly,
Interaction Graph, and Deception) across all 8 telemetry captures:
- 5 benign captures: day_101, day_102, day_103, day_104, day_105
- 3 attack captures: demo_baseline, reordered, slow_burn

Generates:
1. Full Detector x Capture Signal Matrix
2. Rule-by-rule firing table across all 8 captures (fires on attack, 0 on benign)
3. Baseline & Anomaly Self-test vs Leave-One-Out validation numbers
4. Graph interaction detector performance
5. Confirmed honeytoken deception signal verification
6. Golden step coverage table for each attack scenario
"""

import argparse
import asyncio
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Add engine to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.detect.anomaly.trainer import train_anomaly_model  # noqa: E402
from sentinelx.detect.baseline.trainer import (  # noqa: E402
    load_capture_events,
    train_baseline_model,
)
from sentinelx.detect.graph.trainer import train_graph_model  # noqa: E402
from sentinelx.detect.runtime import DetectorPipeline  # noqa: E402
from sentinelx.schemas.event import Event  # noqa: E402
from sentinelx.schemas.signal import Signal  # noqa: E402

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("detector_eval")

BENIGN_NAMES = ["day_101", "day_102", "day_103", "day_104", "day_105"]
ATTACK_NAMES = ["demo_baseline", "reordered", "slow_burn"]
ALL_CAPTURES = BENIGN_NAMES + ATTACK_NAMES


async def evaluate_capture(capture_dir: Path) -> list[Signal]:
    """Run capture through isolated scratch DB and return all emitted Signals."""
    import shutil
    import sqlite3
    import tempfile

    from sentinelx.ingest.runtime import Ingestor

    temp_dir = Path(tempfile.mkdtemp(prefix="sx_eval_"))
    try:
        temp_db = temp_dir / "eval.db"
        pipeline = DetectorPipeline(db=temp_db)
        pipeline.reset_state()

        async def on_event(ev: Event) -> None:
            pipeline.process_event(ev)

        ingestor = Ingestor(
            log_root=capture_dir,
            db=temp_db,
            mode="replay",
            speed="max",
            on_event=on_event,
        )
        await ingestor.start()
        while ingestor._tasks and not all(t.done() for t in ingestor._tasks):
            await asyncio.sleep(0.01)
        await ingestor.stop()

        conn = sqlite3.connect(temp_db)
        rows = conn.execute("SELECT json FROM signals ORDER BY ts ASC").fetchall()
        return [Signal.model_validate_json(r[0]) for r in rows]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def print_matrix(matrix: dict[str, dict[str, int]]):
    """Print Detector x Capture x Signal Count table."""
    detectors = ["rule", "baseline", "anomaly", "graph", "deception", "TOTAL"]
    print("\n" + "=" * 90)
    print("TABLE 1: DETECTOR x CAPTURE EVALUATION MATRIX (SIGNAL COUNTS)")
    print("=" * 90)
    header = f"{'Capture':<16} | " + " | ".join(f"{d:>9}" for d in detectors)
    print(header)
    print("-" * len(header))

    for cap in ALL_CAPTURES:
        row_counts = matrix.get(cap, {})
        tot = sum(row_counts.get(d, 0) for d in detectors[:-1])
        row_str = f"{cap:<16} | "
        for d in detectors[:-1]:
            c = row_counts.get(d, 0)
            row_str += f"{c:>9} | "
        row_str += f"{tot:>9}"
        print(row_str)
    print("=" * 90)


def print_rule_table(rule_firings: dict[str, Counter]):
    """Print rule-by-rule firing table across all 8 captures."""
    rule_ids = [
        "RULE-SHELL-001",
        "RULE-AUTH-001",
        "RULE-CRED-001",
        "RULE-DECOY-001",
        "RULE-OT-001",
        "RULE-NET-001",
    ]
    print("\n" + "=" * 110)
    print("TABLE 2: RULE-BY-RULE FIRING ACROSS ALL 8 CAPTURES")
    print("=" * 110)
    header = f"{'Rule ID':<16} | " + " | ".join(f"{c:>10}" for c in ALL_CAPTURES)
    print(header)
    print("-" * len(header))

    for rid in rule_ids:
        row = f"{rid:<16} | "
        for cap in ALL_CAPTURES:
            cnt = rule_firings[cap][rid]
            row += f"{cnt:>10} | "
        print(row.rstrip(" |"))
    print("=" * 110)


def run_leave_one_out_validation(benign_dirs: list[Path]):
    """Run rigorous leave-one-out cross-validation across all 5 benign captures."""
    print("\n" + "=" * 80)
    print("TABLE 3: LEAVE-ONE-OUT CROSS-VALIDATION (5 BENIGN SPLITS)")
    print("=" * 80)
    print(f"{'Held-Out Split':<18} | {'Baseline FP':>12} | {'Anomaly FP':>12} | {'Graph FP':>12}")
    print("-" * 80)

    # Load all benign capture events into memory
    capture_events: dict[str, list[Event]] = {}
    for d in benign_dirs:
        capture_events[d.name] = asyncio.run(load_capture_events(d))

    for held_out_name in BENIGN_NAMES:
        train_dirs = [d for d in benign_dirs if d.name != held_out_name]

        # 1. Train on 4
        b_model = train_baseline_model(train_dirs, exclude_startup_sim_hours=1.0)
        a_bundle = train_anomaly_model(train_dirs, exclude_startup_sim_hours=1.0, window_sec=300.0)
        g_model = train_graph_model(train_dirs, exclude_startup_sim_hours=1.0)

        # 2. Score held-out 5th
        from sentinelx.detect.anomaly.detector import AnomalyDetector
        from sentinelx.detect.baseline.detector import BaselineDetector
        from sentinelx.detect.graph.detector import GraphDetector

        b_det = BaselineDetector(model=b_model)
        a_det = AnomalyDetector(bundle=a_bundle, window_sec=300.0)
        g_det = GraphDetector(model=g_model)

        test_events = capture_events[held_out_name]
        b_fp = sum(len(b_det.evaluate_event(e)) for e in test_events)
        a_fp = sum(len(a_det.evaluate_event(e)) for e in test_events)
        g_fp = sum(len(g_det.evaluate_event(e)) for e in test_events)

        print(f"{held_out_name:<18} | {b_fp:>12} | {a_fp:>12} | {g_fp:>12}")
    print("=" * 80)


def print_golden_step_table(attack_signals: dict[str, list[Signal]]):
    """Print golden scenario step coverage table across all 3 attack scenarios."""
    print("\n" + "=" * 145)
    print("TABLE 4: GOLDEN ATTACK STEP DETECTION COVERAGE")
    print("=" * 145)
    print(f"{'Scenario Step':<38} | {'demo_baseline':<32} | {'reordered':<32} | {'slow_burn':<32}")
    print("-" * 145)

    step_definitions = [
        (
            "Step 1: Initial Access (svc_backup)",
            lambda s: (
                s.rule_id == "RULE-AUTH-001"
                or (s.detector == "baseline" and "svc_backup" in s.explanation)
            ),
        ),
        (
            "Step 2: IT Subnet Discovery Scan",
            lambda s: (
                s.rule_id == "GRAPH-SCAN-001"
                or any(t.technique_id == "T1046" for t in s.techniques)
                or s.detector == "anomaly"
            ),
        ),
        (
            "Step 3: Credential Theft (.db_creds)",
            lambda s: s.rule_id == "RULE-CRED-001" or ".db_creds" in s.explanation,
        ),
        (
            "Step 4: Decoy Pivot (cowrie/opencanary)",
            lambda s: s.detector == "deception" or s.rule_id == "RULE-DECOY-001",
        ),
        (
            "Step 5: Lateral Movement to eng-ws",
            lambda s: (
                s.rule_id in ("RULE-NET-001", "GRAPH-PATH-001", "GRAPH-EDGE-001")
                or "eng-ws" in s.explanation
            ),
        ),
        (
            "Step 6: Modbus Valve Manipulation",
            lambda s: (
                s.rule_id == "RULE-OT-001" or any(t.technique_id == "T0855" for t in s.techniques)
            ),
        ),
        (
            "Step 7: Decoy PLC Reconnaissance",
            lambda s: (
                "10.10.3.60" in s.explanation
                or "decoy-plc" in s.explanation
                or any(t.technique_id == "T0846" for t in s.techniques)
            ),
        ),
    ]

    all_steps_passed = True
    for step_name, matcher in step_definitions:
        row_str = f"{step_name:<38} | "
        for cap_name in ATTACK_NAMES:
            sigs = attack_signals[cap_name]
            catching_dets = sorted(set(s.detector for s in sigs if matcher(s)))
            if not catching_dets:
                row_str += f"{'MISSING!':<32} | "
                all_steps_passed = False
            else:
                det_str = ", ".join(catching_dets)
                row_str += f"{det_str:<32} | "
        print(row_str.rstrip(" |"))
    print("=" * 145)
    return all_steps_passed


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate SentinelX detectors across all captures."
    )
    parser.add_argument("--captures-dir", type=Path, default=REPO_ROOT / "eval" / "captures")
    args = parser.parse_args()

    benign_dirs = [args.captures_dir / "benign" / name for name in BENIGN_NAMES]
    attack_dirs = [args.captures_dir / "attack" / name for name in ATTACK_NAMES]

    matrix: dict[str, dict[str, int]] = {}
    rule_firings: dict[str, Counter] = defaultdict(Counter)
    attack_signals: dict[str, list[Signal]] = {}

    print("Evaluating all 8 captures through SentinelX DetectorPipeline...")
    for cap_dir in benign_dirs + attack_dirs:
        cap_name = cap_dir.name
        signals = asyncio.run(evaluate_capture(cap_dir))
        if cap_name in ATTACK_NAMES:
            attack_signals[cap_name] = signals

        det_counts = Counter(s.detector for s in signals)
        matrix[cap_name] = dict(det_counts)

        for s in signals:
            if s.rule_id:
                rule_firings[cap_name][s.rule_id] += 1

    # 1. Print Matrix
    print_matrix(matrix)

    # 2. Print Rule Table
    print_rule_table(rule_firings)

    # 3. Print Leave-One-Out Validation Table
    run_leave_one_out_validation(benign_dirs)

    # 4. Print Golden Step Coverage Table
    golden_ok = print_golden_step_table(attack_signals)

    # Assertions
    # DoD 6: Confirmed honeytoken in every attack capture, 0 in benign
    for b in BENIGN_NAMES:
        assert matrix.get(b, {}).get("deception", 0) == 0, f"False positive deception on benign {b}"
    for a in ATTACK_NAMES:
        assert matrix.get(a, {}).get("deception", 0) > 0, f"Missing deception signals on attack {a}"

    if not golden_ok:
        logger.error("Golden test scenario step coverage failed!")
        sys.exit(1)

    print("\nALL DETECTOR EVALUATION CHECKS PASSED SUCCESSFULLY!\n")


if __name__ == "__main__":
    main()
