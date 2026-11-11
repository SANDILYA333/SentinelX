"""CLI entry point for running SentinelX detection evaluation (`python -m sentinelx.eval`).

Validates the ground-truth dataset, executes multi-level evaluation across
all captures and detection engines, persists results to SQLite, and prints
a comprehensive evaluation summary.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from sentinelx.eval.engine import GROUND_TRUTH_PATH, DetectionEvaluationEngine
from sentinelx.schemas.eval import GroundTruthDataset
from sentinelx.store.sqlite import init_db, save_evaluation_run

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelx.eval")

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = REPO_ROOT / "data" / "sentinelx.db"
REPORTS_DIR = REPO_ROOT / "eval" / "reports"


def validate_ground_truth(path: Path) -> GroundTruthDataset:
    """Validate dataset schema and invariants before evaluation."""
    if not path.exists():
        raise FileNotFoundError(f"Ground truth dataset not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    dataset = GroundTruthDataset.model_validate(data)

    scenario_ids: set[str] = set()
    for sc in dataset.scenarios:
        if sc.scenario_id in scenario_ids:
            raise ValueError(f"Duplicate scenario_id detected: {sc.scenario_id}")
        scenario_ids.add(sc.scenario_id)

        if sc.is_malicious:
            if not sc.expected_detections and not sc.expected_attack_stages:
                raise ValueError(
                    f"Malicious scenario {sc.scenario_id} must have expected detections or attack stages."
                )
        else:
            if sc.expected_detections:
                raise ValueError(
                    f"Benign scenario {sc.scenario_id} must not specify expected malicious detections."
                )

    return dataset


async def run_cli() -> int:
    parser = argparse.ArgumentParser(
        description="SentinelX Detection Evaluation Engine (Phase D)",
        prog="python -m sentinelx.eval",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=GROUND_TRUTH_PATH,
        help="Path to ground truth dataset JSON file",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help="Path to SQLite database for persisting run results",
    )
    parser.add_argument(
        "--budget-threshold",
        type=float,
        default=0.50,
        help="Alert budget controller incident score threshold (default: 0.50)",
    )
    parser.add_argument(
        "--splits",
        nargs="+",
        default=["dev", "validation", "test"],
        choices=["dev", "validation", "test"],
        help="Dataset splits to evaluate (default: dev validation test)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPORTS_DIR / "phase_d_eval_summary.json",
        help="Output JSON summary report path",
    )
    args = parser.parse_args()

    # 1. Dataset validation
    print("=" * 80)
    print("SENTINELX PHASE D: DETECTION EVALUATION HARNESS")
    print("=" * 80)
    print(f"Validating dataset: {args.dataset}")
    try:
        dataset = validate_ground_truth(args.dataset)
        print(
            f"Dataset validated successfully: {len(dataset.scenarios)} scenarios (v{dataset.version})"
        )
    except Exception as exc:
        print(f"DATASET VALIDATION FAILED: {exc}", file=sys.stderr)
        return 1

    # 2. Run evaluation
    print(f"Executing multi-tier evaluation across splits: {args.splits}...")
    engine = DetectionEvaluationEngine(ground_truth_path=args.dataset)
    try:
        summary = await engine.run_full_evaluation(
            splits=args.splits,
            budget_threshold=args.budget_threshold,
        )
    except Exception as exc:
        logger.exception("Evaluation execution encountered fatal error")
        print(f"EVALUATION EXECUTION FAILED: {exc}", file=sys.stderr)
        return 2

    # 3. Print tabular summary
    print("-" * 80)
    print(f"Run ID:            {summary.run_id}")
    print(f"Git Commit:        {summary.git_commit}")
    print(f"Dataset Version:   {summary.dataset_version}")
    print(f"Throughput:        {summary.throughput_eps:.1f} events/sec")
    print("-" * 80)
    print(
        f"{'Granularity':<18} | {'TP':<4} | {'FP':<4} | {'FN':<4} | {'TN':<4} | {'Precision':<9} | {'Recall':<7} | {'F1':<6}"
    )
    print("-" * 80)

    def fmt_row(name: str, m) -> str:
        p_str = f"{m.precision:.4f}" if m.precision is not None else "N/A"
        r_str = f"{m.recall:.4f}" if m.recall is not None else "N/A"
        f_str = f"{m.f1_score:.4f}" if m.f1_score is not None else "N/A"
        return f"{name:<18} | {m.tp:<4} | {m.fp:<4} | {m.fn:<4} | {m.tn:<4} | {p_str:<9} | {r_str:<7} | {f_str:<6}"

    print(fmt_row("Headline (Scenario)", summary.headline))
    print(fmt_row("Incident Level", summary.incident_level))
    print(fmt_row("Event Level", summary.event_level))
    print("-" * 80)

    print("DETECTOR PERFORMANCE BREAKDOWN:")
    for d in summary.detectors:
        print(
            f"  • {d.detector:<12}: TP={d.metrics.tp:<3} FP={d.metrics.fp:<3} FN={d.metrics.fn:<3} TN={d.metrics.tn:<3} "
            f"Prec={d.metrics.precision if d.metrics.precision is not None else 'N/A'} "
            f"Rec={d.metrics.recall if d.metrics.recall is not None else 'N/A'} "
            f"Total Signals={d.total_signals}"
        )

    print("-" * 80)
    print("DETECTION LATENCY PROFILES (ms):")
    lat = summary.latency
    print(
        f"  • Detector Processing: P50={lat.detector_latency.p50:.2f}ms  P95={lat.detector_latency.p95:.2f}ms  P99={lat.detector_latency.p99:.2f}ms"
    )
    print(
        f"  • Correlator Latency:  P50={lat.correlator_latency.p50:.2f}ms  P95={lat.correlator_latency.p95:.2f}ms  P99={lat.correlator_latency.p99:.2f}ms"
    )
    print(
        f"  • End-to-End Latency:  P50={lat.end_to_end_latency.p50:.2f}ms  P95={lat.end_to_end_latency.p95:.2f}ms  P99={lat.end_to_end_latency.p99:.2f}ms"
    )

    print("-" * 80)
    print("ALERT BUDGET CONTROLLER METRICS:")
    b = summary.budget
    print(
        f"  • Emitted Signals: {b.total_signals_emitted} | Admitted: {b.admitted_signals} | Suppressed: {b.suppressed_signals}"
    )
    print(f"  • High Severity Preservation Rate: {b.high_severity_preservation_rate * 100:.1f}%")
    print(
        f"  • Critical Attacks Suppressed: {b.critical_signals_suppressed} (Attacks Safely Admitted: {b.budget_admitted_without_suppressing_attacks})"
    )

    print("-" * 80)
    print(f"SCENARIOS EVALUATED: {len(summary.scenarios)}")
    for sc in summary.scenarios:
        status_symbol = "✓ PASS" if sc.classification in ("TP", "TN") else "✗ MISS"
        print(
            f"  [{sc.classification:<2}] {status_symbol} {sc.scenario_id:<14} ({sc.category:<16}) - {sc.name}"
        )

    if summary.false_negatives:
        print("-" * 80)
        print(f"FALSE NEGATIVES ({len(summary.false_negatives)} Missed Attack Scenarios):")
        for fn in summary.false_negatives:
            print(f"  ✗ {fn['scenario_id']}: {fn['name']} ({fn['category']})")

    # 4. Persistence
    try:
        args.db.parent.mkdir(parents=True, exist_ok=True)
        conn = init_db(args.db)
        save_evaluation_run(conn, summary)
        print("-" * 80)
        print(f"Evaluation run persisted successfully to SQLite database: {args.db}")
    except Exception as exc:
        print(f"Warning: Failed to persist to SQLite: {exc}", file=sys.stderr)

    # 5. Export JSON report
    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(summary.model_dump_json(indent=2))
        print(f"Detailed JSON scorecard exported: {args.out}")
    except Exception as exc:
        print(f"Warning: Failed to export JSON scorecard: {exc}", file=sys.stderr)

    print("=" * 80)
    print("PHASE D EVALUATION COMPLETED DETERMINISTICALLY.")
    print("=" * 80)
    return 0


def main() -> None:
    code = asyncio.run(run_cli())
    sys.exit(code)


if __name__ == "__main__":
    main()
