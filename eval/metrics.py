#!/usr/bin/env python3
"""SentinelX Incident-Level Precision, Recall, and F1 Metrics Suite (Phase 7).

Computes incident-level performance across all 8 captures with Leave-One-Out (LOO)
cross-validation for the 5 benign folds:
- True Positives (TP): Attack captures yielding an active incident (score >= threshold)
- False Positives (FP): Held-out benign folds yielding an active incident (score >= threshold)
- False Negatives (FN): Attack captures failing to trigger an active incident
- True Negatives (TN): Held-out benign folds producing zero active incidents

Outputs:
1. Headline Incident-Level Metrics (Precision, Recall, F1, Accuracy)
2. Incident Confusion Matrix
3. Threshold Operating Curve & Sensitivity Table (0.10 to 0.90)
"""

import argparse
import asyncio
import json
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

# Add engine to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.correlate.correlator import Correlator  # noqa: E402
from sentinelx.detect.anomaly.detector import AnomalyDetector  # noqa: E402
from sentinelx.detect.anomaly.trainer import train_anomaly_model  # noqa: E402
from sentinelx.detect.baseline.detector import BaselineDetector  # noqa: E402
from sentinelx.detect.baseline.trainer import (  # noqa: E402
    load_capture_events,
    train_baseline_model,
)
from sentinelx.detect.graph.detector import GraphDetector  # noqa: E402
from sentinelx.detect.graph.trainer import train_graph_model  # noqa: E402
from sentinelx.detect.runtime import DetectorPipeline  # noqa: E402
from sentinelx.ingest.runtime import Ingestor  # noqa: E402
from sentinelx.schemas.event import Event  # noqa: E402
from sentinelx.schemas.signal import Signal  # noqa: E402

BENIGN_NAMES = ["day_101", "day_102", "day_103", "day_104", "day_105"]
ATTACK_NAMES = ["demo_baseline", "reordered", "slow_burn"]


BENIGN_HOURS_TOTAL: float = 25.0
BENIGN_SIMULATED_DAYS: float = (
    BENIGN_HOURS_TOTAL / 24.0
)  # 1.04167 days across 5 diurnal slices (5.0h each)


@dataclass
class ConfusionMatrix:
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float


@dataclass
class ThresholdMetrics:
    threshold: float
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1_score: float
    recommendation: str
    fp_rate_per_24h: float = 0.0


@dataclass
class MetricsReport:
    threshold: float
    headline: ConfusionMatrix
    threshold_curve: list[ThresholdMetrics]
    loo_benign_scores: dict[str, list[float]]
    attack_scores: dict[str, float]
    score_margin: float = 0.0
    min_attack_score: float = 0.0
    max_benign_score: float = 0.0
    benign_hours_total: float = BENIGN_HOURS_TOTAL
    benign_simulated_days: float = BENIGN_SIMULATED_DAYS
    benign_fp_per_24h: float = 0.0
    benign_fp_upper_bound_95: float = 3.0 / BENIGN_SIMULATED_DAYS


async def evaluate_attack_capture(cap_dir: Path) -> float:
    """Replay an attack capture through DetectorPipeline and Correlator and return top incident score."""
    with tempfile.TemporaryDirectory(prefix="sx_atk_") as tmpdir:
        temp_db = Path(tmpdir) / "eval.db"
        pipeline = DetectorPipeline(db=temp_db)
        correlator = Correlator(db=temp_db)

        async def on_event(ev: Event) -> None:
            sigs = pipeline.process_event(ev)
            for s in sigs:
                correlator.process_signal(s)

        ingestor = Ingestor(
            log_root=cap_dir,
            db=temp_db,
            mode="replay",
            speed="max",
            on_event=on_event,
        )
        await ingestor.start()
        while ingestor._tasks and not all(t.done() for t in ingestor._tasks):
            await asyncio.sleep(0.005)
        await ingestor.stop()

        incs = correlator.get_all_incidents()
        return incs[0].score if incs else 0.0


def evaluate_loo_and_attacks() -> tuple[dict[str, list[float]], dict[str, float]]:
    """Evaluate 5 LOO benign folds and 3 attack captures, returning incident scores."""
    captures_dir = REPO_ROOT / "eval" / "captures"
    benign_dirs = [captures_dir / "benign" / n for n in BENIGN_NAMES]
    attack_dirs = [captures_dir / "attack" / n for n in ATTACK_NAMES]

    # Preload all benign events
    capture_events: dict[str, list[Event]] = {}
    for d in benign_dirs:
        capture_events[d.name] = asyncio.run(load_capture_events(d))

    loo_benign_scores: dict[str, list[float]] = {}

    for held_out in BENIGN_NAMES:
        train_dirs = [d for d in benign_dirs if d.name != held_out]
        b_model = train_baseline_model(train_dirs, exclude_startup_sim_hours=1.0)
        a_bundle = train_anomaly_model(train_dirs, exclude_startup_sim_hours=1.0, window_sec=300.0)
        g_model = train_graph_model(train_dirs, exclude_startup_sim_hours=1.0)

        b_det = BaselineDetector(model=b_model)
        a_det = AnomalyDetector(bundle=a_bundle, window_sec=300.0)
        g_det = GraphDetector(model=g_model)

        test_events = capture_events[held_out]
        signals: list[Signal] = []
        for e in test_events:
            signals.extend(b_det.evaluate_event(e))
            signals.extend(a_det.evaluate_event(e))
            signals.extend(g_det.evaluate_event(e))

        correlator = Correlator(db=None)
        for s in signals:
            correlator.process_signal(s)

        scores = [round(inc.score, 4) for inc in correlator.get_all_incidents()]
        loo_benign_scores[held_out] = scores

    attack_scores: dict[str, float] = {}
    for ad in attack_dirs:
        score = asyncio.run(evaluate_attack_capture(ad))
        attack_scores[ad.name] = round(score, 4)

    return loo_benign_scores, attack_scores


def compute_metrics_report(
    loo_benign_scores: dict[str, list[float]],
    attack_scores: dict[str, float],
    calibrated_threshold: float = 0.50,
) -> MetricsReport:
    """Compute headline confusion matrix and threshold sensitivity table with derived commentary."""
    thresholds = [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]
    curve: list[ThresholdMetrics] = []

    # Score margins computed directly from data
    min_atk = min(attack_scores.values()) if attack_scores else 0.0
    all_benign_scores = [s for scores in loo_benign_scores.values() for s in scores]
    max_ben = max(all_benign_scores) if all_benign_scores else 0.0
    margin = round(min_atk - max_ben, 4)

    for th in thresholds:
        tp = sum(1 for s in attack_scores.values() if s >= th)
        fn = len(attack_scores) - tp

        # Benign fold FP: fold counts as FP if any incident score in that fold >= th
        fp = sum(1 for scores in loo_benign_scores.values() if any(s >= th for s in scores))
        tn = len(loo_benign_scores) - fp

        # Derive classification/recommendation dynamically from computed TP, FP, FN and margins
        if fp > 0:
            rec = (
                f"Sub-optimal: {fp} benign FP(s) (threshold <= max LOO benign score {max_ben:.2f})"
            )
        elif fn > 0:
            rec = f"Sub-optimal: {fn} attack(s) missed (threshold > min attack score {min_atk:.2f})"
        else:
            dist_ben = round(th - max_ben, 2)
            dist_atk = round(min_atk - th, 2)
            if abs(th - calibrated_threshold) < 0.01:
                rec = f"Recommended (Zero FP, 100% Recall; margin: +{dist_ben:.2f} above benign, +{dist_atk:.2f} below attack)"
            else:
                rec = f"Viable operating band (Zero FP, 100% Recall; margin: +{dist_ben:.2f} above benign, +{dist_atk:.2f} below attack)"

        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (prec * recall) / (prec + recall) if (prec + recall) > 0 else 0.0
        fp_rate = (fp / BENIGN_SIMULATED_DAYS) if fp > 0 else 0.0

        curve.append(
            ThresholdMetrics(
                threshold=th,
                tp=tp,
                fp=fp,
                fn=fn,
                tn=tn,
                precision=prec,
                recall=recall,
                f1_score=f1,
                recommendation=rec,
                fp_rate_per_24h=round(fp_rate, 4),
            )
        )

    # Headline at calibrated threshold
    headline_th = next(c for c in curve if abs(c.threshold - calibrated_threshold) < 0.01)
    headline_cm = ConfusionMatrix(
        tp=headline_th.tp,
        fp=headline_th.fp,
        fn=headline_th.fn,
        tn=headline_th.tn,
        precision=headline_th.precision,
        recall=headline_th.recall,
        f1_score=headline_th.f1_score,
        accuracy=(headline_th.tp + headline_th.tn)
        / (headline_th.tp + headline_th.tn + headline_th.fp + headline_th.fn),
    )

    headline_fp_rate = (headline_cm.fp / BENIGN_SIMULATED_DAYS) if headline_cm.fp > 0 else 0.0
    headline_ub_95 = (
        3.0 / BENIGN_SIMULATED_DAYS
        if headline_cm.fp == 0
        else (headline_cm.fp + 3.0) / BENIGN_SIMULATED_DAYS
    )

    return MetricsReport(
        threshold=calibrated_threshold,
        headline=headline_cm,
        threshold_curve=curve,
        loo_benign_scores=loo_benign_scores,
        attack_scores=attack_scores,
        score_margin=margin,
        min_attack_score=min_atk,
        max_benign_score=max_ben,
        benign_hours_total=BENIGN_HOURS_TOTAL,
        benign_simulated_days=BENIGN_SIMULATED_DAYS,
        benign_fp_per_24h=round(headline_fp_rate, 4),
        benign_fp_upper_bound_95=round(headline_ub_95, 3),
    )


def print_metrics_report(report: MetricsReport) -> None:
    """Print master precision/recall and confusion matrix report."""
    hl = report.headline
    print("\n" + "=" * 115)
    print(f"INCIDENT-LEVEL EVALUATION REPORT & METRICS (BUDGET THRESHOLD = {report.threshold:.2f})")
    print("=" * 115)

    print("\n1. HEADLINE PERFORMANCE SUMMARY:")
    print(
        f"  * Precision:       {hl.precision * 100.0:.2f}% (True Positives: {hl.tp}/{hl.tp + hl.fp})"
    )
    print(
        f"  * Recall:          {hl.recall * 100.0:.2f}% (Attacks Caught: {hl.tp}/{hl.tp + hl.fn})"
    )
    print(f"  * F1 Score:        {hl.f1_score:.4f}")
    print(
        f"  * Classification:  {hl.accuracy * 100.0:.2f}% ({hl.tp + hl.tn}/{hl.tp + hl.tn + hl.fp + hl.fn} captures correctly gated)"
    )
    print(
        f"  * Benign FP Rate:  {report.benign_fp_per_24h:.3f} FP / 24h "
        f"({hl.fp} FP across {report.benign_hours_total:.1f} simulated hours = {report.benign_simulated_days:.3f} simulated days)"
    )
    print(
        f"  * 95% Upper Bound: {report.benign_fp_upper_bound_95:.3f} FP / 24h (Rule of Three: 3 / days when FP = 0)"
    )
    print(
        f"  * Score Separation Margin: {report.score_margin:.4f} "
        f"(Min Attack: {report.min_attack_score:.4f} - Max LOO Benign: {report.max_benign_score:.4f})"
    )

    print("\n2. INCIDENT CONFUSION MATRIX (At Calibrated Threshold 0.50):")
    print("  " + "-" * 62)
    print("  |                     | Actual Attack (Pos) | Actual Benign (Neg) |")
    print("  " + "-" * 62)
    print(
        f"  | Predicted Attack    | TP = {hl.tp:<14} | FP = {hl.fp:<14} | Total Pred Pos: {hl.tp + hl.fp}"
    )
    print(
        f"  | Predicted Benign    | FN = {hl.fn:<14} | TN = {hl.tn:<14} | Total Pred Neg: {hl.fn + hl.tn}"
    )
    print("  " + "-" * 62)
    print(
        f"  | Total Actuals       | Total Pos: {hl.tp + hl.fn:<8} | Total Neg: {hl.tn + hl.fp:<8} | Total Folds: 8"
    )
    print("  " + "-" * 62)

    print("\n3. THRESHOLD SENSITIVITY & ROC OPERATING CURVE:")
    print("=" * 115)
    print(
        f"{'Threshold':<10} | {'TP':<4} | {'FP':<4} | {'FN':<4} | {'TN':<4} | {'Precision':<10} | {'Recall':<8} | {'F1':<6} | {'Operational Status'}"
    )
    print("-" * 115)
    for c in report.threshold_curve:
        marker = " <--" if abs(c.threshold - report.threshold) < 0.01 else ""
        print(
            f"{c.threshold:<10.2f} | {c.tp:<4} | {c.fp:<4} | {c.fn:<4} | {c.tn:<4} | "
            f"{c.precision * 100:<9.1f}% | {c.recall * 100:<7.1f}% | {c.f1_score:<6.3f} | {c.recommendation}{marker}"
        )
    print("=" * 115)


def main():
    parser = argparse.ArgumentParser(description="SentinelX Incident Metrics Suite")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")
    parser.add_argument(
        "--threshold", type=float, default=0.50, help="Budget threshold (default: 0.50)"
    )
    args = parser.parse_args()

    loo_scores, atk_scores = evaluate_loo_and_attacks()
    report = compute_metrics_report(loo_scores, atk_scores, calibrated_threshold=args.threshold)

    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        print_metrics_report(report)


if __name__ == "__main__":
    main()
