"""Unit and integration tests for SentinelX Phase 7 evaluation suite."""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from eval.ablation import run_capture_ablation  # noqa: E402
from eval.metrics import (  # noqa: E402
    compute_benign_hours_total,
    compute_metrics_report,
    compute_poisson_95_upper_bound,
)
from eval.organizer_test import run_organizer_evaluation  # noqa: E402


@pytest.mark.anyio
async def test_organizer_windows_fixture_execution():
    """Verify organizer Windows EVTX test runs, ingests events, and emits signals."""
    fixture_path = REPO_ROOT / "eval" / "fixtures" / "organizer_windows_events.jsonl"
    events, signals, incidents, result = await run_organizer_evaluation(
        fixture_path, threshold=0.50
    )

    assert result.events_ingested == 12
    assert result.signals_emitted > 0
    assert result.incidents_formed >= 1
    assert 0.0 <= result.top_score <= 1.0
    assert result.top_score >= 0.50  # Correlates above threshold
    assert "RULE-SHELL-001" in result.fired_rules
    # Assert Windows-appropriate technique mapping: generic T1059 and T1021, not Unix/SSH sub-techniques
    assert "T1059" in result.detected_techniques
    assert "T1021" in result.detected_techniques
    assert "T1059.004" not in result.detected_techniques
    assert "T1021.004" not in result.detected_techniques
    assert len(result.what_detected) >= 3
    assert len(result.what_missed) >= 3


@pytest.mark.anyio
async def test_organizer_windows_benign_fixture_execution():
    """Verify benign Windows fixture is evaluated and test unfamiliar telemetry false-positive behavior."""
    benign_fixture_path = REPO_ROOT / "eval" / "fixtures" / "organizer_windows_benign.jsonl"
    assert benign_fixture_path.exists(), "organizer_windows_benign.jsonl fixture must exist"

    events, signals, incidents, result = await run_organizer_evaluation(
        benign_fixture_path, threshold=0.50
    )

    assert result.events_ingested == 14
    assert result.signals_emitted > 0  # Baseline & Graph emit novelty signals
    # Unfamiliar baseline signals must only come from baseline and graph, NOT rules
    assert "RULE-SHELL-001" not in result.fired_rules
    assert set(result.detectors_fired).issubset({"baseline", "graph"})
    assert "T1059" not in result.detected_techniques
    assert 0.0 <= result.top_score <= 1.0


def test_poisson_95_upper_bound():
    """Verify exact one-sided 95% Poisson upper confidence limit per 24 hours.

    Note: fp counts captures with an incident at or above threshold, not individual incidents.
    """
    days = 25.0 / 24.0  # nominal 1.04167 days
    # k = 0: upper_events = chi2.ppf(0.95, 2)/2 = 2.9957 -> ~2.996 / days
    ub0 = compute_poisson_95_upper_bound(0, days)
    assert abs(ub0 - (2.995732 / days)) < 0.01
    assert round(ub0, 3) == round(2.996 / days, 3)

    # k = 1: upper_events = chi2.ppf(0.95, 4)/2 = 4.7439 -> ~4.744 / days
    ub1 = compute_poisson_95_upper_bound(1, days)
    assert abs(ub1 - (4.743865 / days)) < 0.01
    assert round(ub1, 3) == round(4.744 / days, 3)


def test_computed_benign_hours_total(tmp_path):
    """Verify computed total benign hours is within 0.1h of 25.0 and fails loudly on missing or zero-duration captures."""
    computed_hours = compute_benign_hours_total()
    assert abs(computed_hours - 25.0) < 0.1, f"Expected within 0.1h of 25.0, got {computed_hours}"

    # Fails loudly if any capture is missing
    with pytest.raises(FileNotFoundError):
        compute_benign_hours_total(captures_dir=tmp_path / "nonexistent")

    # Fails loudly if a capture directory has zero duration
    fake_benign = tmp_path / "fake_benign"
    fake_benign.mkdir()
    for day in ["day_101", "day_102", "day_103", "day_104", "day_105"]:
        d_dir = fake_benign / day
        d_dir.mkdir()
        # Write manifest with 0 duration
        (d_dir / "manifest.json").write_text('{"total_sim_hours": 0.0}')

    with pytest.raises(ValueError, match=r"zero (duration|events)"):
        compute_benign_hours_total(captures_dir=fake_benign)


def test_metrics_computation_ranges():
    """Verify compute_metrics_report calculates valid statistical metrics."""
    synthetic_loo_benign = {
        "day_101": [0.15],
        "day_102": [],
        "day_103": [0.42],
        "day_104": [],
        "day_105": [0.20],
    }
    synthetic_attacks = {
        "demo_baseline": 1.00,
        "reordered": 1.00,
        "slow_burn": 1.00,
    }

    report = compute_metrics_report(
        loo_benign_scores=synthetic_loo_benign,
        attack_scores=synthetic_attacks,
        calibrated_threshold=0.50,
    )

    # Headline at 0.50: all 3 attacks >= 0.50, zero benign >= 0.50
    assert report.headline.tp == 3
    assert report.headline.fp == 0
    assert report.headline.fn == 0
    assert report.headline.tn == 5
    assert report.headline.precision == 1.0
    assert report.headline.recall == 1.0
    assert report.headline.f1_score == 1.0
    assert report.headline.accuracy == 1.0

    # Sensitivity curve check
    assert len(report.threshold_curve) == 9
    for point in report.threshold_curve:
        assert 0.0 <= point.precision <= 1.0
        assert 0.0 <= point.recall <= 1.0
        assert 0.0 <= point.f1_score <= 1.0
        assert point.tp + point.fn == 3
        assert point.fp + point.tn == 5


@pytest.mark.anyio
async def test_ablation_single_capture_execution():
    """Smoke test: run_capture_ablation on day_101 with rules-only configuration."""
    all_incs, act_incs, sigs, ev_count = await run_capture_ablation(
        capture_name="day_101",
        detectors=["rule"],
        threshold=0.50,
    )

    assert ev_count > 0
    assert isinstance(sigs, list)
    assert len(act_incs) == 0  # Zero benign false positives on day_101


def test_scorecard_artifact_integrity():
    """Verify scorecard.md report is present and contains required Phase 7 sections."""
    scorecard_path = REPO_ROOT / "eval" / "reports" / "scorecard.md"
    assert scorecard_path.exists(), "scorecard.md must exist in eval/reports/"

    content = scorecard_path.read_text(encoding="utf-8")
    assert "## 1. Executive Summary & Headline Metrics" in content
    assert "## 2. Detector Layer Ablation Study" in content
    assert "## 3. Incident-Level Precision, Recall, and Confusion Matrix" in content
    assert "## 4. Golden Attack Step Coverage & TTFMA Summary" in content
    assert "## 5. Detector Contribution & Real Ranking Matrix" in content
    assert "## 6. Organizer-Log Robustness Test & Context Boundaries" in content
    assert "## 7. Operational Limitations & Threat Model Boundaries" in content
    assert "100.0%" in content
    assert "0.000 FP / 24h" in content
