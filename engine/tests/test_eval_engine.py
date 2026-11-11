"""Unit tests for SentinelX Detection Evaluation Engine and metric computations."""

from pathlib import Path

import pytest
from sentinelx.eval.engine import (
    DetectionEvaluationEngine,
    compute_metrics,
    compute_percentiles,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_compute_metrics_standard():
    """Verify standard metric calculations."""
    scores = compute_metrics(tp=8, fp=2, fn=2, tn=8)
    assert scores.tp == 8
    assert scores.fp == 2
    assert scores.fn == 2
    assert scores.tn == 8
    assert scores.precision == 0.8
    assert scores.recall == 0.8
    assert scores.f1_score == 0.8
    assert scores.accuracy == 0.8
    assert scores.fpr == 0.2
    assert scores.fnr == 0.2


def test_compute_metrics_zero_division():
    """Verify zero-division returns None gracefully without exceptions."""
    scores = compute_metrics(tp=0, fp=0, fn=0, tn=0)
    assert scores.precision is None
    assert scores.recall is None
    assert scores.f1_score is None
    assert scores.accuracy is None
    assert scores.fpr is None
    assert scores.fnr is None

    scores_no_pos = compute_metrics(tp=0, fp=0, fn=5, tn=5)
    assert scores_no_pos.precision is None
    assert scores_no_pos.recall == 0.0
    assert scores_no_pos.f1_score is None


def test_compute_percentiles():
    """Verify percentile distribution math."""
    samples = [10.0, 20.0, 30.0, 40.0, 50.0]
    p = compute_percentiles(samples)
    assert p.count == 5
    assert p.min_ms == 10.0
    assert p.max_ms == 50.0
    assert p.mean_ms == 30.0
    assert p.p50 == 30.0
    assert p.p90 == 50.0

    empty = compute_percentiles([])
    assert empty.count == 0
    assert empty.mean_ms == 0.0


def test_eval_engine_init():
    """Verify engine loads dataset properly."""
    engine = DetectionEvaluationEngine()
    assert engine.dataset.version == "1.0.0"
    assert len(engine.dataset.scenarios) > 0


@pytest.mark.anyio
async def test_eval_engine_single_capture():
    """Test evaluating a single capture via the engine."""
    engine = DetectionEvaluationEngine()
    cap_path = REPO_ROOT / "eval" / "captures" / "attack" / "demo_baseline"
    if cap_path.is_dir():
        res = await engine.evaluate_capture("demo_baseline", cap_path)
        assert res["capture_name"] == "demo_baseline"
        assert res["events_count"] > 0
        assert len(res["signals"]) > 0
        assert len(res["active_incidents"]) > 0
        assert len(res["l_detect"]) > 0
