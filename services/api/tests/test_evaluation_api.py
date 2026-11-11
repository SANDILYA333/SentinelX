"""Integration tests for SentinelX Detection Evaluation API endpoints (Workstream D5)."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.config import settings
from app.db import close_db, get_db
from app.main import app
from fastapi.testclient import TestClient
from sentinelx.eval.engine import compute_metrics, compute_percentiles
from sentinelx.schemas.eval import (
    BudgetEvaluationMetric,
    DetectorEvaluationMetric,
    EvaluationRunSummary,
    LatencyMetrics,
    RuleEvaluationMetric,
    ScenarioEvaluationResult,
)
from sentinelx.store.sqlite import save_evaluation_run


@pytest.fixture(autouse=True)
def test_db_env(monkeypatch):
    """Use a temporary SQLite database for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_db = Path(tmpdir) / "test_api_eval.db"
        monkeypatch.setattr(settings, "SENTINELX_DB_PATH", tmp_db)
        monkeypatch.setattr(settings, "SENTINELX_ENV", "dev")
        close_db()
        get_db()
        yield
        close_db()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def create_seeded_run(run_id: str = "eval-test-01") -> EvaluationRunSummary:
    now = datetime(2026, 11, 10, 15, 0, 0, tzinfo=UTC)
    scores = compute_metrics(12, 1, 0, 8)
    return EvaluationRunSummary(
        run_id=run_id,
        created_at=now,
        git_commit="d3f4b5a",
        dataset_version="1.0.0",
        splits_evaluated=["dev", "validation", "test"],
        headline=scores,
        event_level=scores,
        scenario_level=scores,
        incident_level=scores,
        detectors=[
            DetectorEvaluationMetric(
                detector="rule",
                metrics=scores,
                total_signals=10,
                attack_signals=9,
                benign_signals=1,
            )
        ],
        rules=[
            RuleEvaluationMetric(
                rule_id="RULE-OT-001",
                title="Unauthorized Modbus Write",
                metrics=scores,
                total_fires=5,
                attack_fires=5,
                benign_fires=0,
            )
        ],
        latency=LatencyMetrics(
            ingest_latency=compute_percentiles([0.5, 1.0]),
            detector_latency=compute_percentiles([4.0, 5.0]),
            correlator_latency=compute_percentiles([1.5, 2.0]),
            end_to_end_latency=compute_percentiles([6.0, 8.0]),
            time_to_detect=compute_percentiles([10.0, 15.0]),
        ),
        budget=BudgetEvaluationMetric(
            total_signals_emitted=15,
            admitted_signals=15,
            suppressed_signals=0,
            suppression_ratio=0.0,
            critical_signals_admitted=3,
            critical_signals_suppressed=0,
            high_severity_preservation_rate=1.0,
            incidents_formed=1,
            active_incidents=1,
            budget_admitted_without_suppressing_attacks=True,
        ),
        scenarios=[
            ScenarioEvaluationResult(
                scenario_id="SCEN-OT-001",
                name="Modbus Write Manipulation",
                category="industrial_ot",
                split="dev",
                is_malicious=True,
                detected=True,
                classification="TP",
                score=0.95,
                matched_rules=["RULE-OT-001"],
                matched_detectors=["rule"],
            ),
            ScenarioEvaluationResult(
                scenario_id="SCEN-AUTH-002",
                name="Legitimate Admin SSH",
                category="authentication",
                split="dev",
                is_malicious=False,
                detected=False,
                classification="TN",
                score=0.0,
            ),
        ],
        false_positives=[],
        false_negatives=[],
        throughput_eps=185.0,
    )


def test_evaluation_api_endpoints(client: TestClient):
    """Test all evaluation REST API endpoints end-to-end."""
    db = get_db()
    run = create_seeded_run("eval-test-01")
    save_evaluation_run(db, run)

    # 1. Overview
    resp = client.get("/api/v1/evaluation/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert data["latest_run_id"] == "eval-test-01"
    assert data["headline"]["tp"] == 12
    assert data["throughput_eps"] == 185.0
    assert data["total_historical_runs"] == 1

    # 2. List Runs
    resp = client.get("/api/v1/evaluation/runs")
    assert resp.status_code == 200
    runs = resp.json()
    assert len(runs) == 1
    assert runs[0]["run_id"] == "eval-test-01"

    # 3. Get Specific Run
    resp = client.get("/api/v1/evaluation/runs/eval-test-01")
    assert resp.status_code == 200
    run_detail = resp.json()
    assert run_detail["run_id"] == "eval-test-01"
    assert len(run_detail["scenarios"]) == 2

    # 4. Unknown Run 404
    resp = client.get("/api/v1/evaluation/runs/unknown-id")
    assert resp.status_code == 404

    # 5. Detectors
    resp = client.get("/api/v1/evaluation/runs/eval-test-01/detectors")
    assert resp.status_code == 200
    dets = resp.json()
    assert len(dets) == 1
    assert dets[0]["detector"] == "rule"

    # 6. Scenarios (with filter)
    resp = client.get("/api/v1/evaluation/runs/eval-test-01/scenarios")
    assert resp.status_code == 200
    scs = resp.json()
    assert len(scs) == 2

    resp_filtered = client.get(
        "/api/v1/evaluation/runs/eval-test-01/scenarios?category=industrial_ot"
    )
    assert resp_filtered.status_code == 200
    filtered_scs = resp_filtered.json()
    assert len(filtered_scs) == 1
    assert filtered_scs[0]["scenario_id"] == "SCEN-OT-001"

    # 7. False Positives & Negatives
    resp_fp = client.get("/api/v1/evaluation/runs/eval-test-01/false-positives")
    assert resp_fp.status_code == 200
    assert resp_fp.json() == []

    resp_fn = client.get("/api/v1/evaluation/runs/eval-test-01/false-negatives")
    assert resp_fn.status_code == 200
    assert resp_fn.json() == []

    # 8. Performance
    resp_perf = client.get("/api/v1/evaluation/runs/eval-test-01/performance")
    assert resp_perf.status_code == 200
    perf = resp_perf.json()
    assert "latency" in perf
    assert perf["throughput_eps"] == 185.0
    assert perf["budget"]["high_severity_preservation_rate"] == 1.0

    # 9. History
    resp_hist = client.get("/api/v1/evaluation/history")
    assert resp_hist.status_code == 200
    assert len(resp_hist.json()) == 1
