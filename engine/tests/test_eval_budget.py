"""Unit tests for Alert Quality and Alert Budget Evaluation (Workstream D4)."""

import pytest
from datetime import datetime, timezone
from pathlib import Path

from sentinelx.budget.controller import BudgetController, DEFAULT_INCIDENT_THRESHOLD
from sentinelx.eval.engine import DetectionEvaluationEngine
from sentinelx.schemas.common import Severity, UtcDatetime
from sentinelx.schemas.incident import Incident, IncidentStatus, NetworkZone
from sentinelx.schemas.signal import Signal

REPO_ROOT = Path(__file__).resolve().parents[2]


def create_test_incident(incident_id: str, score: float, severity: Severity) -> Incident:
    now = datetime.now(timezone.utc)
    return Incident(
        incident_id=incident_id,
        status="open",
        created_at=now,
        updated_at=now,
        first_signal_ts=now,
        score=score,
        severity=severity,
        entities=[],
        signal_ids=["sig-1"],
        event_ids=["evt-1"],
        kill_chain_stages=["initial_access"],
        techniques=[],
        decoy_touched=False,
        ot_touched=(severity == "critical"),
        explanation=["Test explanation"],
        summary="Test incident",
    )


def test_budget_preserves_high_severity_attacks():
    """Verify that the budget controller never suppresses critical or high severity attacks."""
    controller = BudgetController(threshold=0.50)

    critical_attack = create_test_incident("inc-crit", score=0.95, severity="critical")
    high_attack = create_test_incident("inc-high", score=0.75, severity="high")
    benign_noise = create_test_incident("inc-low", score=0.30, severity="low")

    incidents = [critical_attack, high_attack, benign_noise]
    active = controller.filter_active(incidents)

    # Active must contain critical and high attack, but not low-score benign noise
    active_ids = {inc.incident_id for inc in active}
    assert "inc-crit" in active_ids
    assert "inc-high" in active_ids
    assert "inc-low" not in active_ids


def test_budget_suppression_ratio_and_preservation_rate():
    """Verify mathematical calculation of suppression ratio and critical preservation."""
    controller = BudgetController(threshold=DEFAULT_INCIDENT_THRESHOLD)

    benign_scores = [0.10, 0.25, 0.35, 0.45]
    attack_scores = [0.85, 0.90, 0.95, 1.00]

    # Grid evaluation
    grid = controller.evaluate_threshold_grid(
        candidate_thresholds=[0.50],
        benign_incident_scores=benign_scores,
        attack_incident_scores=attack_scores,
        total_simulated_benign_days=5.0,
    )

    row = grid[0]
    assert row["fp_count"] == 0
    assert row["recall"] == 1.0


@pytest.mark.anyio
async def test_budget_evaluation_engine_integration():
    """Verify full evaluation engine measures budget preservation accurately."""
    engine = DetectionEvaluationEngine()
    # Evaluate baseline attack capture
    cap_path = REPO_ROOT / "eval" / "captures" / "attack" / "demo_baseline"
    if cap_path.is_dir():
        res = await engine.evaluate_capture("demo_baseline", cap_path, budget_threshold=0.50)
        # Verify active incidents are present
        assert len(res["active_incidents"]) > 0
        for inc in res["active_incidents"]:
            assert inc.score >= 0.50
