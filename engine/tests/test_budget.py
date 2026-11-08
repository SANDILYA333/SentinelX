"""Unit tests for SentinelX Alert Budget Controller."""

from sentinelx.budget.controller import BudgetController


def test_budget_grid_evaluation_and_calibration():
    """Verify BudgetController evaluates threshold grid and chooses optimal threshold."""
    controller = BudgetController()

    # Synthetic incident scores:
    # 5 benign days: day 101-105 produced 0 incidents or low-score anomalies (e.g. 0.25, 0.35)
    benign_scores = [0.25, 0.35, 0.30]
    # 3 attack scenarios: all produced high-scoring incidents (~0.95 - 1.0)
    attack_scores = [0.95, 0.98, 1.0]

    grid = controller.evaluate_threshold_grid(
        candidate_thresholds=[0.30, 0.40, 0.50, 0.60, 0.70, 0.80],
        benign_incident_scores=benign_scores,
        attack_incident_scores=attack_scores,
        total_simulated_benign_days=5.0,
    )

    # At threshold 0.30: some benign scores >= 0.30
    assert grid[0]["threshold"] == 0.30
    assert grid[0]["fp_count"] > 0
    assert grid[0]["recall"] == 1.0

    # At threshold 0.50: 0 benign false positives, 100% recall
    row_50 = next(r for r in grid if r["threshold"] == 0.50)
    assert row_50["fp_count"] == 0
    assert row_50["fp_per_24h"] == 0.0
    assert row_50["recall"] == 1.0
    assert row_50["attacks_caught"] == "3/3"

    # Calibration should select a threshold achieving 0 FP/24h and 100% recall
    optimal_th = controller.calibrate(
        benign_incident_scores=benign_scores,
        attack_incident_scores=attack_scores,
        max_fp_per_24h=0.0,
        total_simulated_benign_days=5.0,
    )
    assert optimal_th >= 0.40
    assert optimal_th <= 0.60
