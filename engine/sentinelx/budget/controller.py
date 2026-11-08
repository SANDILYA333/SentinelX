"""Alert and Incident Budget Controller for false-positive suppression and calibration."""

import logging
from typing import Any

from sentinelx.schemas.incident import Incident

logger = logging.getLogger(__name__)

# Default recommended threshold chosen from leave-one-out benign cross-validation
DEFAULT_INCIDENT_THRESHOLD: float = 0.50


class BudgetController:
    """Manages incident alerting thresholds and evaluates FP budget metrics."""

    def __init__(self, threshold: float = DEFAULT_INCIDENT_THRESHOLD):
        self._threshold = threshold

    @property
    def threshold(self) -> float:
        return self._threshold

    @threshold.setter
    def threshold(self, val: float) -> None:
        self._threshold = max(0.0, min(1.0, float(val)))

    def is_active(self, incident: Incident) -> bool:
        """Check if an incident exceeds the current operational score threshold."""
        return incident.score >= self._threshold

    def filter_active(self, incidents: list[Incident]) -> list[Incident]:
        """Filter a list of incidents returning only those meeting the active threshold."""
        return [inc for inc in incidents if self.is_active(inc)]

    @staticmethod
    def evaluate_threshold_grid(
        candidate_thresholds: list[float],
        benign_incident_scores: list[float],
        attack_incident_scores: list[float],
        total_simulated_benign_days: float = 5.0,
    ) -> list[dict[str, Any]]:
        """Compute precision/recall and daily false-positive rate across candidate thresholds."""
        results: list[dict[str, Any]] = []
        total_attacks = len(attack_incident_scores)

        for th in candidate_thresholds:
            fp_count = sum(1 for s in benign_incident_scores if s >= th)
            fp_per_24h = (
                fp_count / total_simulated_benign_days if total_simulated_benign_days > 0 else 0.0
            )
            tp_count = sum(1 for s in attack_incident_scores if s >= th)
            recall = (tp_count / total_attacks) if total_attacks > 0 else 1.0

            results.append(
                {
                    "threshold": round(th, 2),
                    "fp_count": fp_count,
                    "fp_per_24h": round(fp_per_24h, 3),
                    "attacks_caught": f"{tp_count}/{total_attacks}",
                    "recall": round(recall, 3),
                }
            )

        return results

    def calibrate(
        self,
        benign_incident_scores: list[float],
        attack_incident_scores: list[float],
        max_fp_per_24h: float = 0.0,
        total_simulated_benign_days: float = 5.0,
        min_threshold_floor: float = 0.50,
    ) -> float:
        """Find optimal threshold satisfying max_fp_per_24h with safety buffer while maintaining 100% recall."""
        candidates = [round(x * 0.05, 2) for x in range(6, 19)]  # 0.30 to 0.90
        grid = self.evaluate_threshold_grid(
            candidates,
            benign_incident_scores,
            attack_incident_scores,
            total_simulated_benign_days,
        )

        # Select threshold >= min_threshold_floor that satisfies fp budget and achieves 100% attack recall
        for row in grid:
            if (
                row["threshold"] >= min_threshold_floor
                and row["fp_per_24h"] <= max_fp_per_24h
                and row["recall"] >= 1.0
            ):
                self._threshold = row["threshold"]
                return self._threshold

        # Fallback to default
        self._threshold = DEFAULT_INCIDENT_THRESHOLD
        return self._threshold
