"""SentinelX correlation pipeline managing signal ingestion, incident state, and budget gating.

Phase A improvements:
  - Task 3: Pipeline exposes hydrate_from_db() so the lifespan manager can restore state before
    accepting new signals.
  - Task 2: alert_threshold is passed to the Correlator so TTFMA uses the operational threshold.
"""

import logging
from typing import Any, Awaitable, Callable

from sentinelx.budget.controller import BudgetController
from sentinelx.correlate.correlator import Correlator
from sentinelx.schemas.incident import Incident
from sentinelx.schemas.signal import Signal

logger = logging.getLogger(__name__)


class CorrelationPipeline:
    """Pipelines incoming Signals into the Correlator, applies budget gating, and persists Incidents."""

    def __init__(
        self,
        db: Any = None,
        window_sec: float = 1800.0,
        budget_threshold: float = 0.50,
        novelty_cap: float = 0.40,
        on_incident: Callable[[Incident], Awaitable[None]] | None = None,
    ):
        self.db = db
        # Pass alert_threshold to the correlator so TTFMA is computed against the same threshold.
        self.correlator = Correlator(
            window_sec=window_sec,
            db=db,
            novelty_cap=novelty_cap,
            alert_threshold=budget_threshold,
        )
        self.budget = BudgetController(threshold=budget_threshold)
        self.on_incident = on_incident

    def reset_state(self) -> None:
        """Reset correlator memory for isolated replay and evaluation."""
        self.correlator.reset_state()

    async def hydrate_from_db(self) -> tuple[int, int]:
        """Restore eligible open incident state from the database.

        Must be called after database initialization and before ingestion begins.
        Returns (restored_count, skipped_expired_count).

        If the correlator has no database configured, logs a warning and returns (0, 0)
        rather than raising, so test pipelines without a DB still work.
        """
        if self.correlator.db is None:
            logger.warning(
                "CorrelationPipeline.hydrate_from_db called but no database is configured; "
                "starting with empty correlator state."
            )
            return 0, 0
        try:
            restored, skipped = self.correlator.hydrate_from_db()
            return restored, skipped
        except Exception as exc:
            # Hydration failure is a degraded-state condition, not a silent no-op.
            logger.error(
                "Correlator hydration FAILED: %s — system starting with empty incident state. "
                "Existing open incidents will not be correlated until the next restart.",
                exc,
            )
            raise

    async def process_signal(self, signal: Signal) -> Incident:
        """Process incoming signal, update incident, persist, and trigger broadcast."""
        incident = self.correlator.process_signal(signal)

        # Notify downstream WebSocket or broadcast listeners
        if self.on_incident is not None:
            try:
                await self.on_incident(incident)
            except Exception as e:
                logger.warning(f"Error in on_incident callback: {e}")

        return incident

    def get_active_incidents(self) -> list[Incident]:
        """Return incidents passing the operational budget threshold."""
        return self.budget.filter_active(self.correlator.get_all_incidents())

    def get_all_incidents(self) -> list[Incident]:
        """Return all tracked incidents including sub-threshold evaluations."""
        return self.correlator.get_all_incidents()
