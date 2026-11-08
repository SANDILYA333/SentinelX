"""SentinelX correlation pipeline managing signal ingestion, incident state, and budget gating."""

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
        self.correlator = Correlator(window_sec=window_sec, db=db, novelty_cap=novelty_cap)
        self.budget = BudgetController(threshold=budget_threshold)
        self.on_incident = on_incident

    def reset_state(self) -> None:
        """Reset correlator memory for isolated replay and evaluation."""
        self.correlator.reset_state()

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
