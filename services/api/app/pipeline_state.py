"""State manager for CorrelationPipeline and GuardEvaluator in API lifespan."""

import sqlite3
from pathlib import Path

from sentinelx.correlate.pipeline import CorrelationPipeline
from sentinelx.guard.evaluator import GuardEvaluator

from app.config import settings

_correlation_pipeline: CorrelationPipeline | None = None
_guard_evaluator: GuardEvaluator | None = None


def get_correlation_pipeline(db: sqlite3.Connection | None = None) -> CorrelationPipeline:
    """Retrieve shared CorrelationPipeline instance or initialize default."""
    global _correlation_pipeline
    if _correlation_pipeline is None:
        _correlation_pipeline = CorrelationPipeline(
            db=db or Path(settings.SENTINELX_DB_PATH),
        )
    return _correlation_pipeline


def set_correlation_pipeline(pipeline: CorrelationPipeline | None) -> None:
    """Set global active CorrelationPipeline instance."""
    global _correlation_pipeline
    _correlation_pipeline = pipeline


def get_guard_evaluator(db: sqlite3.Connection | None = None) -> GuardEvaluator:
    """Retrieve shared GuardEvaluator instance or initialize default."""
    global _guard_evaluator
    if _guard_evaluator is None:
        _guard_evaluator = GuardEvaluator(
            db=db or Path(settings.SENTINELX_DB_PATH),
        )
    return _guard_evaluator


def set_guard_evaluator(evaluator: GuardEvaluator | None) -> None:
    """Set global active GuardEvaluator instance."""
    global _guard_evaluator
    _guard_evaluator = evaluator
