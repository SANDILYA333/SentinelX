"""Ingestor dependency provider for FastAPI routes."""

import sqlite3
from pathlib import Path

from sentinelx.ingest.runtime import Ingestor

from app.config import settings

_ingestor_instance: Ingestor | None = None


def get_ingestor(db: sqlite3.Connection | None = None) -> Ingestor:
    """Retrieve shared Ingestor instance or initialize an idle observer."""
    global _ingestor_instance
    if _ingestor_instance is None:
        _ingestor_instance = Ingestor(
            log_root=settings.SENTINELX_LOG_ROOT,
            db=db or Path(settings.SENTINELX_DB_PATH),
            mode="off",
        )
    return _ingestor_instance


def set_ingestor(ingestor: Ingestor | None) -> None:
    """Set global active Ingestor instance."""
    global _ingestor_instance
    _ingestor_instance = ingestor
