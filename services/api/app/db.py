"""Database dependency provider for FastAPI routes."""

import sqlite3

from sentinelx.store.sqlite import init_db

from app.config import settings

_db_instance: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    """Retrieve shared SQLite database connection."""
    global _db_instance
    if _db_instance is None:
        _db_instance = init_db(settings.SENTINELX_DB_PATH)
    return _db_instance


def close_db() -> None:
    """Close shared SQLite connection."""
    global _db_instance
    if _db_instance is not None:
        _db_instance.close()
        _db_instance = None
