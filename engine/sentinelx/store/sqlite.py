"""SQLite storage layer in WAL mode using standard library sqlite3."""

import sqlite3
from pathlib import Path
from typing import Any

from sentinelx.schemas.event import Event


def init_db(path: str | Path) -> sqlite3.Connection:
    """Initialize SQLite database with WAL mode and core tables."""
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")

    with conn:
        # Core telemetry events table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                source_tool TEXT NOT NULL,
                domain TEXT NOT NULL,
                category TEXT NOT NULL,
                json TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
        """)

        # Stub tables for subsequent phases
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signals (
                signal_id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                json TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                json TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS guard_decisions (
                decision_id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                json TEXT NOT NULL
            );
        """)

    return conn


def insert_event(db: sqlite3.Connection, event: Event) -> None:
    """Insert a normalized Event into the events table."""
    with db:
        db.execute(
            """
            INSERT INTO events (event_id, ts, source_tool, domain, category, json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.ts.isoformat(),
                event.source_tool.value,
                event.domain.value,
                event.category,
                event.model_dump_json(),
            ),
        )


def list_events(
    db: sqlite3.Connection, limit: int = 50, before_ts: str | None = None
) -> list[Event]:
    """Retrieve latest events newest-first, optionally paginated before a given timestamp."""
    query = "SELECT json FROM events"
    params: list[Any] = []

    if before_ts:
        query += " WHERE ts < ?"
        params.append(before_ts)

    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    cursor = db.cursor()
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    return [Event.model_validate_json(row[0]) for row in rows]
