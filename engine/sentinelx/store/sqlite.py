"""SQLite storage layer in WAL mode using standard library sqlite3."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinelx.schemas.event import Event
from sentinelx.schemas.signal import Signal


def init_db(path: str | Path) -> sqlite3.Connection:
    """Initialize SQLite database with WAL mode, core tables, and telemetry query indexes."""
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

        # Performance indexes for API filtering and live feed ordering
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_source_ts ON events(source_tool, ts DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_category_ts ON events(category, ts DESC);"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_domain_ts ON events(domain, ts DESC);")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_json_user ON events(json_extract(json, '$.user'), ts DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_json_host ON events(json_extract(json, '$.host'), ts DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_json_src_ip ON events(json_extract(json, '$.src_ip'), ts DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_json_dst_ip ON events(json_extract(json, '$.dst_ip'), ts DESC);"
        )

        # Checkpoints table for tailers
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ingest_checkpoints (
                source_key TEXT PRIMARY KEY,
                inode INTEGER NOT NULL,
                offset INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)

        # Stub tables for subsequent phases
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signals (
                signal_id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                json TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_ts ON signals(ts DESC);")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_signals_detector_ts ON signals(json_extract(json, '$.detector'), ts DESC);"
        )
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


def reset_db(path: str | Path) -> sqlite3.Connection:
    """Reset the database by removing file and reinitializing schema."""
    db_path = Path(path)
    for p in (
        db_path,
        db_path.with_name(f"{db_path.name}-wal"),
        db_path.with_name(f"{db_path.name}-shm"),
    ):
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass
    return init_db(db_path)


def insert_event(db: sqlite3.Connection, event: Event) -> bool:
    """Insert a normalized Event into the events table with INSERT OR IGNORE.

    Returns True if row was inserted, False if ignored as duplicate.
    """
    with db:
        cur = db.execute(
            """
            INSERT OR IGNORE INTO events (event_id, ts, source_tool, domain, category, json)
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
        return cur.rowcount > 0


def insert_events_batch(db: sqlite3.Connection, events: list[Event]) -> int:
    """Batch insert normalized events into the events table with INSERT OR IGNORE.

    Returns count of newly inserted rows.
    """
    if not events:
        return 0
    params = [
        (
            e.event_id,
            e.ts.isoformat(),
            e.source_tool.value,
            e.domain.value,
            e.category,
            e.model_dump_json(),
        )
        for e in events
    ]
    with db:
        cur = db.executemany(
            """
            INSERT OR IGNORE INTO events (event_id, ts, source_tool, domain, category, json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            params,
        )
        return cur.rowcount


def get_event_by_id(db: sqlite3.Connection, event_id: str) -> Event | None:
    """Retrieve full event by event_id."""
    row = db.execute("SELECT json FROM events WHERE event_id = ?", (event_id,)).fetchone()
    if row:
        return Event.model_validate_json(row[0])
    return None


def list_events(
    db: sqlite3.Connection,
    limit: int = 50,
    before: str | None = None,
    since: str | None = None,
    source_tool: str | None = None,
    domain: str | None = None,
    category: str | None = None,
    host: str | None = None,
    user: str | None = None,
    ip: str | None = None,
    before_ts: str | None = None,  # Backward compatibility
) -> list[Event]:
    """Retrieve latest events matching filters, sorted newest-first."""
    query = "SELECT json FROM events WHERE 1=1"
    params: list[Any] = []

    if source_tool:
        query += " AND source_tool = ?"
        params.append(source_tool)
    if domain:
        query += " AND domain = ?"
        params.append(domain)
    if category:
        query += " AND category = ?"
        params.append(category)
    if host:
        query += " AND json_extract(json, '$.host') = ?"
        params.append(host)
    if user:
        query += " AND json_extract(json, '$.user') = ?"
        params.append(user)
    if ip:
        query += " AND (json_extract(json, '$.src_ip') = ? OR json_extract(json, '$.dst_ip') = ?)"
        params.append(ip)
        params.append(ip)
    if since:
        query += " AND ts >= ?"
        params.append(since)

    effective_before = before or before_ts
    if effective_before:
        query += " AND ts < ?"
        params.append(effective_before)

    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    cursor = db.cursor()
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    return [Event.model_validate_json(row[0]) for row in rows]


def get_stats(db: sqlite3.Connection, window_seconds: int = 300) -> dict[str, Any]:
    """Retrieve aggregate telemetry metrics for the last window_seconds (default 5 min)."""
    cutoff = (datetime.now(UTC) - timedelta(seconds=window_seconds)).isoformat()

    by_source: dict[str, int] = {}
    for row in db.execute(
        "SELECT source_tool, COUNT(*) FROM events WHERE ts >= ? GROUP BY source_tool",
        (cutoff,),
    ):
        by_source[row[0]] = int(row[1])

    by_category: dict[str, int] = {}
    for row in db.execute(
        "SELECT category, COUNT(*) FROM events WHERE ts >= ? GROUP BY category",
        (cutoff,),
    ):
        by_category[row[0]] = int(row[1])

    by_domain: dict[str, int] = {}
    for row in db.execute(
        "SELECT domain, COUNT(*) FROM events WHERE ts >= ? GROUP BY domain",
        (cutoff,),
    ):
        by_domain[row[0]] = int(row[1])

    total_row = db.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (cutoff,)).fetchone()
    total_events = int(total_row[0]) if total_row else 0
    events_per_sec = round(total_events / max(1.0, float(window_seconds)), 2)

    return {
        "window_seconds": window_seconds,
        "total_events": total_events,
        "events_per_sec": events_per_sec,
        "by_source": by_source,
        "by_category": by_category,
        "by_domain": by_domain,
    }


def insert_signal(db: sqlite3.Connection, signal: Signal) -> bool:
    """Insert a Signal into the signals table with INSERT OR IGNORE."""
    with db:
        cur = db.execute(
            """
            INSERT OR IGNORE INTO signals (signal_id, ts, json)
            VALUES (?, ?, ?)
            """,
            (
                signal.signal_id,
                signal.ts.isoformat(),
                signal.model_dump_json(),
            ),
        )
        return cur.rowcount > 0


def insert_signals_batch(db: sqlite3.Connection, signals: list[Signal]) -> int:
    """Batch insert Signals into the signals table with INSERT OR IGNORE."""
    if not signals:
        return 0
    params = [
        (
            s.signal_id,
            s.ts.isoformat(),
            s.model_dump_json(),
        )
        for s in signals
    ]
    with db:
        cur = db.executemany(
            """
            INSERT OR IGNORE INTO signals (signal_id, ts, json)
            VALUES (?, ?, ?)
            """,
            params,
        )
        return cur.rowcount


def get_signal_by_id(db: sqlite3.Connection, signal_id: str) -> Signal | None:
    """Retrieve full Signal by signal_id."""
    row = db.execute("SELECT json FROM signals WHERE signal_id = ?", (signal_id,)).fetchone()
    if row:
        return Signal.model_validate_json(row[0])
    return None


def list_signals(
    db: sqlite3.Connection,
    limit: int = 50,
    before: str | None = None,
    since: str | None = None,
    detector: str | None = None,
    entity: str | None = None,
    min_confidence: float | None = None,
) -> list[Signal]:
    """Retrieve latest signals matching filters, sorted newest-first."""
    query = "SELECT json FROM signals WHERE 1=1"
    params: list[Any] = []

    if detector:
        query += " AND json_extract(json, '$.detector') = ?"
        params.append(detector)
    if min_confidence is not None:
        query += " AND json_extract(json, '$.confidence') >= ?"
        params.append(min_confidence)
    if entity:
        # Check if entity string matches any entity value in json
        query += " AND json_extract(json, '$.entities') LIKE ?"
        params.append(f"%{entity}%")
    if since:
        query += " AND ts >= ?"
        params.append(since)
    if before:
        query += " AND ts < ?"
        params.append(before)

    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    cursor = db.cursor()
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    return [Signal.model_validate_json(row[0]) for row in rows]
