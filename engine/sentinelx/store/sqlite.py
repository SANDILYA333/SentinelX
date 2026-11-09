"""SQLite storage layer in WAL mode using standard library sqlite3."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinelx.schemas.event import Event
from sentinelx.schemas.guard import GuardDecision
from sentinelx.schemas.incident import Incident
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(ts DESC);")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS guard_decisions (
                decision_id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                json TEXT NOT NULL
            );
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_guard_decisions_ts ON guard_decisions(ts DESC);"
        )

        # Sidecar table for LLM / template analyst summaries (Phase 8)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_summaries (
                incident_id TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                mode TEXT NOT NULL,
                text TEXT NOT NULL,
                claims_json TEXT NOT NULL,
                verified INTEGER NOT NULL,
                total INTEGER NOT NULL,
                dropped INTEGER NOT NULL,
                model TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                PRIMARY KEY (incident_id, evidence_hash)
            );
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incident_summaries_lookup ON incident_summaries(incident_id, generated_at DESC);"
        )

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


def upsert_incident(db: sqlite3.Connection, incident: Incident) -> bool:
    """Insert or update an Incident record in the incidents table.

    Returns True on success.
    """
    with db:
        db.execute(
            """
            INSERT INTO incidents (incident_id, ts, json)
            VALUES (?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                ts = excluded.ts,
                json = excluded.json
            """,
            (
                incident.incident_id,
                incident.updated_at.isoformat(),
                incident.model_dump_json(),
            ),
        )
        return True


def get_incident_by_id(db: sqlite3.Connection, incident_id: str) -> Incident | None:
    """Retrieve full Incident by incident_id."""
    row = db.execute("SELECT json FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if row:
        return Incident.model_validate_json(row[0])
    return None


def list_incidents(
    db: sqlite3.Connection,
    limit: int = 50,
    status: str | None = None,
    min_score: float | None = None,
    since: str | None = None,
) -> list[Incident]:
    """Retrieve incidents matching filters, sorted newest-first."""
    query = "SELECT json FROM incidents WHERE 1=1"
    params: list[Any] = []

    if status:
        query += " AND json_extract(json, '$.status') = ?"
        params.append(status)
    if min_score is not None:
        query += " AND json_extract(json, '$.score') >= ?"
        params.append(min_score)
    if since:
        query += " AND ts >= ?"
        params.append(since)

    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    cursor = db.cursor()
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    return [Incident.model_validate_json(row[0]) for row in rows]


def insert_guard_decision(db: sqlite3.Connection, decision: GuardDecision) -> bool:
    """Insert a guard decision record into guard_decisions table.

    Returns True if row was inserted, False if duplicate.
    """
    with db:
        cur = db.execute(
            """
            INSERT OR IGNORE INTO guard_decisions (decision_id, ts, json)
            VALUES (?, ?, ?)
            """,
            (
                decision.decision_id,
                decision.ts.isoformat(),
                decision.model_dump_json(),
            ),
        )
        return cur.rowcount > 0


def list_guard_decisions(
    db: sqlite3.Connection,
    limit: int = 50,
    incident_id: str | None = None,
) -> list[GuardDecision]:
    """Retrieve recent guard decisions."""
    query = "SELECT json FROM guard_decisions WHERE 1=1"
    params: list[Any] = []

    if incident_id:
        query += " AND json_extract(json, '$.incident_id') = ?"
        params.append(incident_id)

    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    cursor = db.cursor()
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    return [GuardDecision.model_validate_json(row[0]) for row in rows]


def upsert_incident_summary(
    db: sqlite3.Connection,
    incident_id: str,
    evidence_hash: str,
    mode: str,
    text: str,
    claims_json: str,
    verified: int,
    total: int,
    dropped: int,
    model: str,
    generated_at: str,
) -> bool:
    """Insert or replace an advisory analyst summary in the incident_summaries sidecar table."""
    with db:
        cur = db.execute(
            """
            INSERT OR REPLACE INTO incident_summaries (
                incident_id, evidence_hash, mode, text, claims_json, verified, total, dropped, model, generated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                evidence_hash,
                mode,
                text,
                claims_json,
                verified,
                total,
                dropped,
                model,
                generated_at,
            ),
        )
        return cur.rowcount > 0


def get_incident_summary(
    db: sqlite3.Connection,
    incident_id: str,
    evidence_hash: str,
) -> dict[str, Any] | None:
    """Retrieve an analyst summary matching incident_id and exact evidence_hash."""
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT incident_id, evidence_hash, mode, text, claims_json, verified, total, dropped, model, generated_at
        FROM incident_summaries
        WHERE incident_id = ? AND evidence_hash = ?
        """,
        (incident_id, evidence_hash),
    )
    row = cursor.fetchone()
    if not row:
        return None
    return {
        "incident_id": row[0],
        "evidence_hash": row[1],
        "mode": row[2],
        "text": row[3],
        "claims_json": row[4],
        "verified": row[5],
        "total": row[6],
        "dropped": row[7],
        "model": row[8],
        "generated_at": row[9],
    }


def get_latest_incident_summary(
    db: sqlite3.Connection,
    incident_id: str,
) -> dict[str, Any] | None:
    """Retrieve the most recently generated analyst summary for an incident."""
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT incident_id, evidence_hash, mode, text, claims_json, verified, total, dropped, model, generated_at
        FROM incident_summaries
        WHERE incident_id = ?
        ORDER BY generated_at DESC
        LIMIT 1
        """,
        (incident_id,),
    )
    row = cursor.fetchone()
    if not row:
        return None
    return {
        "incident_id": row[0],
        "evidence_hash": row[1],
        "mode": row[2],
        "text": row[3],
        "claims_json": row[4],
        "verified": row[5],
        "total": row[6],
        "dropped": row[7],
        "model": row[8],
        "generated_at": row[9],
    }
