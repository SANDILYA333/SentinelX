"""SQLite storage layer in WAL mode using standard library sqlite3."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sentinelx.schemas.deception import LotLAnalytics, LotLInteraction, LotLLure
from sentinelx.schemas.eval import EvaluationRunSummary
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
                headline_source TEXT DEFAULT 'llm',
                PRIMARY KEY (incident_id, evidence_hash)
            );
        """)
        try:
            conn.execute(
                "ALTER TABLE incident_summaries ADD COLUMN headline_source TEXT DEFAULT 'llm';"
            )
        except sqlite3.OperationalError:
            pass
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_incident_summaries_lookup ON incident_summaries(incident_id, generated_at DESC);"
        )

        # Tables for Detection Evaluation Runs and Scenario Results (Phase D)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evaluation_runs (
                run_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                git_commit TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                splits TEXT NOT NULL,
                headline_precision REAL,
                headline_recall REAL,
                headline_f1 REAL,
                headline_accuracy REAL,
                p95_latency_ms REAL,
                throughput_eps REAL,
                json TEXT NOT NULL
            );
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evaluation_runs_created ON evaluation_runs(created_at DESC);"
        )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS evaluation_scenario_results (
                run_id TEXT NOT NULL,
                scenario_id TEXT NOT NULL,
                classification TEXT NOT NULL,
                detected INTEGER NOT NULL,
                score REAL NOT NULL,
                time_to_detect_ms REAL,
                notes TEXT,
                PRIMARY KEY (run_id, scenario_id),
                FOREIGN KEY (run_id) REFERENCES evaluation_runs(run_id) ON DELETE CASCADE
            );
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evaluation_scenarios_lookup ON evaluation_scenario_results(run_id, scenario_id);"
        )

        # Living-off-the-Land (LotL) Deception Engine Tables (Phase F)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS lotl_lures (
                lure_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                lure_type TEXT NOT NULL,
                platform TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_interaction TEXT,
                total_interactions INTEGER NOT NULL DEFAULT 0,
                json TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_lotl_lures_host ON lotl_lures(host);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_lotl_lures_type ON lotl_lures(lure_type);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_lotl_lures_status ON lotl_lures(status);")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS lotl_interactions (
                interaction_id TEXT PRIMARY KEY,
                lure_id TEXT NOT NULL,
                lure_type TEXT NOT NULL,
                interaction_type TEXT NOT NULL,
                host TEXT NOT NULL,
                ts TEXT NOT NULL,
                event_id TEXT NOT NULL,
                json TEXT NOT NULL,
                FOREIGN KEY (lure_id) REFERENCES lotl_lures(lure_id)
            );
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_lotl_interactions_ts ON lotl_interactions(ts DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_lotl_interactions_lure ON lotl_interactions(lure_id, ts DESC);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_lotl_interactions_host ON lotl_interactions(host, ts DESC);"
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
    """Insert or update a guard decision record in guard_decisions table.

    Returns True if row was inserted/updated.
    """
    with db:
        cur = db.execute(
            """
            INSERT OR REPLACE INTO guard_decisions (decision_id, ts, json)
            VALUES (?, ?, ?)
            """,
            (
                decision.decision_id,
                decision.ts.isoformat(),
                decision.model_dump_json(),
            ),
        )
        return cur.rowcount > 0


def get_guard_decision_by_id(db: sqlite3.Connection, decision_id: str) -> GuardDecision | None:
    """Retrieve an individual guard decision by decision_id."""
    cursor = db.cursor()
    row = cursor.execute(
        "SELECT json FROM guard_decisions WHERE decision_id = ?", (decision_id,)
    ).fetchone()
    if not row:
        return None
    return GuardDecision.model_validate_json(row[0])


def update_guard_decision(db: sqlite3.Connection, decision: GuardDecision) -> bool:
    """Update an existing guard decision record in guard_decisions table."""
    with db:
        cur = db.execute(
            """
            UPDATE guard_decisions
            SET json = ?
            WHERE decision_id = ?
            """,
            (
                decision.model_dump_json(),
                decision.decision_id,
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
    headline_source: str = "llm",
) -> bool:
    """Insert or replace an advisory analyst summary in the incident_summaries sidecar table."""
    with db:
        cur = db.execute(
            """
            INSERT OR REPLACE INTO incident_summaries (
                incident_id, evidence_hash, mode, text, claims_json, verified, total, dropped, model, generated_at, headline_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                headline_source,
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
        SELECT incident_id, evidence_hash, mode, text, claims_json, verified, total, dropped, model, generated_at, headline_source
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
        "headline_source": row[10] if len(row) > 10 and row[10] is not None else "llm",
    }


def get_latest_incident_summary(
    db: sqlite3.Connection,
    incident_id: str,
) -> dict[str, Any] | None:
    """Retrieve the most recently generated analyst summary for an incident."""
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT incident_id, evidence_hash, mode, text, claims_json, verified, total, dropped, model, generated_at, headline_source
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
        "headline_source": row[10] if len(row) > 10 and row[10] is not None else "llm",
    }


def save_evaluation_run(db: sqlite3.Connection, run: EvaluationRunSummary) -> None:
    """Persist an evaluation run and its scenario breakdown in SQLite."""
    with db:
        splits_str = json.dumps(run.splits_evaluated)
        db.execute(
            """
            INSERT OR REPLACE INTO evaluation_runs (
                run_id, created_at, git_commit, dataset_version, splits,
                headline_precision, headline_recall, headline_f1, headline_accuracy,
                p95_latency_ms, throughput_eps, json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.run_id,
                run.created_at.isoformat(),
                run.git_commit,
                run.dataset_version,
                splits_str,
                run.headline.precision,
                run.headline.recall,
                run.headline.f1_score,
                run.headline.accuracy,
                run.latency.end_to_end_latency.p95,
                run.throughput_eps,
                run.model_dump_json(),
            ),
        )

        for sc in run.scenarios:
            db.execute(
                """
                INSERT OR REPLACE INTO evaluation_scenario_results (
                    run_id, scenario_id, classification, detected, score, time_to_detect_ms, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    sc.scenario_id,
                    sc.classification,
                    1 if sc.detected else 0,
                    sc.score,
                    sc.time_to_detect_ms,
                    sc.notes,
                ),
            )


def get_evaluation_run(db: sqlite3.Connection, run_id: str) -> EvaluationRunSummary | None:
    """Retrieve full evaluation run summary by run_id."""
    cursor = db.cursor()
    cursor.execute("SELECT json FROM evaluation_runs WHERE run_id = ?", (run_id,))
    row = cursor.fetchone()
    if not row:
        return None
    return EvaluationRunSummary.model_validate_json(row[0])


def get_latest_evaluation_run(db: sqlite3.Connection) -> EvaluationRunSummary | None:
    """Retrieve the most recent evaluation run summary."""
    cursor = db.cursor()
    cursor.execute("SELECT json FROM evaluation_runs ORDER BY created_at DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        return None
    return EvaluationRunSummary.model_validate_json(row[0])


def list_evaluation_runs(db: sqlite3.Connection, limit: int = 20) -> list[dict[str, Any]]:
    """List historical evaluation runs with headline metrics."""
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT run_id, created_at, git_commit, dataset_version, splits,
               headline_precision, headline_recall, headline_f1, headline_accuracy,
               p95_latency_ms, throughput_eps
        FROM evaluation_runs
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    results = []
    for r in rows:
        results.append(
            {
                "run_id": r[0],
                "created_at": r[1],
                "git_commit": r[2],
                "dataset_version": r[3],
                "splits": json.loads(r[4]) if r[4] else [],
                "headline_precision": r[5],
                "headline_recall": r[6],
                "headline_f1": r[7],
                "headline_accuracy": r[8],
                "p95_latency_ms": r[9],
                "throughput_eps": r[10],
            }
        )
    return results


# ==============================================================================
# Living-off-the-Land (LotL) Deception Engine Database Accessors (Phase F)
# ==============================================================================


def upsert_lotl_lure(db: sqlite3.Connection, lure: LotLLure) -> None:
    """Insert or update a LotL deception lure in the registry."""
    with db:
        db.execute(
            """
            INSERT INTO lotl_lures (
                lure_id, name, lure_type, platform, host, path, status,
                enabled, created_at, last_interaction, total_interactions, json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(lure_id) DO UPDATE SET
                name = excluded.name,
                lure_type = excluded.lure_type,
                platform = excluded.platform,
                host = excluded.host,
                path = excluded.path,
                status = excluded.status,
                enabled = excluded.enabled,
                last_interaction = excluded.last_interaction,
                total_interactions = excluded.total_interactions,
                json = excluded.json;
            """,
            (
                lure.lure_id,
                lure.name,
                lure.lure_type,
                lure.platform,
                lure.host,
                lure.path,
                lure.status,
                1 if lure.enabled else 0,
                lure.created_at.isoformat(),
                lure.last_interaction.isoformat() if lure.last_interaction else None,
                lure.total_interactions,
                lure.model_dump_json(),
            ),
        )


def get_lotl_lure(db: sqlite3.Connection, lure_id: str) -> LotLLure | None:
    """Retrieve a single LotL lure by its lure_id."""
    cursor = db.cursor()
    cursor.execute("SELECT json FROM lotl_lures WHERE lure_id = ?", (lure_id,))
    row = cursor.fetchone()
    if not row:
        return None
    return LotLLure.model_validate_json(row[0])


def list_lotl_lures(
    db: sqlite3.Connection,
    host: str | None = None,
    lure_type: str | None = None,
    status: str | None = None,
    enabled: bool | None = None,
) -> list[LotLLure]:
    """Retrieve all LotL lures matching optional filter criteria."""
    query = "SELECT json FROM lotl_lures WHERE 1=1"
    params: list[Any] = []
    if host:
        query += " AND host = ?"
        params.append(host)
    if lure_type:
        query += " AND lure_type = ?"
        params.append(lure_type)
    if status:
        query += " AND status = ?"
        params.append(status)
    if enabled is not None:
        query += " AND enabled = ?"
        params.append(1 if enabled else 0)
    query += " ORDER BY lure_id ASC"

    cursor = db.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    return [LotLLure.model_validate_json(r[0]) for r in rows]


def set_lotl_lure_enabled(db: sqlite3.Connection, lure_id: str, enabled: bool) -> LotLLure | None:
    """Enable or disable a LotL lure by ID."""
    lure = get_lotl_lure(db, lure_id)
    if not lure:
        return None
    updated = lure.model_copy(
        update={
            "enabled": enabled,
            "status": "active" if enabled and lure.status == "disabled" else ("disabled" if not enabled else lure.status),
        }
    )
    upsert_lotl_lure(db, updated)
    return updated


def record_lotl_interaction(db: sqlite3.Connection, interaction: LotLInteraction) -> None:
    """Record an attacker interaction with a LotL lure and update lure statistics."""
    with db:
        db.execute(
            """
            INSERT OR REPLACE INTO lotl_interactions (
                interaction_id, lure_id, lure_type, interaction_type, host, ts, event_id, json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                interaction.interaction_id,
                interaction.lure_id,
                interaction.lure_type,
                interaction.interaction_type,
                interaction.host,
                interaction.ts.isoformat(),
                interaction.event_id,
                interaction.model_dump_json(),
            ),
        )
        # Update lure last_interaction and total_interactions
        lure = get_lotl_lure(db, interaction.lure_id)
        if lure:
            new_count = lure.total_interactions + 1
            new_last = interaction.ts
            updated_lure = lure.model_copy(
                update={"total_interactions": new_count, "last_interaction": new_last}
            )
            upsert_lotl_lure(db, updated_lure)


def list_lotl_interactions(
    db: sqlite3.Connection,
    lure_id: str | None = None,
    host: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[LotLInteraction]:
    """List LotL interactions in reverse chronological order."""
    query = "SELECT json FROM lotl_interactions WHERE 1=1"
    params: list[Any] = []
    if lure_id:
        query += " AND lure_id = ?"
        params.append(lure_id)
    if host:
        query += " AND host = ?"
        params.append(host)
    query += " ORDER BY ts DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor = db.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    return [LotLInteraction.model_validate_json(r[0]) for r in rows]


def get_lotl_analytics(db: sqlite3.Connection) -> LotLAnalytics:
    """Compute aggregated analytics for LotL deception lures and interactions."""
    lures = list_lotl_lures(db)
    interactions = list_lotl_interactions(db, limit=1000)

    total_active = sum(1 for l in lures if l.enabled and l.status == "active")
    discovered_lure_ids = {i.lure_id for i in interactions}
    total_discovered = len(discovered_lure_ids)

    canary_pres = sum(1 for i in interactions if i.interaction_type == "canary_credential_presented")
    decoy_auths = sum(1 for i in interactions if "ssh" in i.interaction_type and "login" in i.interaction_type)
    file_mods = sum(1 for i in interactions if i.interaction_type in ("decoy_file_modified", "decoy_task_modified"))

    interacting_hosts = sorted(list({i.host for i in interactions if i.host}))

    by_type: dict[str, int] = {}
    for i in interactions:
        by_type[i.interaction_type] = by_type.get(i.interaction_type, 0) + 1

    by_lure: dict[str, int] = {}
    for i in interactions:
        by_lure[i.lure_id] = by_lure.get(i.lure_id, 0) + 1

    return LotLAnalytics(
        total_active_lures=total_active,
        total_discovered_lures=total_discovered,
        total_interactions=len(interactions),
        canary_presentations=canary_pres,
        decoy_authentications=decoy_auths,
        file_modifications=file_mods,
        interacting_hosts=interacting_hosts,
        interactions_by_type=by_type,
        interactions_by_lure=by_lure,
    )

