"""Tests for SentinelX SQLite storage layer."""

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinelx.schemas import Domain, Event, Outcome, SourceTool, new_id
from sentinelx.store.sqlite import init_db, insert_event, list_events


def make_event(offset_seconds: int, action: str) -> Event:
    ts = datetime(2026, 11, 7, 12, 0, 0, tzinfo=UTC) + timedelta(seconds=offset_seconds)
    return Event(
        event_id=new_id("evt"),
        ts=ts,
        ingested_at=ts,
        source_tool=SourceTool.generic,
        domain=Domain.it,
        category="authentication",
        action=action,
        outcome=Outcome.success,
        raw_ref={"source": "test"},
        raw={"action": action},
        tags=["store_test"],
    )


def test_sqlite_insert_and_list_ordering():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test.db"
        db = init_db(db_path)

        # Insert 5 events with ascending timestamps
        e1 = make_event(10, "login_1")
        e2 = make_event(20, "login_2")
        e3 = make_event(30, "login_3")
        e4 = make_event(40, "login_4")
        e5 = make_event(50, "login_5")

        for e in [e1, e2, e3, e4, e5]:
            insert_event(db, e)

        # Test list_events: should be newest first (e5, e4, e3, ...)
        events = list_events(db, limit=3)
        assert len(events) == 3
        assert events[0].event_id == e5.event_id
        assert events[1].event_id == e4.event_id
        assert events[2].event_id == e3.event_id

        # Test pagination with before_ts
        paginated = list_events(db, limit=10, before_ts=e3.ts.isoformat())
        assert len(paginated) == 2
        assert paginated[0].event_id == e2.event_id
        assert paginated[1].event_id == e1.event_id

        db.close()


def test_sqlite_incident_novelty_only_roundtrip():
    """Verify that Incident.novelty_only field round-trips accurately through SQLite."""
    from sentinelx.schemas.common import Severity
    from sentinelx.schemas.incident import Incident
    from sentinelx.store.sqlite import get_incident_by_id, upsert_incident

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "test_incident.db"
        db = init_db(db_path)

        now = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)

        # 1. Incident with novelty_only=True
        inc_novelty = Incident(
            incident_id="inc_novelty_001",
            status="open",
            created_at=now,
            updated_at=now,
            first_signal_ts=now,
            score=0.40,
            severity=Severity.low,
            entities=[],
            signal_ids=["sig_001"],
            event_ids=["evt_001"],
            kill_chain_stages=["initial_access"],
            techniques=[],
            decoy_touched=False,
            ot_touched=False,
            novelty_only=True,
            explanation=["Novelty only signal capped"],
        )
        upsert_incident(db, inc_novelty)

        # 2. Incident with novelty_only=False
        inc_standard = Incident(
            incident_id="inc_standard_001",
            status="open",
            created_at=now,
            updated_at=now,
            first_signal_ts=now,
            score=0.85,
            severity=Severity.high,
            entities=[],
            signal_ids=["sig_002"],
            event_ids=["evt_002"],
            kill_chain_stages=["initial_access", "lateral_movement"],
            techniques=[],
            decoy_touched=False,
            ot_touched=False,
            novelty_only=False,
            explanation=["Rule corroborated attack chain"],
        )
        upsert_incident(db, inc_standard)

        # Retrieve and verify round-trip
        retrieved_nov = get_incident_by_id(db, "inc_novelty_001")
        assert retrieved_nov is not None
        assert retrieved_nov.novelty_only is True
        assert retrieved_nov.score == 0.40

        retrieved_std = get_incident_by_id(db, "inc_standard_001")
        assert retrieved_std is not None
        assert retrieved_std.novelty_only is False
        assert retrieved_std.score == 0.85

        db.close()
