"""Integration tests for SentinelX API endpoints and WebSocket streaming."""

import json
import tempfile
from pathlib import Path

import pytest
from app.config import settings
from app.db import close_db, get_db
from app.main import app
from fastapi.testclient import TestClient
from sentinelx.schemas.common import SCHEMA_VERSION


@pytest.fixture(autouse=True)
def test_db_env(monkeypatch):
    """Use a temporary SQLite database for each test and prevent live network calls."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_db = Path(tmpdir) / "test_api.db"
        monkeypatch.setattr(settings, "SENTINELX_DB_PATH", tmp_db)
        monkeypatch.setattr(settings, "SENTINELX_ENV", "dev")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        close_db()
        get_db()
        yield
        close_db()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["env"] == "dev"


def test_dev_emit_event_and_list(client: TestClient):
    # Initially events list should be empty
    res_initial = client.get("/api/v1/events")
    assert res_initial.status_code == 200
    assert res_initial.json() == []

    # Emit a dev event
    res_emit = client.post("/api/v1/dev/emit-test-event")
    assert res_emit.status_code == 200
    emitted = res_emit.json()
    assert "event_id" in emitted
    assert emitted["tags"] == ["dev-test"]

    # Retrieve events
    res_events = client.get("/api/v1/events")
    assert res_events.status_code == 200
    events = res_events.json()
    assert len(events) == 1
    assert events[0]["event_id"] == emitted["event_id"]


def test_websocket_stream(client: TestClient):
    with client.websocket_connect("/ws/stream") as ws:
        # First message must be 'hello'
        hello_raw = ws.receive_text()
        hello_msg = json.loads(hello_raw)
        assert hello_msg["type"] == "hello"
        assert hello_msg["payload"]["schema_version"] == SCHEMA_VERSION

        # Test ping-pong
        ws.send_text("ping")
        pong = ws.receive_text()
        assert pong == "pong"

        # Emit an event via REST and verify it arrives via WS
        res_emit = client.post("/api/v1/dev/emit-test-event")
        assert res_emit.status_code == 200
        emitted_event = res_emit.json()

        # Receive broadcast event
        event_raw = ws.receive_text()
        event_msg = json.loads(event_raw)
        assert event_msg["type"] == "event"
        assert event_msg["payload"]["event_id"] == emitted_event["event_id"]


def test_sources_health_and_stats(client: TestClient):
    # Test sources health
    res_health = client.get("/api/v1/sources/health")
    assert res_health.status_code == 200
    sources = res_health.json()
    assert isinstance(sources, list)
    assert len(sources) > 0
    assert "source_key" in sources[0]
    assert "status" in sources[0]

    # Test stats
    res_stats = client.get("/api/v1/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert "total_events" in stats
    assert "events_per_sec" in stats
    assert "by_source" in stats
    assert "by_category" in stats
    assert "by_domain" in stats


def test_get_event_by_id_and_filters(client: TestClient):
    # Emit an event
    res_emit = client.post("/api/v1/dev/emit-test-event")
    assert res_emit.status_code == 200
    ev = res_emit.json()
    eid = ev["event_id"]

    # Fetch by ID
    res_single = client.get(f"/api/v1/events/{eid}")
    assert res_single.status_code == 200
    assert res_single.json()["event_id"] == eid

    # Fetch non-existent ID
    res_404 = client.get("/api/v1/events/non_existent_id")
    assert res_404.status_code == 404

    # Filter by category
    cat = ev["category"]
    res_filtered = client.get(f"/api/v1/events?category={cat}")
    assert res_filtered.status_code == 200
    matched = res_filtered.json()
    assert len(matched) >= 1
    assert any(e["event_id"] == eid for e in matched)


def test_incidents_and_guard_endpoints(client: TestClient):
    # 1. Incidents endpoint returns empty list initially
    res_inc = client.get("/api/v1/incidents")
    assert res_inc.status_code == 200
    assert res_inc.json() == []

    # 2. Guard evaluation endpoint
    res_guard = client.post(
        "/api/v1/guard/evaluate",
        json={"action": "block_ip", "target": "10.10.1.5"},
    )
    assert res_guard.status_code == 200
    guard_dec = res_guard.json()
    assert guard_dec["decision"] == "allow"
    assert guard_dec["action"] == "block_ip"
    assert guard_dec["target"] == "10.10.1.5"

    # 3. Guard decisions listing
    res_decs = client.get("/api/v1/guard/decisions")
    assert res_decs.status_code == 200
    decs = res_decs.json()
    assert len(decs) >= 1
    assert decs[0]["decision_id"] == guard_dec["decision_id"]

    # 4. Budget endpoint
    res_budget = client.get("/api/v1/budget")
    assert res_budget.status_code == 200
    budget_data = res_budget.json()
    assert "threshold" in budget_data
    assert budget_data["threshold"] == 0.50

    # 5. Update budget threshold
    res_budget_set = client.post("/api/v1/budget", json={"threshold": 0.65})
    assert res_budget_set.status_code == 200
    assert res_budget_set.json()["threshold"] == 0.65


def test_incident_summary_endpoints(client: TestClient):
    from datetime import datetime, timezone

    from sentinelx.schemas.incident import Incident
    from sentinelx.store.sqlite import upsert_incident

    # 404 for unknown incident
    res = client.get("/api/v1/incidents/inc_unknown/summary")
    assert res.status_code == 404

    # Create an incident
    now = datetime.now(timezone.utc)
    inc = Incident(
        incident_id="inc_summary_test",
        status="open",
        created_at=now,
        updated_at=now,
        first_signal_ts=now,
        score=0.85,
        severity="high",
        entities=[],
        signal_ids=[],
        event_ids=[],
        kill_chain_stages=["initial_access", "execution"],
        techniques=[],
        decoy_touched=False,
        ot_touched=False,
        explanation=["Initial access observed on jump-host.", "Privilege escalation executed."],
    )
    db = get_db()
    upsert_incident(db, inc)

    # Initially GET summary returns 404 (not yet generated)
    res_get_init = client.get("/api/v1/incidents/inc_summary_test/summary")
    assert res_get_init.status_code == 404

    # POST generates fallback template summary (deterministic)
    res_post = client.post("/api/v1/incidents/inc_summary_test/summary")
    assert res_post.status_code == 200
    summary = res_post.json()
    assert summary["incident_id"] == "inc_summary_test"
    assert summary["mode"] in ("template", "llm")
    assert summary["headline"]
    assert len(summary["claims"]) > 0

    # Subsequent GET returns the cached summary
    res_get = client.get("/api/v1/incidents/inc_summary_test/summary")
    assert res_get.status_code == 200
    assert res_get.json()["incident_id"] == "inc_summary_test"
    assert res_get.json()["evidence_hash"] == summary["evidence_hash"]


def test_incident_graph_and_timeline_api(client: TestClient):
    from datetime import datetime, timezone

    from sentinelx.schemas.common import Domain, Entity, EntityType, Outcome, SourceTool
    from sentinelx.schemas.event import Event
    from sentinelx.schemas.incident import Incident
    from sentinelx.schemas.signal import Signal
    from sentinelx.store.sqlite import insert_event, insert_signal, upsert_incident

    now = datetime.now(timezone.utc)
    ev = Event(
        event_id="evt_api_001",
        ts=now,
        ingested_at=now,
        source_tool=SourceTool.zeek,
        domain=Domain.it,
        category="network",
        action="conn_ssh",
        outcome=Outcome.success,
        host="jump-host",
        src_ip="10.10.1.5",
        dst_ip="10.10.1.10",
        raw_ref={"src": "test"},
        raw={"ok": True},
    )
    sig = Signal(
        signal_id="sig_api_001",
        ts=now,
        detector="rule",
        rule_id="RULE-AUTH-001",
        title="Unauthorized SSH Access",
        score=0.8,
        confidence=0.95,
        entities=[
            Entity(type=EntityType.ip, value="10.10.1.5"),
            Entity(type=EntityType.host, value="jump-host"),
        ],
        evidence_event_ids=["evt_api_001"],
        techniques=[],
        explanation="Adversary connected via SSH",
    )
    inc = Incident(
        incident_id="inc_graph_test",
        status="open",
        created_at=now,
        updated_at=now,
        first_signal_ts=now,
        score=0.8,
        severity="high",
        entities=[
            Entity(type=EntityType.ip, value="10.10.1.5"),
            Entity(type=EntityType.host, value="jump-host"),
        ],
        signal_ids=["sig_api_001"],
        event_ids=["evt_api_001"],
        kill_chain_stages=["initial_access"],
        techniques=[],
        decoy_touched=False,
        ot_touched=False,
        explanation=["Adversary accessed jump-host"],
    )

    db = get_db()
    insert_event(db, ev)
    insert_signal(db, sig)
    upsert_incident(db, inc)

    # 1. Test GET /api/v1/incidents/{incident_id}
    res_detail = client.get("/api/v1/incidents/inc_graph_test")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert detail["incident_id"] == "inc_graph_test"
    assert "graph" in detail
    assert detail["graph"] is not None
    assert len(detail["graph"]["nodes"]) >= 2
    assert len(detail["graph"]["edges"]) >= 1

    # Verify canonical node attributes
    jump_node = next(n for n in detail["graph"]["nodes"] if "jump-host" in n["label"])
    assert jump_node["network_zone"] == "it"
    assert jump_node["risk_level"] in ("high", "critical", "medium")

    # Verify timeline inlined
    assert "timeline" in detail
    assert len(detail["timeline"]) == 1
    assert detail["timeline"][0]["event_id"] == "evt_api_001"
    assert detail["timeline"][0]["provenance"] == "observed"

    # 2. Test GET /api/v1/incidents/{incident_id}/timeline
    res_timeline = client.get("/api/v1/incidents/inc_graph_test/timeline")
    assert res_timeline.status_code == 200
    timeline = res_timeline.json()
    assert len(timeline) == 1
    assert timeline[0]["event_id"] == "evt_api_001"
    assert "jump-host" in timeline[0]["description"]
