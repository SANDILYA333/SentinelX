"""Integration tests for Deception Intelligence and Guard API endpoints."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.config import settings
from app.db import close_db, get_db
from app.main import app
from fastapi.testclient import TestClient
from sentinelx.schemas.common import Domain, Entity, EntityType, Outcome, Severity, SourceTool
from sentinelx.schemas.event import Event, OTFields
from sentinelx.schemas.incident import Incident
from sentinelx.store.sqlite import insert_event, upsert_incident


@pytest.fixture(autouse=True)
def test_db_env(monkeypatch):
    """Use a temporary SQLite database for each test."""
    from app.pipeline_state import set_guard_evaluator

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_db = Path(tmpdir) / "test_api_deception.db"
        monkeypatch.setattr(settings, "SENTINELX_DB_PATH", tmp_db)
        monkeypatch.setattr(settings, "SENTINELX_ENV", "dev")
        set_guard_evaluator(None)
        close_db()
        get_db()
        yield
        close_db()
        set_guard_evaluator(None)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_deception_endpoints(client: TestClient):
    """Verify Deception Intelligence REST endpoints."""
    db = get_db()
    now1 = datetime(2026, 11, 10, 14, 0, 0, tzinfo=UTC)
    now2 = datetime(2026, 11, 10, 14, 10, 0, tzinfo=UTC)

    # Insert sample deception events
    ev_ssh = Event(
        event_id="dec_ev_01",
        ts=now1,
        ingested_at=now1,
        source_tool=SourceTool.cowrie,
        domain=Domain.decoy,
        category="decoy_interaction",
        action="login_success",
        outcome=Outcome.success,
        src_ip="10.10.1.5",
        dst_ip="10.10.2.20",
        host="backup-srv-02",
        user="root",
        raw_ref={"path": "/var/log/cowrie.json", "line": 1},
        raw={"user": "root", "password": "compromised_pass"},
        tags=["deception"],
    )
    ev_modbus = Event(
        event_id="dec_ev_02",
        ts=now2,
        ingested_at=now2,
        source_tool=SourceTool.modbus,
        domain=Domain.decoy,
        category="decoy_interaction",
        action="read_holding_registers",
        outcome=Outcome.success,
        src_ip="10.10.3.40",
        dst_ip="10.10.3.60",
        host="decoy-plc",
        ot=OTFields(unit_id=1, function_code=3, register=100, is_write=False),
        raw_ref={"path": "/var/log/modbus.pcap", "line": 2},
        raw={},
        tags=["deception"],
    )
    insert_event(db, ev_ssh)
    insert_event(db, ev_modbus)

    # 1. Overview endpoint
    res_ov = client.get("/api/v1/deception/overview")
    assert res_ov.status_code == 200
    ov_data = res_ov.json()
    assert ov_data["total_interactions"] == 2
    assert len(ov_data["top_decoys"]) >= 2

    # 2. Activities list endpoint
    res_acts = client.get("/api/v1/deception/activities")
    assert res_acts.status_code == 200
    acts_data = res_acts.json()
    assert len(acts_data) == 2
    assert acts_data[0]["event_id"] == "dec_ev_02"  # most recent first

    # 3. Activity detail endpoint
    res_detail = client.get("/api/v1/deception/activities/dec_ev_01")
    assert res_detail.status_code == 200
    detail_data = res_detail.json()
    assert detail_data["event_id"] == "dec_ev_01"
    assert detail_data["decoy_asset"] in ("cowrie", "backup-srv-02")

    # Non-existent detail
    res_404 = client.get("/api/v1/deception/activities/non_existent_id")
    assert res_404.status_code == 404

    # 4. Decoy assets endpoint
    res_assets = client.get("/api/v1/deception/assets")
    assert res_assets.status_code == 200
    assets_data = res_assets.json()
    assert len(assets_data) == 3


def test_guard_recommendations_and_approval_api(client: TestClient):
    """Verify Response Safety Guard recommendations and approval/rejection endpoints."""
    db = get_db()
    now = datetime(2026, 11, 10, 14, 0, 0, tzinfo=UTC)
    # Insert an incident
    inc = Incident(
        incident_id="inc_api_test_01",
        status="open",
        created_at=now,
        updated_at=now,
        first_signal_ts=now,
        score=0.95,
        severity=Severity.critical,
        entities=[
            Entity(type=EntityType.ip, value="10.10.1.5"),
            Entity(type=EntityType.host, value="jump-host"),
            Entity(type=EntityType.host, value="plc-sim"),
        ],
        signal_ids=["sig_001"],
        event_ids=["evt_001"],
        kill_chain_stages=["lateral_movement"],
        techniques=[],
        decoy_touched=False,
        ot_touched=True,
        novelty_only=False,
        explanation=["Active Industrial Intrusion"],
    )
    upsert_incident(db, inc)

    # 1. Fetch recommendations for incident
    res_recs = client.get("/api/v1/guard/recommendations/inc_api_test_01")
    assert res_recs.status_code == 200
    recs = res_recs.json()
    assert len(recs) >= 3

    # Find the recommendation with allow
    rec_block = next((r for r in recs if r["action"] == "block_ip"), None)
    assert rec_block is not None
    assert rec_block["decision"]["decision"] == "allow"

    # 2. Test evaluate and approve workflow for a needs_human action
    res_eval = client.post(
        "/api/v1/guard/evaluate",
        json={
            "action": "isolate_host",
            "target": "plc-sim",
            "incident_id": "inc_api_test_01",
            "plc_state": {"flag": "normal", "tank_level": 50.0, "valve_open": True},
        },
    )
    assert res_eval.status_code == 200
    eval_data = res_eval.json()
    assert eval_data["decision"] == "needs_human"
    assert eval_data["approval_status"] == "pending_review"
    decision_id = eval_data["decision_id"]

    # 3. Retrieve decision by ID
    res_get_dec = client.get(f"/api/v1/guard/decisions/{decision_id}")
    assert res_get_dec.status_code == 200
    assert res_get_dec.json()["decision_id"] == decision_id

    # 4. Approve the decision
    res_approve = client.post(
        f"/api/v1/guard/decisions/{decision_id}/approve",
        json={
            "operator_name": "lead_secops_carol",
            "notes": "Reviewed system telemetry; safe to isolate during shift",
        },
    )
    assert res_approve.status_code == 200
    approved_data = res_approve.json()
    assert approved_data["approval_status"] == "approved"
    assert approved_data["approved_by"] == "lead_secops_carol"
    assert "Reviewed system telemetry" in approved_data["approval_notes"]

    # 5. Verify attempting to approve a DENY decision returns 400 with clear message
    res_eval_deny = client.post(
        "/api/v1/guard/evaluate",
        json={
            "action": "isolate_host",
            "target": "plc-sim",
            "incident_id": "inc_api_test_01",
            "plc_state": {"flag": "manipulated", "tank_level": 95.0, "valve_open": False},
        },
    )
    assert res_eval_deny.status_code == 200
    deny_decision_id = res_eval_deny.json()["decision_id"]
    assert res_eval_deny.json()["decision"] == "deny"

    res_approve_deny = client.post(
        f"/api/v1/guard/decisions/{deny_decision_id}/approve",
        json={"operator_name": "attacker", "notes": "override safety"},
    )
    assert res_approve_deny.status_code == 400
    assert (
        "Human approval cannot override an explicit safety denial"
        in res_approve_deny.json()["detail"]
    )
