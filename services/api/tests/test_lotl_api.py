"""Integration tests for Living-off-the-Land (LotL) Deception REST API endpoints."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.config import settings
from app.db import close_db, get_db
from app.main import app
from fastapi.testclient import TestClient
from sentinelx.schemas.common import Outcome, Severity
from sentinelx.schemas.deception import LotLInteraction
from sentinelx.store.sqlite import record_lotl_interaction


@pytest.fixture(autouse=True)
def test_db_env(monkeypatch):
    """Use an isolated temporary SQLite database for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_db = Path(tmpdir) / "test_api_lotl.db"
        monkeypatch.setattr(settings, "SENTINELX_DB_PATH", tmp_db)
        monkeypatch.setattr(settings, "SENTINELX_ENV", "dev")
        close_db()
        get_db()
        yield
        close_db()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_lotl_lures_listing_and_filtering(client: TestClient):
    """Test GET /api/v1/deception/lotl/lures endpoint with filtering."""
    resp = client.get("/api/v1/deception/lotl/lures")
    assert resp.status_code == 200
    lures = resp.json()
    assert len(lures) >= 14

    # Filter by host
    resp_host = client.get("/api/v1/deception/lotl/lures?host=eng-ws")
    assert resp_host.status_code == 200
    eng_lures = resp_host.json()
    assert len(eng_lures) >= 4
    for l in eng_lures:
        assert l["host"] == "eng-ws"

    # Filter by lure_type
    resp_type = client.get("/api/v1/deception/lotl/lures?lure_type=shell_history")
    assert resp_type.status_code == 200
    hist_lures = resp_type.json()
    assert len(hist_lures) >= 2


def test_lotl_lure_detail_and_toggle(client: TestClient):
    """Test retrieving detail and administrative enable/disable toggle."""
    resp = client.get("/api/v1/deception/lotl/lures/LURE-HIST-001")
    assert resp.status_code == 200
    lure = resp.json()
    assert lure["lure_id"] == "LURE-HIST-001"
    assert lure["enabled"] is True

    # Disable lure
    resp_dis = client.post("/api/v1/deception/lotl/lures/LURE-HIST-001/disable")
    assert resp_dis.status_code == 200
    assert resp_dis.json()["enabled"] is False
    assert resp_dis.json()["status"] == "disabled"

    # Verify detail reflects disabled state
    resp_after = client.get("/api/v1/deception/lotl/lures/LURE-HIST-001")
    assert resp_after.json()["enabled"] is False

    # Re-enable lure
    resp_en = client.post("/api/v1/deception/lotl/lures/LURE-HIST-001/enable")
    assert resp_en.status_code == 200
    assert resp_en.json()["enabled"] is True
    assert resp_en.json()["status"] == "active"


def test_lotl_interactions_and_analytics(client: TestClient):
    """Test GET /api/v1/deception/lotl/interactions and analytics."""
    db = get_db()
    now = datetime.now(UTC)

    # Insert sample LotL interactions
    act1 = LotLInteraction(
        interaction_id="lotl_test_act_01",
        lure_id="LURE-HIST-001",
        lure_name="Legacy Engineering Workstation Bash History",
        lure_type="shell_history",
        interaction_type="shell_history_read",
        host="eng-ws",
        user="svc_backup",
        cmdline="cat /home/svc_backup/.bash_history",
        target="/home/svc_backup/.bash_history",
        ts=now,
        event_id="evt_lotl_api_01",
        severity=Severity.high,
        evidence_source="wazuh",
        provenance="observed",
        mitre_technique="T1552.001",
        outcome=Outcome.success,
    )
    record_lotl_interaction(db, act1)

    act2 = LotLInteraction(
        interaction_id="lotl_test_act_02",
        lure_id="LURE-ENV-001",
        lure_name="Canary Backup Environment Credentials",
        lure_type="canary_env",
        interaction_type="canary_credential_presented",
        host="eng-ws",
        user="svc_backup",
        cmdline="curl -H 'Authorization: Bearer sx_canary_tok' http://10.10.2.30:8080/canary/auth",
        target="http://10.10.2.30:8080/canary/auth",
        ts=now,
        event_id="evt_lotl_api_02",
        severity=Severity.critical,
        evidence_source="opencanary",
        provenance="observed",
        mitre_technique="T1078.003",
        outcome=Outcome.success,
    )
    record_lotl_interaction(db, act2)

    # Query interactions
    resp_acts = client.get("/api/v1/deception/lotl/interactions")
    assert resp_acts.status_code == 200
    acts = resp_acts.json()
    assert len(acts) == 2
    assert acts[0]["interaction_id"] in ("lotl_test_act_01", "lotl_test_act_02")

    # Query analytics
    resp_ana = client.get("/api/v1/deception/lotl/analytics")
    assert resp_ana.status_code == 200
    ana = resp_ana.json()
    assert ana["total_interactions"] == 2
    assert ana["canary_presentations"] == 1
    assert "eng-ws" in ana["interacting_hosts"]


def test_lotl_health_endpoint(client: TestClient):
    """Test GET /api/v1/deception/lotl/health."""
    resp = client.get("/api/v1/deception/lotl/health")
    assert resp.status_code == 200
    health = resp.json()
    assert health["total_lures"] >= 14
    assert health["active_lures"] >= 12
    assert health["unsupported_lures"] >= 1
    assert len(health["details"]) == health["total_lures"]


def test_secret_redaction_in_api(client: TestClient):
    """Verify that private keys and plaintext tokens are never exposed in lure APIs."""
    resp = client.get("/api/v1/deception/lotl/lures/LURE-SSH-001")
    assert resp.status_code == 200
    lure_data = resp.text
    # Ensure full private key block is not present
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in lure_data

