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
    """Use a temporary SQLite database for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_db = Path(tmpdir) / "test_api.db"
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
