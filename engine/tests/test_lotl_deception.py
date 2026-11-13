"""Comprehensive Unit & Integration Test Suite for Living-off-the-Land (LotL) Deception Engine."""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sentinelx.correlate.correlator import Correlator
from sentinelx.deception.classifier import (
    classify_deception_event,
    generate_deception_interpretations,
    is_deception_event,
)
from sentinelx.deception.lotl.health import LureHealthMonitor
from sentinelx.deception.lotl.manager import LureManager
from sentinelx.deception.lotl.monitor import InteractionMonitor
from sentinelx.deception.lotl.normalizer import normalize_lotl_event
from sentinelx.deception.lotl.registry import LureRegistry, compute_sha256
from sentinelx.detect.rules.engine import RulesEngine, load_rules
from sentinelx.schemas.common import Domain, Outcome, Severity, SourceTool
from sentinelx.schemas.deception import LotLInteraction, LotLLure
from sentinelx.schemas.event import Event
from sentinelx.store.sqlite import (
    init_db,
    record_lotl_interaction,
    upsert_lotl_lure,
)


@pytest.fixture
def memory_db():
    """In-memory SQLite connection with full SentinelX schema initialized."""
    conn = init_db(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def test_registry(memory_db):
    """LureRegistry initialized with default catalog."""
    return LureRegistry(memory_db)


def test_lure_registry_seeding_and_retrieval(test_registry):
    """Test LureRegistry seeds default catalog and supports retrieval and filtering."""
    lures = test_registry.list_lures()
    assert len(lures) >= 14

    # Verify specific key lures exist
    hist_lure = test_registry.get_lure("LURE-HIST-001")
    assert hist_lure is not None
    assert hist_lure.name == "Legacy Engineering Workstation Bash History"
    assert hist_lure.host == "eng-ws"
    assert hist_lure.lure_type == "shell_history"
    assert hist_lure.path == "/home/svc_backup/.bash_history"
    assert hist_lure.status == "active"
    assert hist_lure.enabled is True
    assert "T1552.001" in hist_lure.mitre_techniques

    # Filtering tests
    eng_lures = test_registry.list_lures(host="eng-ws")
    assert len(eng_lures) >= 4
    for l in eng_lures:
        assert l.host == "eng-ws"

    ssh_lures = test_registry.list_lures(lure_type="ssh_key")
    assert len(ssh_lures) >= 1
    assert ssh_lures[0].lure_id == "LURE-SSH-001"

    # Unsupported platform check
    win_lure = test_registry.get_lure("LURE-WIN-001")
    assert win_lure is not None
    assert win_lure.platform == "windows"
    assert win_lure.status == "unsupported"
    assert win_lure.enabled is False


def test_lure_registry_enable_disable(test_registry):
    """Test administrative enabling and disabling of lures."""
    lure_id = "LURE-HIST-001"
    disabled = test_registry.disable_lure(lure_id)
    assert disabled is not None
    assert disabled.enabled is False
    assert disabled.status == "disabled"

    # Verify state in DB
    refetched = test_registry.get_lure(lure_id)
    assert refetched.enabled is False
    assert refetched.status == "disabled"

    # Re-enable
    enabled = test_registry.enable_lure(lure_id)
    assert enabled is not None
    assert enabled.enabled is True
    assert enabled.status == "active"


def test_lure_command_and_path_matching(test_registry):
    """Test finding lures via command strings and file paths."""
    # Command matching
    lure = test_registry.find_lure_by_command("cat /home/svc_backup/.bash_history", host="eng-ws")
    assert lure is not None
    assert lure.lure_id == "LURE-HIST-001"

    lure_ssh = test_registry.find_lure_by_command(
        "ssh -i ~/.ssh/id_ed25519_backup svc_dbadmin@10.10.2.20", host="eng-ws"
    )
    assert lure_ssh is not None
    assert lure_ssh.lure_id == "LURE-SSH-001"

    # Path matching
    by_path = test_registry.find_lures_by_path("/opt/scada/config/controllers.conf", host="eng-ws")
    assert len(by_path) >= 1
    assert by_path[0].lure_id == "LURE-CFG-004"


def test_lure_manager_manifest_and_safe_removal(test_registry, tmp_path):
    """Test LureManager maintains manifest and refuses to touch unmanaged files."""
    manifest_file = tmp_path / "test_manifest.json"
    manager = LureManager(test_registry, manifest_path=manifest_file)

    lure = test_registry.get_lure("LURE-CFG-001")
    assert lure is not None

    # Refusal to remove unmanaged lure
    success, msg = manager.remove_lure("UNMANAGED-001")
    assert not success
    assert "not in managed manifest" in msg

    # Record into manifest
    manager._record_manifest(lure, "abc123sha", "0644", "root:root")
    assert "LURE-CFG-001" in manager._manifest
    assert manifest_file.exists()


def test_interaction_monitor_process_telemetry(test_registry, memory_db):
    """Test InteractionMonitor evaluates command execution and attributes LotL touch."""
    monitor = InteractionMonitor(test_registry, memory_db)

    now = datetime.now(UTC)
    evt = Event(
        event_id="evt_test_history_01",
        ts=now,
        ingested_at=now,
        source_tool=SourceTool.wazuh,
        domain=Domain.it,
        category="process",
        action="exec",
        outcome=Outcome.success,
        host="eng-ws",
        user="svc_backup",
        process="cat",
        cmdline="cat /home/svc_backup/.bash_history",
        raw_ref={"file": "cmd.jsonl", "offset": 10},
        raw={"cmd": "cat /home/svc_backup/.bash_history"},
        tags=["audit_cmd"],
    )

    interaction = monitor.evaluate_event(evt)
    assert interaction is not None
    assert interaction.lure_id == "LURE-HIST-001"
    assert interaction.interaction_type == "shell_history_read"
    assert interaction.host == "eng-ws"
    assert interaction.user == "svc_backup"
    assert interaction.provenance == "observed"
    assert interaction.mitre_technique == "T1552.001"

    # Verify lure total_interactions updated in DB
    updated_lure = test_registry.get_lure("LURE-HIST-001")
    assert updated_lure.total_interactions == 1
    assert updated_lure.last_interaction is not None


def test_interaction_monitor_fim_telemetry(test_registry, memory_db):
    """Test InteractionMonitor evaluates FIM file modification events."""
    monitor = InteractionMonitor(test_registry, memory_db)

    now = datetime.now(UTC)
    evt = Event(
        event_id="evt_test_fim_01",
        ts=now,
        ingested_at=now,
        source_tool=SourceTool.wazuh,
        domain=Domain.it,
        category="file",
        action="file_modified",
        outcome=Outcome.success,
        host="eng-ws",
        raw_ref={"file": "archives.json", "offset": 100},
        raw={"path": "/opt/scada/config/controllers.conf"},
        tags=["fim"],
    )

    interaction = monitor.evaluate_event(evt)
    assert interaction is not None
    assert interaction.lure_id == "LURE-CFG-004"
    assert interaction.interaction_type == "decoy_file_modified"
    assert interaction.severity == Severity.high


def test_event_normalizer_canonical_output(test_registry):
    """Test EventNormalizer generates strict canonical Event schema with lure attribution."""
    lure = test_registry.get_lure("LURE-SSH-001")
    now = datetime.now(UTC)

    interaction = LotLInteraction(
        interaction_id="lotl_act_001",
        lure_id=lure.lure_id,
        lure_name=lure.name,
        lure_type=lure.lure_type,
        interaction_type="ssh_key_read",
        host="eng-ws",
        user="svc_backup",
        process="cat",
        cmdline="cat /home/svc_backup/.ssh/id_ed25519_backup",
        target=lure.path,
        ts=now,
        event_id="evt_normalizer_test_01",
        severity=Severity.critical,
        evidence_source="wazuh",
        provenance="observed",
        mitre_technique="T1552.004",
    )

    canonical_event = normalize_lotl_event(interaction, lure)
    assert canonical_event.event_id == "evt_normalizer_test_01"
    assert canonical_event.domain == Domain.decoy
    assert "lotl" in canonical_event.tags
    assert f"lure_id:{lure.lure_id}" in canonical_event.tags
    assert "technique:T1552.004" in canonical_event.tags
    assert canonical_event.raw["lure_name"] == lure.name


def test_lure_health_monitor_reporting(test_registry, memory_db, tmp_path):
    """Test LureHealthMonitor computes active, disabled, and unsupported counts."""
    manager = LureManager(test_registry, manifest_path=tmp_path / "manifest.json")
    health_mon = LureHealthMonitor(test_registry, manager, memory_db)

    status = health_mon.check_health()
    assert status.total_lures >= 14
    assert status.unsupported_lures >= 1  # Windows stub
    assert status.active_lures >= 12
    assert len(status.details) == status.total_lures


def test_deception_classifier_lotl_recognition():
    """Test deception classifier correctly classifies LotL canonical events."""
    now = datetime.now(UTC)
    evt = Event(
        event_id="evt_lotl_class_01",
        ts=now,
        ingested_at=now,
        source_tool=SourceTool.wazuh,
        domain=Domain.decoy,
        category="process",
        action="exec",
        outcome=Outcome.success,
        host="eng-ws",
        user="svc_backup",
        cmdline="cat /home/svc_backup/.bash_history",
        raw_ref={"file": "cmd.jsonl", "offset": 50},
        raw={"cmd": "cat /home/svc_backup/.bash_history"},
        tags=["decoy", "lotl", "lure_id:LURE-HIST-001", "lure_type:shell_history", "shell_history_read"],
    )

    assert is_deception_event(evt) is True

    activity = classify_deception_event(evt)
    assert activity is not None
    assert activity.interaction_type == "shell_history_read"
    assert activity.mitre_technique == "T1552.001"
    assert activity.severity == Severity.high
    assert "Living-off-the-Land Shell History Enumeration" in activity.title

    # Interpretations test
    interpretations = generate_deception_interpretations([activity])
    assert len(interpretations) >= 1
    assert "OBSERVED" in interpretations[0]
    assert "INFERRED" in interpretations[0]
    assert "Living-off-the-Land shell history enumeration" in interpretations[0]


def test_rules_engine_lotl_detection(test_registry):
    """Test RulesEngine fires RULE-LOTL-001 and RULE-LOTL-002 on decoy touches."""
    rules = load_rules()
    engine = RulesEngine(rules)

    now = datetime.now(UTC)

    # 1. Shell history read event
    evt_hist = Event(
        event_id="evt_rule_test_hist",
        ts=now,
        ingested_at=now,
        source_tool=SourceTool.wazuh,
        domain=Domain.it,
        category="process",
        action="shell_history_read",
        outcome=Outcome.success,
        host="eng-ws",
        user="svc_backup",
        cmdline="cat /home/svc_backup/.bash_history",
        raw_ref={"file": "cmd.jsonl", "offset": 1},
        raw={},
        tags=["lotl", "shell_history_read"],
    )
    signals_hist = engine.evaluate_event(evt_hist)
    assert any(s.rule_id == "RULE-LOTL-001" for s in signals_hist)

    # 2. SSH key read event
    evt_ssh = Event(
        event_id="evt_rule_test_ssh",
        ts=now,
        ingested_at=now,
        source_tool=SourceTool.wazuh,
        domain=Domain.it,
        category="process",
        action="ssh_key_read",
        outcome=Outcome.success,
        host="eng-ws",
        user="svc_backup",
        cmdline="cat /home/svc_backup/.ssh/id_ed25519_backup",
        raw_ref={"file": "cmd.jsonl", "offset": 2},
        raw={},
        tags=["lotl", "ssh_key_read"],
    )
    signals_ssh = engine.evaluate_event(evt_ssh)
    assert any(s.rule_id == "RULE-LOTL-002" for s in signals_ssh)


def test_incident_correlator_lotl_attack_chain(memory_db):
    """Test multi-stage incident correlation linking LotL lure discovery to decoy authentication."""
    rules = load_rules()
    engine = RulesEngine(rules)
    correlator = Correlator(db=memory_db, window_sec=1800.0)

    now = datetime.now(UTC)

    # Step 1: Shell History Enumeration on eng-ws
    ev1 = Event(
        event_id="evt_chain_1",
        ts=now,
        ingested_at=now,
        source_tool=SourceTool.wazuh,
        domain=Domain.it,
        category="process",
        action="shell_history_read",
        outcome=Outcome.success,
        host="eng-ws",
        src_ip="10.10.1.5",
        user="svc_backup",
        cmdline="cat /home/svc_backup/.bash_history",
        raw_ref={"file": "cmd.jsonl", "offset": 1},
        raw={},
        tags=["lotl", "shell_history_read"],
    )
    sigs1 = engine.evaluate_event(ev1)
    assert sigs1
    inc1 = correlator.process_signal(sigs1[0])
    assert inc1 is not None

    # Step 2: SSH Key Theft on eng-ws
    ev2 = Event(
        event_id="evt_chain_2",
        ts=now,
        ingested_at=now,
        source_tool=SourceTool.wazuh,
        domain=Domain.it,
        category="process",
        action="ssh_key_read",
        outcome=Outcome.success,
        host="eng-ws",
        src_ip="10.10.1.5",
        user="svc_backup",
        cmdline="cat /home/svc_backup/.ssh/id_ed25519_backup",
        raw_ref={"file": "cmd.jsonl", "offset": 2},
        raw={},
        tags=["lotl", "ssh_key_read"],
    )
    sigs2 = engine.evaluate_event(ev2)
    assert sigs2
    inc2 = correlator.process_signal(sigs2[0])
    assert inc2.incident_id == inc1.incident_id
    assert len(inc2.signal_ids) >= 2
    assert inc2.score >= 0.85

