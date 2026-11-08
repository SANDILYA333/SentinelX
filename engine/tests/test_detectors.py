"""Unit and integration tests for SentinelX Phase 4 detection engines."""

from datetime import UTC, datetime

import pytest
from sentinelx.detect.baseline.detector import BaselineDetector
from sentinelx.detect.baseline.model import BaselineModel, EntityProfile
from sentinelx.detect.graph.detector import GraphDetector
from sentinelx.detect.graph.model import GraphModel
from sentinelx.detect.rules.engine import RulesEngine, load_rules
from sentinelx.detect.rules.models import RuleDefinition
from sentinelx.detect.runtime import DetectorPipeline
from sentinelx.enrich.mitre import get_mitre_catalog
from sentinelx.schemas.event import Event, OTFields
from sentinelx.store.sqlite import init_db


@pytest.fixture
def test_event_factory():
    def _create(
        event_id: str = "evt_test_001",
        user: str | None = "alice",
        host: str | None = "jump-host",
        src_ip: str | None = "10.10.1.10",
        dst_ip: str | None = "10.10.1.20",
        category: str = "authentication",
        action: str = "login",
        domain: str = "it",
        cmdline: str | None = "uptime",
        tags: list[str] | None = None,
        ot: OTFields | None = None,
    ) -> Event:
        t = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)
        return Event(
            event_id=event_id,
            ts=t,
            ingested_at=t,
            source_tool="wazuh",
            domain=domain,  # type: ignore[arg-type]
            category=category,  # type: ignore[arg-type]
            action=action,
            outcome="success",
            host=host,
            user=user,
            src_ip=src_ip,
            dst_ip=dst_ip,
            cmdline=cmdline,
            tags=tags or [],
            ot=ot,
            raw_ref={"file": "test", "offset": 0},
            raw={"sample": True},
        )

    return _create


# ==============================================================================
# Task 1: MITRE ATT&CK Catalog Tests
# ==============================================================================
def test_mitre_catalog_loading_and_technique_resolution():
    catalog = get_mitre_catalog()
    assert len(catalog) >= 10

    # Enterprise techniques
    ssh_tech = catalog.get("T1021.004")
    assert ssh_tech is not None
    assert ssh_tech.technique_id == "T1021.004"
    assert ssh_tech.framework == "enterprise"

    # ICS techniques
    ot_tech = catalog.get("T0855")
    assert ot_tech is not None
    assert ot_tech.technique_id == "T0855"
    assert ot_tech.framework == "ics"


# ==============================================================================
# Task 2: Rules Engine Loading and Loud Failures (DoD 2)
# ==============================================================================
def test_rules_load_and_validate():
    rules = load_rules()
    assert len(rules) >= 6
    rule_ids = {r.id for r in rules}
    expected = {
        "RULE-SHELL-001",
        "RULE-AUTH-001",
        "RULE-CRED-001",
        "RULE-DECOY-001",
        "RULE-OT-001",
        "RULE-NET-001",
    }
    assert expected.issubset(rule_ids)

    # Initialize RulesEngine without error
    engine = RulesEngine(rules)
    assert engine is not None


def test_malformed_rule_fails_loudly_at_load_time():
    """Verify DoD 2: a deliberately malformed rule file fails loudly at load with a clear error."""
    # 1. Unknown technique ID
    bad_rule_technique = RuleDefinition(
        id="RULE-BAD-001",
        title="Bad Technique Rule",
        severity_hint="high",
        technique_ids=["T9999.999_NON_EXISTENT"],
        explanation_template="Bad rule test",
        condition={"field": "action", "operator": "eq", "value": "test"},
    )
    with pytest.raises(ValueError, match="unknown MITRE technique ID"):
        RulesEngine([bad_rule_technique])

    # 2. Duplicate Rule ID
    rule1 = RuleDefinition(
        id="RULE-DUP-001",
        title="Duplicate Rule 1",
        severity_hint="low",
        technique_ids=["T1078"],
        explanation_template="Dup rule test 1",
        condition={"field": "action", "operator": "eq", "value": "test"},
    )
    rule2 = RuleDefinition(
        id="RULE-DUP-001",
        title="Duplicate Rule 2",
        severity_hint="high",
        technique_ids=["T1078"],
        explanation_template="Dup rule test 2",
        condition={"field": "action", "operator": "eq", "value": "test2"},
    )
    with pytest.raises(ValueError, match="Duplicate rule id detected"):
        RulesEngine([rule1, rule2])

    # 3. Invalid condition operator
    bad_rule_op = RuleDefinition(
        id="RULE-BAD-OP",
        title="Bad Operator Rule",
        severity_hint="low",
        technique_ids=["T1078"],
        explanation_template="Bad op rule test",
        condition={"field": "action", "operator": "UNSUPPORTED_OP", "value": "test"},
    )
    with pytest.raises(ValueError, match="invalid condition"):
        RulesEngine([bad_rule_op])


def test_rule_auth_001_context_aware_genericness(test_event_factory):
    """Verify Phase 4.2 genericness: RULE-AUTH-001 fires on unexpected zone/unauthorized IPs, not just 10.10.1.5."""
    rules = load_rules()
    engine = RulesEngine(rules)

    # 1. Synthetic event: login from unauthorized IP in unexpected zone (10.10.9.99 mgmt subnet)
    unauth_mgmt_ev = test_event_factory(
        event_id="evt_synth_unauth_mgmt",
        user="svc_backup",
        host="jump-host",
        src_ip="10.10.9.99",
        dst_ip="10.10.1.10",
        category="authentication",
        action="ssh_login",
    )
    sigs_mgmt = engine.evaluate_event(unauth_mgmt_ev)
    auth_sigs_mgmt = [s for s in sigs_mgmt if s.rule_id == "RULE-AUTH-001"]
    assert len(auth_sigs_mgmt) == 1, (
        "RULE-AUTH-001 must fire on unauthorized IP from mgmt zone (10.10.9.99)"
    )
    assert auth_sigs_mgmt[0].rule_id == "RULE-AUTH-001"
    assert "T1078.003" in [t.technique_id for t in auth_sigs_mgmt[0].techniques]

    # 2. Synthetic event: login from unapproved rogue IP in IT subnet (10.10.1.77)
    unauth_it_ev = test_event_factory(
        event_id="evt_synth_unauth_it",
        user="alice",
        host="jump-host",
        src_ip="10.10.1.77",
        dst_ip="10.10.1.10",
        category="authentication",
        action="ssh_login",
    )
    sigs_it = engine.evaluate_event(unauth_it_ev)
    auth_sigs_it = [s for s in sigs_it if s.rule_id == "RULE-AUTH-001"]
    assert len(auth_sigs_it) == 1, (
        "RULE-AUTH-001 must fire on unapproved client origin (10.10.1.77)"
    )

    # 3. Benign login from authorized workstation (10.10.1.50)
    benign_ev = test_event_factory(
        event_id="evt_synth_benign",
        user="alice",
        host="jump-host",
        src_ip="10.10.1.50",
        dst_ip="10.10.1.10",
        category="authentication",
        action="ssh_login",
    )
    sigs_benign = engine.evaluate_event(benign_ev)
    auth_sigs_benign = [s for s in sigs_benign if s.rule_id == "RULE-AUTH-001"]
    assert len(auth_sigs_benign) == 0, (
        "RULE-AUTH-001 must NOT fire on authorized client origin (10.10.1.50)"
    )


# ==============================================================================
# Task 3: Baseline Behavioral Profile Detector Tests
# ==============================================================================
def test_baseline_detector_flags_deviations(test_event_factory):
    # Train synthetic baseline
    profile = EntityProfile(
        entity_id="user:alice",
        entity_type="user",
        active_hours=[8, 9, 10, 11, 12, 13, 14, 15, 16],
        allowed_hosts=["jump-host", "file-srv"],
        allowed_zones=["it"],
        allowed_commands=["uptime", "df -h"],
        total_observations=100,
    )
    model = BaselineModel(
        profiles={"user:alice": profile},
        known_users=["alice"],
        known_hosts=["jump-host", "file-srv"],
    )

    detector = BaselineDetector(model=model, threshold=0.60)

    # Benign routine event -> 0 signals
    benign_ev = test_event_factory(user="alice", host="jump-host", cmdline="uptime")
    assert detector.evaluate_event(benign_ev) == []

    # Unknown user -> baseline signal
    bad_user_ev = test_event_factory(user="attacker_user", host="jump-host")
    bad_user_sigs = detector.evaluate_event(bad_user_ev)
    assert len(bad_user_sigs) == 1
    assert bad_user_sigs[0].detector == "baseline"
    assert "unknown_user" in bad_user_sigs[0].metadata["factors"]

    # Known user executing unseen command and rare host -> baseline signal
    anom_ev = test_event_factory(
        user="alice",
        host="db-srv",  # Rare host (+0.40)
        cmdline="cat /etc/shadow",  # Unseen command (+0.50) -> total 0.90 >= 0.60
    )
    anom_sigs = detector.evaluate_event(anom_ev)
    assert len(anom_sigs) == 1
    assert anom_sigs[0].score >= 0.60
    assert "rare_host_for_user" in anom_sigs[0].metadata["factors"]
    assert "unseen_command" in anom_sigs[0].metadata["factors"]


# ==============================================================================
# Task 4: Graph Detector Tests
# ==============================================================================
def test_graph_detector_new_edges_and_scans(test_event_factory):
    known_model = GraphModel(
        known_edges=[
            ["user:alice", "host:jump-host"],
            ["ip:10.10.1.10", "ip:10.10.1.20"],
        ]
    )
    detector = GraphDetector(
        model=known_model,
        scan_window_seconds=60.0,
        scan_threshold=3,
    )

    # 1. Known edge -> 0 signals
    ev_known = test_event_factory(
        user="alice",
        host="jump-host",
        src_ip="10.10.1.10",
        dst_ip="10.10.1.20",
    )
    assert detector.evaluate_event(ev_known) == []

    # 2. Genuinely new edge -> GRAPH-EDGE-001 signal
    ev_new = test_event_factory(
        user="eng1",
        host="db-srv",
        src_ip="10.10.1.10",
        dst_ip="10.10.1.30",
    )
    new_sigs = detector.evaluate_event(ev_new)
    assert any(s.rule_id == "GRAPH-EDGE-001" for s in new_sigs)

    # 3. High out-degree scan burst -> GRAPH-SCAN-001 signal
    # Send packets to distinct IPs to cross threshold 3
    for i in range(1, 5):
        scan_ev = test_event_factory(
            event_id=f"evt_scan_{i}",
            user=None,
            host=None,
            src_ip="10.10.1.5",
            dst_ip=f"10.10.1.{100 + i}",
            category="network",
        )
        sigs = detector.evaluate_event(scan_ev)
        if any(s.rule_id == "GRAPH-SCAN-001" for s in sigs):
            break
    else:
        pytest.fail("High out-degree discovery scan was not triggered")


# ==============================================================================
# Task 5: Deception Signals and Confirmed Honeytoken Elevation (DoD 6)
# ==============================================================================
def test_confirmed_honeytoken_confidence_elevation(test_event_factory):
    rules = load_rules()
    engine = RulesEngine(rules)

    # Standard decoy touch with generic user
    decoy_ev = test_event_factory(
        domain="decoy",
        user="guest",
        host="cowrie",
        category="decoy_interaction",
    )
    sigs1 = engine.evaluate_event(decoy_ev)
    assert len(sigs1) >= 1
    assert sigs1[0].detector == "deception"
    assert sigs1[0].confidence <= 0.95

    # Honeytoken touch with known honey credential 'svc_dbadmin'
    honey_ev = test_event_factory(
        domain="decoy",
        user="svc_dbadmin",  # Defined in content/assets.yaml
        host="cowrie",
        category="decoy_interaction",
    )
    sigs2 = engine.evaluate_event(honey_ev)
    assert len(sigs2) >= 1
    honey_sig = next(s for s in sigs2 if s.metadata.get("confirmed_honeytoken"))
    assert honey_sig.score == 0.99
    assert honey_sig.confidence == 0.99
    assert "confirmed_honeytoken" in honey_sig.metadata["tags"]


# ==============================================================================
# Task 6 & DoD 9: Detector Pipeline & Idempotency
# ==============================================================================
def test_detector_pipeline_idempotency(test_event_factory, tmp_path):
    db_file = tmp_path / "test_idempotency.db"
    db = init_db(db_file)
    pipeline = DetectorPipeline(db=db)

    # Malicious command triggering RULE-SHELL-001
    bad_ev = test_event_factory(
        event_id="evt_attack_eval_01",
        category="process",
        action="exec",
        cmdline="sshpass -p Backup2024! ssh svc_backup@10.10.1.10",
    )

    # First run
    sigs1 = pipeline.process_event(bad_ev)
    assert len(sigs1) >= 1

    cur = db.execute("SELECT COUNT(*) FROM signals")
    count1 = cur.fetchone()[0]
    assert count1 >= 1

    # Second run with same event (replay idempotency)
    pipeline.reset_state()
    sigs2 = pipeline.process_event(bad_ev)
    assert len(sigs2) == len(sigs1)
    assert sigs2[0].signal_id == sigs1[0].signal_id

    cur = db.execute("SELECT COUNT(*) FROM signals")
    count2 = cur.fetchone()[0]
    assert count2 == count1, f"Signal count doubled: {count2} != {count1}"
