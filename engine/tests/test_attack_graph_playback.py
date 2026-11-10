"""Unit and integration tests for Phase B Attack Graph & Chronological Timeline Playback."""

from datetime import UTC, datetime, timedelta

from sentinelx.correlate.graph import (
    _resolve_entity_zone,
    build_incident_graph,
    build_incident_timeline,
)
from sentinelx.schemas.common import Domain, Entity, EntityType, Outcome, SourceTool, Technique
from sentinelx.schemas.event import Event, OTFields
from sentinelx.schemas.signal import Signal


def make_test_event(
    event_id: str,
    ts: datetime,
    source_tool: SourceTool = SourceTool.zeek,
    domain: Domain = Domain.it,
    category: str = "network",
    action: str = "conn_established",
    outcome: Outcome = Outcome.success,
    src_ip: str | None = "10.10.1.5",
    dst_ip: str | None = "10.10.1.10",
    host: str | None = "jump-host",
    user: str | None = None,
    cmdline: str | None = None,
    ot: OTFields | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        ts=ts,
        ingested_at=ts,
        source_tool=source_tool,
        domain=domain,
        category=category,  # type: ignore[arg-type]
        action=action,
        outcome=outcome,
        host=host,
        src_ip=src_ip,
        dst_ip=dst_ip,
        user=user,
        cmdline=cmdline,
        ot=ot,
        raw_ref={"source": "test"},
        raw={"test": True},
    )


def make_test_signal(
    signal_id: str,
    ts: datetime,
    rule_id: str = "RULE-NET-001",
    detector: str = "rule",
    entities: list[Entity] | None = None,
    evidence_event_ids: list[str] | None = None,
    techniques: list[Technique] | None = None,
    score: float = 0.5,
) -> Signal:
    return Signal(
        signal_id=signal_id,
        ts=ts,
        detector=detector,  # type: ignore[arg-type]
        rule_id=rule_id,
        title=f"Signal {rule_id}",
        score=score,
        confidence=0.9,
        entities=entities or [],
        evidence_event_ids=evidence_event_ids or ["evt_001"],
        techniques=techniques or [],
        explanation=f"Signal {rule_id} triggered",
    )


# ==============================================================================
# 1. Attacker Identity & Network-Zone Correctness Tests
# ==============================================================================


def test_attacker_role_distinct_from_network_zone():
    """Verify that attacker role is distinct from its authoritative network zone."""
    primary_z, all_z, meta = _resolve_entity_zone("ip", "10.10.1.5")
    # 10.10.1.5 is the attacker in the lab IT subnet (10.10.1.0/24)
    assert primary_z == "it"
    assert "it" in all_z
    assert meta.get("role") == "attacker"
    assert meta.get("status") == "untrusted_actor"

    sig = make_test_signal(
        signal_id="sig_att",
        ts=datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC),
        entities=[Entity(type=EntityType.ip, value="10.10.1.5")],
    )
    graph = build_incident_graph([sig])
    node = graph.nodes[0]
    assert node.network_zone == "it"
    assert node.status == "untrusted_actor"
    assert node.risk_level == "high"


def test_multi_zone_membership_eng_ws_and_jump_host():
    """Verify multi-zone hosts preserve all interface memberships rather than collapsing arbitrarily."""
    # Engineering workstation (eng-ws) has interfaces in IT, OT, and MGMT
    prim_eng, zones_eng, meta_eng = _resolve_entity_zone("host", "eng-ws")
    assert prim_eng == "it"
    assert set(zones_eng) == {"it", "ot", "mgmt"}
    assert meta_eng.get("process_critical") is True

    # Jump Host has interfaces in IT, DMZ, and MGMT
    prim_jump, zones_jump, meta_jump = _resolve_entity_zone("host", "jump-host")
    assert prim_jump == "it"
    assert set(zones_jump) == {"it", "dmz", "mgmt"}

    sig = make_test_signal(
        signal_id="sig_zones",
        ts=datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC),
        entities=[
            Entity(type=EntityType.host, value="eng-ws"),
            Entity(type=EntityType.host, value="jump-host"),
        ],
    )
    graph = build_incident_graph([sig])
    nodes_map = {n.label: n for n in graph.nodes}

    assert set(nodes_map["eng-ws"].network_zones) == {"it", "ot", "mgmt"}
    assert set(nodes_map["jump-host"].network_zones) == {"it", "dmz", "mgmt"}


def test_external_ip_classified_as_external():
    """Verify non-lab external IPs are classified as external, not internal."""
    ext_z, ext_zones, meta = _resolve_entity_zone("ip", "198.51.100.77")
    assert ext_z == "external"
    assert ext_zones == ["external"]
    assert meta.get("status") == "untrusted_actor"


# ==============================================================================
# 2. Graph Relationship Evidence Integrity Tests
# ==============================================================================


def test_no_fabrication_on_missing_source_or_destination():
    """Verify that edges are NOT created when source or destination is missing."""
    now = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)

    # Signal with no host destination (e.g. only user entity)
    sig_missing_dst = make_test_signal(
        signal_id="sig_nodst",
        ts=now,
        rule_id="RULE-AUTH-001",
        entities=[Entity(type=EntityType.user, value="alice")],
    )
    graph1 = build_incident_graph([sig_missing_dst])
    # Must NOT fabricate a default 'host:jump-host' edge
    assert len(graph1.edges) == 0

    # Signal with single host for lateral pivot (no second host)
    sig_single_host = make_test_signal(
        signal_id="sig_single",
        ts=now,
        rule_id="RULE-NET-001",
        entities=[Entity(type=EntityType.host, value="file-srv")],
    )
    graph2 = build_incident_graph([sig_single_host])
    # Must NOT fabricate jump-host -> eng-ws default edge
    assert len(graph2.edges) == 0


def test_inferred_vs_observed_relationship_provenance():
    """Verify that lateral pivots from correlation are labeled 'inferred' while direct auth/OT is 'observed'."""
    now = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)

    sig_auth = make_test_signal(
        signal_id="sig_auth",
        ts=now,
        rule_id="RULE-AUTH-001",
        entities=[
            Entity(type=EntityType.ip, value="10.10.1.5"),
            Entity(type=EntityType.host, value="jump-host"),
        ],
    )
    sig_pivot = make_test_signal(
        signal_id="sig_pivot",
        ts=now + timedelta(seconds=10),
        rule_id="RULE-NET-001",
        entities=[
            Entity(type=EntityType.host, value="jump-host"),
            Entity(type=EntityType.host, value="eng-ws"),
        ],
    )
    graph = build_incident_graph([sig_auth, sig_pivot])

    edges_by_type = {e.relationship_type: e for e in graph.edges}
    # Direct SSH authentication attempt is directly observed
    assert edges_by_type["ssh_authentication"].provenance == "observed"
    # Lateral movement path across hops is an analytical inference
    assert edges_by_type["lateral_pivot"].provenance == "inferred"


def test_duplicate_relationship_aggregation():
    """Verify that repeated observations of the same relationship are merged while preserving evidence IDs."""
    base_ts = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)
    sig1 = make_test_signal(
        signal_id="sig_auth_1",
        ts=base_ts,
        rule_id="RULE-AUTH-001",
        entities=[
            Entity(type=EntityType.ip, value="10.10.1.5"),
            Entity(type=EntityType.host, value="jump-host"),
        ],
        evidence_event_ids=["evt_001"],
    )
    sig2 = make_test_signal(
        signal_id="sig_auth_2",
        ts=base_ts + timedelta(seconds=10),
        rule_id="RULE-AUTH-001",
        entities=[
            Entity(type=EntityType.ip, value="10.10.1.5"),
            Entity(type=EntityType.host, value="jump-host"),
        ],
        evidence_event_ids=["evt_002"],
    )

    graph = build_incident_graph([sig1, sig2])
    auth_edges = [e for e in graph.edges if e.relationship_type == "ssh_authentication"]
    assert len(auth_edges) == 1
    edge = auth_edges[0]
    assert set(edge.event_ids) == {"evt_001", "evt_002"}
    assert edge.first_observed_at == base_ts
    assert edge.last_observed_at == base_ts + timedelta(seconds=10)


# ==============================================================================
# 3. Timeline Integrity & Outcome Precision Tests
# ==============================================================================


def test_timeline_outcome_interpretation_authentications():
    """Verify that failed authentication is never described as successful."""
    now = datetime(2026, 11, 8, 10, 0, 0, tzinfo=UTC)

    ev_fail = make_test_event(
        "evt_fail",
        now,
        category="authentication",
        action="ssh_failed_login",
        outcome=Outcome.failure,
        user="root",
        host="jump-host",
    )
    ev_succ = make_test_event(
        "evt_succ",
        now + timedelta(seconds=1),
        category="authentication",
        action="ssh_login",
        outcome=Outcome.success,
        user="svc_backup",
        host="jump-host",
    )

    timeline = build_incident_timeline("inc_auth", [ev_fail, ev_succ], [])
    assert len(timeline) == 2

    assert "Failed Authentication Attempt" in timeline[0].title
    assert "Failed authentication attempt for account 'root'" in timeline[0].description

    assert "Authentication Observed" in timeline[1].title
    assert "Session authentication recorded for account 'svc_backup'" in timeline[1].description


def test_timeline_outcome_interpretation_modbus_and_commands():
    """Verify that blocked writes and command submissions do not overstate outcomes."""
    now = datetime(2026, 11, 8, 10, 0, 0, tzinfo=UTC)

    # 1. Blocked OT write
    ev_ot_blocked = make_test_event(
        "evt_ot_block",
        now,
        source_tool=SourceTool.modbus,
        domain=Domain.ot,
        category="ot_command",
        action="modbus_write",
        outcome=Outcome.failure,
        host="plc-sim",
        ot=OTFields(unit_id=1, function_code=6, register=105, value=999, is_write=True),
    )

    # 2. Command submission attempt that was denied/failed
    ev_cmd_failed = make_test_event(
        "evt_cmd_fail",
        now + timedelta(seconds=2),
        category="process",
        action="exec_failed",
        outcome=Outcome.failure,
        cmdline="sudo rm -rf /etc",
        host="eng-ws",
    )

    timeline = build_incident_timeline("inc_test", [ev_ot_blocked, ev_cmd_failed], [])
    assert len(timeline) == 2

    assert "Blocked/Failed" in timeline[0].title
    assert "command blocked or rejected by controller" in timeline[0].description

    assert "Command Submission Attempt" in timeline[1].title
    assert "Command submission recorded" in timeline[1].description


def test_timeline_chronological_ordering():
    """Verify that timeline events are ordered strictly by timestamp with stable secondary sort."""
    base_ts = datetime(2026, 11, 8, 10, 0, 0, tzinfo=UTC)

    ev3 = make_test_event("evt_003", base_ts + timedelta(seconds=30), action="modbus_write")
    ev1 = make_test_event("evt_001", base_ts, action="ssh_login")
    ev2_b = make_test_event("evt_002_b", base_ts + timedelta(seconds=15), action="conn_b")
    ev2_a = make_test_event("evt_002_a", base_ts + timedelta(seconds=15), action="conn_a")

    timeline = build_incident_timeline("inc_order", [ev3, ev1, ev2_b, ev2_a], [])
    assert [t.event_id for t in timeline] == ["evt_001", "evt_002_a", "evt_002_b", "evt_003"]


def test_deterministic_reconstruction_property():
    """Verify that timeline reconstruction is pure and deterministic given the same inputs."""
    base_ts = datetime(2026, 11, 8, 10, 0, 0, tzinfo=UTC)
    events = [
        make_test_event(f"evt_{i:03d}", base_ts + timedelta(seconds=i * 10)) for i in range(8)
    ]

    t1 = build_incident_timeline("inc_det", events, [])
    t2 = build_incident_timeline("inc_det", events, [])

    assert len(t1) == len(t2)
    for a, b in zip(t1, t2, strict=True):
        assert a.id == b.id
        assert a.event_id == b.event_id
        assert a.title == b.title
        assert a.description == b.description
