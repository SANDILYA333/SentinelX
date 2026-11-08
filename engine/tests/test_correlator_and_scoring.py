"""Unit and synthetic tests for SentinelX Correlator, scoring, and enrichment."""

from datetime import UTC, datetime, timedelta

from sentinelx.correlate.correlator import Correlator
from sentinelx.correlate.scoring import score_incident
from sentinelx.schemas.common import Entity, EntityType, Severity, Technique
from sentinelx.schemas.signal import Signal


def make_test_signal(
    signal_id: str,
    ts: datetime,
    detector: str,
    rule_id: str,
    title: str,
    entities: list[Entity],
    confidence: float = 0.9,
    score: float = 0.8,
    explanation: str = "Test explanation",
    metadata: dict | None = None,
    techniques: list[Technique] | None = None,
) -> Signal:
    """Helper to construct valid Signal objects for correlation testing."""
    return Signal(
        signal_id=signal_id,
        ts=ts,
        detector=detector,  # type: ignore[arg-type]
        rule_id=rule_id,
        title=title,
        confidence=confidence,
        score=score,
        entities=entities,
        evidence_event_ids=[f"evt_{signal_id}"],
        techniques=techniques or [],
        explanation=explanation,
        metadata=metadata or {},
    )


def test_session_aware_ot_weighting_synthetic():
    """Synthetic test proving Phase 4 limitation resolution:

    An OT write from an authorized host/window occurring in the same session/incident
    as a prior suspicious signal must meaningfully raise the incident score versus
    the identical OT write in total isolation.
    """
    now = datetime(2026, 11, 8, 3, 0, 0, tzinfo=UTC)  # 03:00 UTC (inside maintenance window)

    ot_signal = make_test_signal(
        signal_id="sig_ot_write_001",
        ts=now + timedelta(seconds=60),
        detector="rule",
        rule_id="RULE-OT-001",
        title="Modbus coil state change",
        entities=[
            Entity(type=EntityType.host, value="eng-ws"),
            Entity(type=EntityType.device, value="plc-sim"),
            Entity(type=EntityType.user, value="svc_backup"),
        ],
        explanation="Modbus coil 1 write to plc-sim from eng-ws",
        metadata={"domain": "ot"},
    )

    # 1. Isolated OT write (no prior signals in session/incident)
    score_isolated, stages_isolated, sev_isolated = score_incident([ot_signal])

    # 2. Same OT write occurring after prior suspicious initial access signal in the same session
    auth_signal = make_test_signal(
        signal_id="sig_auth_001",
        ts=now,
        detector="rule",
        rule_id="RULE-AUTH-001",
        title="Unexpected cross-zone SSH login",
        entities=[
            Entity(type=EntityType.host, value="jump-host"),
            Entity(type=EntityType.ip, value="10.10.1.5"),
            Entity(type=EntityType.user, value="svc_backup"),
        ],
        explanation="svc_backup logged in from untrusted zone",
    )

    score_with_prior_context, stages_with_prior, sev_with_prior = score_incident(
        [auth_signal, ot_signal]
    )

    # Verifications:
    # Isolated score should be low/medium baseline OT weight (~0.30)
    assert score_isolated == 0.30
    assert stages_isolated == ["ot_impact"]
    assert sev_isolated == Severity.low

    # Score with prior suspicious session context should jump significantly due to session-aware weighting
    assert score_with_prior_context > score_isolated
    assert score_with_prior_context >= 0.95
    assert sev_with_prior == Severity.critical
    assert "initial_access" in stages_with_prior
    assert "ot_impact" in stages_with_prior


def test_confirmed_honeytoken_boost():
    """Verify that confirmed honeytoken / deception signal provides a decisive score boost."""
    now = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)

    scan_signal = make_test_signal(
        signal_id="sig_scan_001",
        ts=now,
        detector="graph",
        rule_id="GRAPH-SCAN-001",
        title="Subnet discovery scan",
        entities=[Entity(type=EntityType.host, value="jump-host")],
    )
    score_scan_only, _, _ = score_incident([scan_signal])

    honey_signal = make_test_signal(
        signal_id="sig_honey_001",
        ts=now + timedelta(seconds=10),
        detector="deception",
        rule_id="RULE-DECOY-001",
        title="Honeytoken credential accessed",
        entities=[
            Entity(type=EntityType.host, value="cowrie"),
            Entity(type=EntityType.user, value="svc_dbadmin"),
        ],
        metadata={"confirmed_honeytoken": True},
    )

    score_with_honey, _, sev_with_honey = score_incident([scan_signal, honey_signal])

    # Honeytoken must boost score substantially
    assert score_with_honey - score_scan_only >= 0.30
    assert score_with_honey >= 0.85
    assert sev_with_honey == Severity.critical


def test_correlator_entity_linking_and_sliding_window():
    """Test Correlator links signals sharing entities within window and separates expired windows."""
    now = datetime(2026, 11, 8, 10, 0, 0, tzinfo=UTC)
    correlator = Correlator(window_sec=600.0)

    # Signal 1: Initial access on jump-host by svc_backup
    sig1 = make_test_signal(
        signal_id="sig_001",
        ts=now,
        detector="rule",
        rule_id="RULE-AUTH-001",
        title="SSH login",
        entities=[
            Entity(type=EntityType.host, value="jump-host"),
            Entity(type=EntityType.user, value="svc_backup"),
        ],
    )
    inc1 = correlator.process_signal(sig1)
    assert len(correlator.incidents) == 1
    assert "sig_001" in inc1.signal_ids

    # Signal 2: Lateral movement 120s later from jump-host to eng-ws
    sig2 = make_test_signal(
        signal_id="sig_002",
        ts=now + timedelta(seconds=120),
        detector="rule",
        rule_id="RULE-NET-001",
        title="Network pivot",
        entities=[
            Entity(type=EntityType.host, value="jump-host"),
            Entity(type=EntityType.host, value="eng-ws"),
        ],
    )
    inc2 = correlator.process_signal(sig2)
    # Must attach to same incident!
    assert len(correlator.incidents) == 1
    assert inc2.incident_id == inc1.incident_id
    assert "sig_002" in inc2.signal_ids
    assert len(inc2.entities) >= 3

    # Signal 3: Completely unrelated entity 2 hours later (outside 600s window)
    sig3 = make_test_signal(
        signal_id="sig_003",
        ts=now + timedelta(hours=2),
        detector="anomaly",
        rule_id="ANOMALY-001",
        title="Unrelated anomaly",
        entities=[Entity(type=EntityType.host, value="unrelated-srv")],
    )
    inc3 = correlator.process_signal(sig3)
    # Must create separate incident
    assert len(correlator.incidents) == 2
    assert inc3.incident_id != inc1.incident_id


def test_incident_graph_construction():
    """Test incremental IncidentGraph node and edge creation."""
    now = datetime(2026, 11, 8, 10, 0, 0, tzinfo=UTC)
    correlator = Correlator()

    sig1 = make_test_signal(
        signal_id="sig_auth",
        ts=now,
        detector="rule",
        rule_id="RULE-AUTH-001",
        title="Auth",
        entities=[
            Entity(type=EntityType.ip, value="10.10.1.5"),
            Entity(type=EntityType.host, value="jump-host"),
            Entity(type=EntityType.user, value="svc_backup"),
        ],
    )
    sig2 = make_test_signal(
        signal_id="sig_pivot",
        ts=now + timedelta(seconds=15),
        detector="rule",
        rule_id="RULE-NET-001",
        title="Pivot",
        entities=[
            Entity(type=EntityType.host, value="jump-host"),
            Entity(type=EntityType.host, value="eng-ws"),
        ],
    )
    sig3 = make_test_signal(
        signal_id="sig_ot",
        ts=now + timedelta(seconds=30),
        detector="rule",
        rule_id="RULE-OT-001",
        title="OT Write",
        entities=[
            Entity(type=EntityType.host, value="eng-ws"),
            Entity(type=EntityType.device, value="plc-sim"),
        ],
    )

    correlator.process_signal(sig1)
    correlator.process_signal(sig2)
    inc = correlator.process_signal(sig3)

    assert inc.graph is not None
    node_labels = {n.label for n in inc.graph.nodes}
    assert "jump-host" in node_labels
    assert "10.10.1.5" in node_labels
    assert "eng-ws" in node_labels
    assert "plc-sim" in node_labels

    edge_labels = {e.label for e in inc.graph.edges}
    assert "unexpected_ssh_login" in edge_labels
    assert "lateral_pivot" in edge_labels
    assert "modbus_write_command" in edge_labels


def test_novelty_only_corroboration_cap():
    """Prove Task 3 (a): An incident whose signals come ONLY from {baseline, graph, anomaly}

    is capped below the budget threshold (default 0.40) and flagged novelty_only=True.
    Without the cap, 2 stages (initial_access + lateral_movement) score 0.5625.
    """
    now = datetime(2026, 11, 8, 10, 0, 0, tzinfo=UTC)
    correlator = Correlator(novelty_cap=0.40)

    # 1. Baseline detector signal (maps to initial_access, weight 0.20)
    sig_base = make_test_signal(
        signal_id="sig_base_001",
        ts=now,
        detector="baseline",
        rule_id="BASE-DEV-001",
        title="Baseline deviation",
        entities=[
            Entity(type=EntityType.host, value="WIN-CORP-DC01"),
            Entity(type=EntityType.user, value="svc_payroll"),
        ],
        techniques=[
            Technique(
                framework="enterprise",
                technique_id="T1078.003",
                name="Valid Accounts",
                tactic="initial-access",
            )
        ],
    )

    # 2. Graph detector signal (maps to lateral_movement, weight 0.25)
    sig_graph = make_test_signal(
        signal_id="sig_graph_001",
        ts=now + timedelta(seconds=10),
        detector="graph",
        rule_id="GRAPH-EDGE-001",
        title="Unprecedented interaction edge",
        entities=[
            Entity(type=EntityType.host, value="WIN-CORP-DC01"),
            Entity(type=EntityType.user, value="svc_payroll"),
        ],
        metadata={"kind": "auth", "source_node": "user:svc_payroll"},
    )

    correlator.process_signal(sig_base)
    inc = correlator.process_signal(sig_graph)

    # In isolation without cap: base_sum = 0.45, multiplier = 1.25x -> 0.5625
    # With cold-start novelty cap: must be capped at 0.40
    assert inc.novelty_only is True
    assert inc.score == 0.40
    assert inc.severity == Severity.low
    assert any("novelty" in exp.lower() for exp in inc.explanation)


def test_novelty_with_rule_corroboration_not_capped():
    """Prove Task 3 (b): The same novelty incident plus one rule signal is NOT capped."""
    now = datetime(2026, 11, 8, 10, 0, 0, tzinfo=UTC)
    correlator = Correlator(novelty_cap=0.40)

    sig_base = make_test_signal(
        signal_id="sig_base_002",
        ts=now,
        detector="baseline",
        rule_id="BASE-DEV-001",
        title="Baseline deviation",
        entities=[
            Entity(type=EntityType.host, value="WIN-CORP-DC01"),
            Entity(type=EntityType.user, value="svc_payroll"),
        ],
        techniques=[
            Technique(
                framework="enterprise",
                technique_id="T1078.003",
                name="Valid Accounts",
                tactic="initial-access",
            )
        ],
    )
    sig_graph = make_test_signal(
        signal_id="sig_graph_002",
        ts=now + timedelta(seconds=10),
        detector="graph",
        rule_id="GRAPH-EDGE-001",
        title="Unprecedented interaction edge",
        entities=[
            Entity(type=EntityType.host, value="WIN-CORP-DC01"),
            Entity(type=EntityType.user, value="svc_payroll"),
        ],
        metadata={"kind": "auth", "source_node": "user:svc_payroll"},
    )
    # Add deterministic rule signal
    sig_rule = make_test_signal(
        signal_id="sig_rule_001",
        ts=now + timedelta(seconds=20),
        detector="rule",
        rule_id="RULE-SHELL-001",
        title="Suspicious shell execution",
        entities=[
            Entity(type=EntityType.host, value="WIN-CORP-DC01"),
            Entity(type=EntityType.user, value="svc_payroll"),
        ],
    )

    correlator.process_signal(sig_base)
    correlator.process_signal(sig_graph)
    inc = correlator.process_signal(sig_rule)

    # Must NOT be capped: retains true multi-stage score 0.5625
    assert inc.novelty_only is False
    assert inc.score == 0.5625
    assert inc.severity == Severity.medium


def test_novelty_with_deception_corroboration_not_capped():
    """Prove Task 3 (c): A deception signal counts as corroboration and removes the cap."""
    now = datetime(2026, 11, 8, 10, 0, 0, tzinfo=UTC)
    correlator = Correlator(novelty_cap=0.40)

    sig_base = make_test_signal(
        signal_id="sig_base_003",
        ts=now,
        detector="baseline",
        rule_id="BASE-DEV-001",
        title="Baseline deviation",
        entities=[
            Entity(type=EntityType.host, value="WIN-CORP-DC01"),
            Entity(type=EntityType.user, value="svc_payroll"),
        ],
        techniques=[
            Technique(
                framework="enterprise",
                technique_id="T1078.003",
                name="Valid Accounts",
                tactic="initial-access",
            )
        ],
    )
    sig_graph = make_test_signal(
        signal_id="sig_graph_003",
        ts=now + timedelta(seconds=10),
        detector="graph",
        rule_id="GRAPH-EDGE-001",
        title="Unprecedented interaction edge",
        entities=[
            Entity(type=EntityType.host, value="WIN-CORP-DC01"),
            Entity(type=EntityType.user, value="svc_payroll"),
        ],
        metadata={"kind": "auth", "source_node": "user:svc_payroll"},
    )
    # Add deception honeytoken signal
    sig_decoy = make_test_signal(
        signal_id="sig_decoy_001",
        ts=now + timedelta(seconds=20),
        detector="deception",
        rule_id="RULE-DECOY-001",
        title="Honeytoken touched",
        entities=[
            Entity(type=EntityType.host, value="WIN-CORP-DC01"),
            Entity(type=EntityType.user, value="svc_payroll"),
        ],
        metadata={"confirmed_honeytoken": True},
    )

    correlator.process_signal(sig_base)
    correlator.process_signal(sig_graph)
    inc = correlator.process_signal(sig_decoy)

    # Must NOT be capped: honeytoken boost elevates score >= 0.85
    assert inc.novelty_only is False
    assert inc.score >= 0.85
    assert inc.severity == Severity.critical
