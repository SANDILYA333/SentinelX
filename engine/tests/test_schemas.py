"""Tests for SentinelX schema contracts, validators, and serialization."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from sentinelx.schemas import (
    Domain,
    Entity,
    EntityType,
    Event,
    GraphEdge,
    GraphNode,
    GuardDecision,
    Incident,
    IncidentGraph,
    OTFields,
    Outcome,
    Severity,
    Signal,
    SourceTool,
    Technique,
    new_id,
)


def sample_event() -> Event:
    now = datetime.now(UTC)
    return Event(
        event_id=new_id("evt"),
        ts=now,
        ingested_at=now,
        source_tool=SourceTool.modbus,
        domain=Domain.ot,
        category="ot_command",
        action="modbus_write",
        outcome=Outcome.success,
        host="plc-01",
        src_ip="192.168.1.10",
        dst_ip="192.168.1.50",
        src_port=50000,
        dst_port=502,
        protocol="modbus",
        ot=OTFields(
            unit_id=1,
            device_id="plc-01",
            function_code=16,
            register=40001,
            value=1,
            is_write=True,
        ),
        raw_ref={"file": "modbus.log", "line": 10},
        raw={"raw_hex": "01030000"},
        tags=["ics", "test"],
    )


def sample_signal() -> Signal:
    now = datetime.now(UTC)
    return Signal(
        signal_id=new_id("sig"),
        ts=now,
        detector="rule",
        rule_id="R-OT-001",
        title="Unauthorized PLC Register Write",
        score=0.85,
        confidence=0.9,
        entities=[Entity(type=EntityType.ip, value="192.168.1.10")],
        evidence_event_ids=["evt_001"],
        techniques=[
            Technique(
                framework="ics",
                technique_id="T0855",
                name="Unauthorized Command Message",
                tactic="Impair Process Control",
            )
        ],
        explanation="Suspicious Modbus write detected",
        metadata={"zone": "level1"},
    )


def sample_incident() -> Incident:
    now = datetime.now(UTC)
    return Incident(
        incident_id=new_id("inc"),
        status="open",
        created_at=now,
        updated_at=now,
        first_signal_ts=now,
        first_meaningful_alert_ts=now,
        ttfma_seconds=12.5,
        score=0.88,
        severity=Severity.high,
        entities=[Entity(type=EntityType.ip, value="192.168.1.10")],
        signal_ids=["sig_001"],
        event_ids=["evt_001"],
        kill_chain_stages=["Initial Access", "Execution"],
        techniques=[
            Technique(
                framework="enterprise",
                technique_id="T1078",
                name="Valid Accounts",
                tactic="Initial Access",
            )
        ],
        decoy_touched=True,
        ot_touched=True,
        explanation=["Compromised credentials used to issue OT write"],
        summary="OT attack chain detected",
        summary_citations=["evt_001"],
        graph=IncidentGraph(
            nodes=[GraphNode(id="n1", type="ip", label="192.168.1.10")],
            edges=[
                GraphEdge(
                    source="n1",
                    target="n1",
                    label="traffic",
                    ts=now,
                    event_ids=["evt_001"],
                )
            ],
        ),
    )


def sample_guard() -> GuardDecision:
    now = datetime.now(UTC)
    return GuardDecision(
        decision_id=new_id("grd"),
        ts=now,
        incident_id="inc_001",
        action="block_modbus_write",
        target="192.168.1.10",
        decision="deny",
        reasons=["Critical OT controller safety policy"],
        rule_ids=["POL-OT-001"],
        asset_criticality="process_critical",
        requested_by="analyst_bob",
    )


def test_roundtrip_event():
    evt = sample_event()
    serialized = evt.model_dump_json()
    deserialized = Event.model_validate_json(serialized)
    assert deserialized == evt


def test_roundtrip_signal():
    sig = sample_signal()
    serialized = sig.model_dump_json()
    deserialized = Signal.model_validate_json(serialized)
    assert deserialized == sig


def test_roundtrip_incident():
    inc = sample_incident()
    serialized = inc.model_dump_json()
    deserialized = Incident.model_validate_json(serialized)
    assert deserialized == inc


def test_roundtrip_guard():
    grd = sample_guard()
    serialized = grd.model_dump_json()
    deserialized = GuardDecision.model_validate_json(serialized)
    assert deserialized == grd


def test_naive_datetime_rejected():
    naive_now = datetime(2026, 11, 7, 12, 0, 0)
    with pytest.raises(ValidationError) as exc_info:
        Event(
            event_id="evt_01",
            ts=naive_now,
            ingested_at=naive_now,
            source_tool=SourceTool.generic,
            domain=Domain.it,
            category="process",
            action="exec",
            outcome=Outcome.success,
            raw_ref={},
            raw={},
        )
    assert "Datetime must be timezone-aware UTC" in str(exc_info.value)


def test_extra_fields_rejected():
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        Event(
            event_id="evt_01",
            ts=now,
            ingested_at=now,
            source_tool=SourceTool.generic,
            domain=Domain.it,
            category="process",
            action="exec",
            outcome=Outcome.success,
            raw_ref={},
            raw={},
            unexpected_field="disallowed",
        )


def test_signal_empty_evidence_rejected():
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        Signal(
            signal_id="sig_01",
            ts=now,
            detector="rule",
            rule_id="R-01",
            title="Test",
            score=0.5,
            confidence=0.5,
            entities=[],
            evidence_event_ids=[],  # Min length 1 required
            techniques=[],
            explanation="Test signal",
        )


def test_score_outside_range_rejected():
    now = datetime.now(UTC)
    # Score > 1.0
    with pytest.raises(ValidationError):
        Signal(
            signal_id="sig_01",
            ts=now,
            detector="rule",
            rule_id="R-01",
            title="Test",
            score=1.5,
            confidence=0.5,
            entities=[],
            evidence_event_ids=["evt_01"],
            techniques=[],
            explanation="Test signal",
        )

    # Score < 0.0
    with pytest.raises(ValidationError):
        Signal(
            signal_id="sig_02",
            ts=now,
            detector="rule",
            rule_id="R-01",
            title="Test",
            score=-0.1,
            confidence=0.5,
            entities=[],
            evidence_event_ids=["evt_01"],
            techniques=[],
            explanation="Test signal",
        )
