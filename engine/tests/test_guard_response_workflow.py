"""Unit tests for SentinelX Response Safety Guard evaluation and approval workflow."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sentinelx.guard.evaluator import GuardEvaluator
from sentinelx.schemas.common import Entity, EntityType, Severity
from sentinelx.schemas.incident import Incident
from sentinelx.store.sqlite import (
    get_guard_decision_by_id,
    init_db,
    upsert_incident,
)


def test_guard_evaluates_policies_and_safety_risk():
    """Verify evaluator produces structured policy evaluations and safety risk."""
    evaluator = GuardEvaluator()

    manipulated_plc_state = {
        "flag": "manipulated",
        "tank_level": 92.5,
        "valve_open": False,
    }

    # Action: Isolate process-critical PLC host while manipulated -> MUST DENY
    dec_deny = evaluator.evaluate(
        action="isolate_host",
        target="plc-sim",
        incident_id="inc_test_001",
        plc_state=manipulated_plc_state,
    )

    assert dec_deny.decision == "deny"
    assert dec_deny.target_zone == "ot"
    assert dec_deny.safety_risk == "high_on_critical"
    assert dec_deny.approval_status == "not_required"  # Denied actions are not pending review

    # Verify policy evaluation breakdown
    assert len(dec_deny.policy_evaluations) > 0
    ot_001 = next(p for p in dec_deny.policy_evaluations if p.policy_id == "GUARD-OT-001")
    assert ot_001.result == "fail"
    assert "process_critical" in ot_001.explanation


def test_guard_needs_human_sets_pending_review():
    """Verify that needs_human decisions set approval_status to pending_review."""
    evaluator = GuardEvaluator()

    normal_plc_state = {
        "flag": "normal",
        "tank_level": 50.0,
        "valve_open": True,
    }

    dec = evaluator.evaluate(
        action="isolate_host",
        target="plc-sim",
        incident_id="inc_test_002",
        plc_state=normal_plc_state,
    )

    assert dec.decision == "needs_human"
    assert dec.approval_status == "pending_review"
    assert dec.approved_by is None
    assert dec.approved_at is None


def test_guard_allow_actions():
    """Verify safe IT containment actions are permitted and don't require human review."""
    evaluator = GuardEvaluator()

    dec = evaluator.evaluate(
        action="block_ip",
        target="10.10.1.5",
        incident_id="inc_test_003",
    )

    assert dec.decision == "allow"
    assert dec.target_zone == "it"
    assert dec.approval_status == "not_required"
    # No policy should fail
    assert all(p.result != "fail" for p in dec.policy_evaluations)


def test_human_approval_workflow_lifecycle():
    """Verify approval transitions pending_review to approved with audit fields."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_guard_lifecycle.db"
        conn = init_db(db_path)

        evaluator = GuardEvaluator(db=conn)

        # Generate a needs_human decision
        dec = evaluator.evaluate(
            action="isolate_host",
            target="plc-sim",
            incident_id="inc_001",
            plc_state={"flag": "normal", "tank_level": 50.0, "valve_open": True},
        )
        assert dec.approval_status == "pending_review"

        # Operator approves the decision
        approved = evaluator.approve_decision(
            decision_id=dec.decision_id,
            operator_name="lead_analyst_alice",
            notes="Authorized during scheduled maintenance window",
        )

        assert approved.approval_status == "approved"
        assert approved.approved_by == "lead_analyst_alice"
        assert approved.approval_notes == "Authorized during scheduled maintenance window"
        assert approved.approved_at is not None

        # Verify persisted state
        stored = get_guard_decision_by_id(conn, dec.decision_id)
        assert stored is not None
        assert stored.approval_status == "approved"
        assert stored.approved_by == "lead_analyst_alice"


def test_human_rejection_workflow():
    """Verify rejection transitions pending_review to rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_guard_reject.db"
        conn = init_db(db_path)

        evaluator = GuardEvaluator(db=conn)

        dec = evaluator.evaluate(
            action="isolate_host",
            target="plc-sim",
            incident_id="inc_001",
            plc_state={"flag": "normal", "tank_level": 50.0, "valve_open": True},
        )

        rejected = evaluator.reject_decision(
            decision_id=dec.decision_id,
            operator_name="lead_analyst_bob",
            notes="Rejected: operational shift active",
        )

        assert rejected.approval_status == "rejected"
        assert rejected.approved_by == "lead_analyst_bob"
        assert "Rejected" in rejected.approval_notes


def test_safety_invariant_cannot_approve_denied_decision():
    """CRITICAL SAFETY RULE:

    Human approval MUST NEVER override a safety DENY decision.
    Attempting to approve a DENY decision must raise ValueError.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_guard_safety.db"
        conn = init_db(db_path)

        evaluator = GuardEvaluator(db=conn)

        dec_denied = evaluator.evaluate(
            action="isolate_host",
            target="plc-sim",
            incident_id="inc_safety_test",
            plc_state={"flag": "manipulated", "tank_level": 95.0, "valve_open": False},
        )
        assert dec_denied.decision == "deny"

        # Attempting approval MUST fail
        with pytest.raises(
            ValueError, match="Human approval cannot override an explicit safety denial"
        ):
            evaluator.approve_decision(
                decision_id=dec_denied.decision_id,
                operator_name="rogue_operator",
                notes="Attempting override",
            )


def test_generate_incident_recommendations():
    """Verify recommendations are synthesized with Guard evaluations for an incident."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_recs.db"
        conn = init_db(db_path)

        now = datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)
        inc = Incident(
            incident_id="inc_rec_001",
            status="open",
            created_at=now,
            updated_at=now,
            first_signal_ts=now,
            score=0.9,
            severity=Severity.critical,
            entities=[
                Entity(type=EntityType.ip, value="10.10.1.5"),
                Entity(type=EntityType.host, value="jump-host"),
                Entity(type=EntityType.host, value="plc-sim"),
            ],
            signal_ids=["sig_001", "sig_002"],
            event_ids=["evt_001", "evt_002"],
            kill_chain_stages=["lateral_movement", "impact"],
            techniques=[],
            decoy_touched=False,
            ot_touched=True,
            novelty_only=False,
            explanation=["Attacker moving towards OT controller"],
        )
        upsert_incident(conn, inc)

        evaluator = GuardEvaluator(db=conn)
        recs = evaluator.generate_incident_recommendations("inc_rec_001")

        assert len(recs) >= 3
        # Should recommend blocking attacker IP (ALLOW)
        rec_block = next((r for r in recs if r.action == "block_ip"), None)
        assert rec_block is not None
        assert rec_block.decision.decision == "allow"

        # Should recommend isolating jump-host (ALLOW or NEEDS_HUMAN)
        rec_jh = next((r for r in recs if r.target == "jump-host"), None)
        assert rec_jh is not None

        # Should include plc-sim recommendation with Guard evaluation (NEEDS_HUMAN or DENY)
        rec_plc = next((r for r in recs if r.target == "plc-sim"), None)
        assert rec_plc is not None
        assert rec_plc.decision.decision in ("needs_human", "deny")


def test_unknown_target_cannot_be_automatically_permitted():
    """SAFETY INVARIANT 8: Unknown targets cannot be automatically permitted."""
    evaluator = GuardEvaluator()

    # Unknown hostname
    dec_unknown_host = evaluator.evaluate(
        action="isolate_host",
        target="unmapped-scada-gateway",
    )
    assert dec_unknown_host.decision == "needs_human"
    assert dec_unknown_host.target_zone == "unknown"
    assert dec_unknown_host.asset_criticality == "high"
    assert "GUARD-DEFAULT" in dec_unknown_host.rule_ids

    # Unknown IP outside inventory
    dec_unknown_ip = evaluator.evaluate(
        action="isolate_host",
        target="192.168.100.50",
    )
    assert dec_unknown_ip.decision == "needs_human"
    assert dec_unknown_ip.target_zone == "unknown"


def test_state_transition_conflicts():
    """AUDIT TRAIL INVARIANT: Repeated requests cannot create conflicting state transitions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_transitions.db"
        conn = init_db(db_path)
        evaluator = GuardEvaluator(db=conn)

        # 1. Needs human decision
        dec = evaluator.evaluate(
            action="isolate_host",
            target="plc-sim",
            incident_id="inc_trans_001",
            plc_state={"flag": "normal"},
        )
        assert dec.approval_status == "pending_review"

        # Approve once -> success
        evaluator.approve_decision(
            decision_id=dec.decision_id,
            operator_name="lead_operator",
            notes="Initial review completed",
        )

        # Cannot approve an already approved decision
        with pytest.raises(ValueError, match="already approved"):
            evaluator.approve_decision(
                decision_id=dec.decision_id,
                operator_name="second_operator",
                notes="Duplicate approval attempt",
            )

        # Cannot reject an approved decision
        with pytest.raises(ValueError, match="already approved"):
            evaluator.reject_decision(
                decision_id=dec.decision_id,
                operator_name="second_operator",
            )

        # 2. Another decision for rejection test
        dec2 = evaluator.evaluate(
            action="isolate_host",
            target="plc-sim",
            incident_id="inc_trans_002",
            plc_state={"flag": "normal"},
        )
        evaluator.reject_decision(
            decision_id=dec2.decision_id,
            operator_name="shift_supervisor",
            notes="Active operational shift",
        )

        # Cannot reject an already rejected decision
        with pytest.raises(ValueError, match="already.*reject"):
            evaluator.reject_decision(
                decision_id=dec2.decision_id,
                operator_name="supervisor_2",
            )

        # Cannot approve an already rejected decision
        with pytest.raises(ValueError, match="already.*reject"):
            evaluator.approve_decision(
                decision_id=dec2.decision_id,
                operator_name="supervisor_2",
            )

        # 3. Cannot approve an ALLOW decision (redundant)
        dec_allow = evaluator.evaluate(
            action="block_ip",
            target="10.10.1.5",
        )
        with pytest.raises(ValueError, match="Redundant Approval"):
            evaluator.approve_decision(
                decision_id=dec_allow.decision_id,
                operator_name="operator",
            )


def test_guard_decision_immutability_and_persistence_restart():
    """AUDIT TRAIL INVARIANT: Full persistence and immutability across backend restart."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_restart.db"

        # Session 1: Create and approve decision
        conn1 = init_db(db_path)
        evaluator1 = GuardEvaluator(db=conn1)
        dec = evaluator1.evaluate(
            action="isolate_host",
            target="plc-sim",
            incident_id="inc_restart_001",
            plc_state={"flag": "normal"},
        )
        approved = evaluator1.approve_decision(
            decision_id=dec.decision_id,
            operator_name="chief_engineer_dave",
            notes="Authorized during plant turnaround window",
        )
        conn1.close()  # Simulate backend termination

        # Session 2: Fresh connection to same database
        conn2 = init_db(db_path)
        reloaded = get_guard_decision_by_id(conn2, dec.decision_id)
        assert reloaded is not None

        # Verify original decision attributes were preserved immutably
        assert reloaded.decision_id == dec.decision_id
        assert reloaded.action == "isolate_host"
        assert reloaded.target == "plc-sim"
        assert reloaded.decision == "needs_human"
        assert reloaded.target_zone == "ot"
        assert reloaded.asset_criticality == "process_critical"
        assert reloaded.rule_ids == ["GUARD-OT-002"]
        assert len(reloaded.policy_evaluations) == len(dec.policy_evaluations)

        # Verify audit approval fields are faithfully persisted
        assert reloaded.approval_status == "approved"
        assert reloaded.approved_by == "chief_engineer_dave"
        assert reloaded.approval_notes == "Authorized during plant turnaround window"
        assert reloaded.approved_at is not None
        assert reloaded.approved_at == approved.approved_at
        conn2.close()


def test_all_five_guard_actions_coverage():
    """SAFETY INVARIANT AUDIT: Complete coverage across all 5 response action types.

    Proves:
    1. isolate_host:
       - Unknown target -> needs_human
       - Process-critical OT asset mid-manipulation -> DENY
       - Process-critical OT asset normal baseline -> needs_human
    2. block_ip:
       - Attacker / external IP -> ALLOW
       - Process-critical OT asset -> needs_human
    3. block_modbus_write:
       - Unknown target -> needs_human
       - Process-critical OT asset mid-manipulation -> DENY
       - Process-critical OT asset normal baseline -> needs_human
    4. kill_process:
       - Non-critical IT host -> ALLOW
       - Unknown target -> needs_human
       - Process-critical OT asset -> needs_human
    5. disable_account:
       - User account -> ALLOW
    """
    evaluator = GuardEvaluator()

    # 1. isolate_host
    assert evaluator.evaluate("isolate_host", "mystery-box").decision == "needs_human"
    assert (
        evaluator.evaluate("isolate_host", "plc-sim", plc_state={"flag": "manipulated"}).decision
        == "deny"
    )
    assert (
        evaluator.evaluate("isolate_host", "plc-sim", plc_state={"flag": "normal"}).decision
        == "needs_human"
    )

    # 2. block_ip
    assert evaluator.evaluate("block_ip", "10.10.1.5").decision == "allow"
    assert evaluator.evaluate("block_ip", "198.51.100.25").decision == "allow"
    assert evaluator.evaluate("block_ip", "plc-sim").decision == "needs_human"
    assert evaluator.evaluate("block_ip", "10.10.3.20").decision == "needs_human"

    # 3. block_modbus_write
    assert evaluator.evaluate("block_modbus_write", "mystery-box").decision == "needs_human"
    assert (
        evaluator.evaluate(
            "block_modbus_write", "plc-sim", plc_state={"flag": "manipulated"}
        ).decision
        == "deny"
    )
    assert (
        evaluator.evaluate("block_modbus_write", "plc-sim", plc_state={"flag": "normal"}).decision
        == "needs_human"
    )

    # 4. kill_process
    assert evaluator.evaluate("kill_process", "10.10.1.20").decision == "allow"
    assert evaluator.evaluate("kill_process", "mystery-box").decision == "needs_human"
    assert evaluator.evaluate("kill_process", "plc-sim").decision == "needs_human"

    # 5. disable_account
    assert evaluator.evaluate("disable_account", "svc_backup").decision == "allow"
