"""Unit tests for SentinelX Response Safety Guard evaluator and policy enforcement."""

import tempfile
from pathlib import Path

from sentinelx.guard.evaluator import GuardEvaluator
from sentinelx.store.sqlite import init_db, list_guard_decisions


def test_guard_denied_mid_process_with_alternative():
    """THE DEMO MOMENT:

    Proves that requesting isolate_host or block_modbus_write against plc-sim
    WHILE the PLC is mid-manipulation (flag != normal) is DENIED with a clear reason,
    and that the guard offers/suggests a safer alternative action in its reasons.
    """
    evaluator = GuardEvaluator()

    # PLC is mid-manipulation
    manipulated_plc_state = {
        "flag": "manipulated",
        "tank_level": 92.5,
        "valve_open": False,
    }

    # Action 1: Isolate process-critical PLC host while manipulated
    dec_isolate = evaluator.evaluate(
        action="isolate_host",
        target="plc-sim",
        incident_id="inc_test_001",
        plc_state=manipulated_plc_state,
    )

    assert dec_isolate.decision == "deny"
    assert "GUARD-OT-001" in dec_isolate.rule_ids
    assert dec_isolate.asset_criticality == "process_critical"
    # Verify reason names safety risk AND explicitly suggests a safer alternative
    reasons_text = " ".join(dec_isolate.reasons)
    assert "process_critical" in reasons_text
    assert "Safer alternative" in reasons_text
    assert "10.10.1.5" in reasons_text or "eng-ws" in reasons_text or "jump-host" in reasons_text

    # Action 2: Block Modbus write against plc-sim while manipulated
    dec_block_ot = evaluator.evaluate(
        action="block_modbus_write",
        target="plc-sim",
        incident_id="inc_test_001",
        plc_state=manipulated_plc_state,
    )
    assert dec_block_ot.decision == "deny"
    assert "GUARD-OT-001" in dec_block_ot.rule_ids


def test_guard_sensibly_allowed_actions():
    """Verify safe and correct actions are sensibly ALLOWED:

    - Isolate non-critical IT host / attacker
    - Block IP on attacker IP 10.10.1.5
    - Disable compromised user account (svc_backup)
    """
    evaluator = GuardEvaluator()

    # 1. Block attacker IP
    dec_block_ip = evaluator.evaluate(
        action="block_ip",
        target="10.10.1.5",
        incident_id="inc_test_001",
    )
    assert dec_block_ip.decision == "allow"
    assert dec_block_ip.asset_criticality == "low"
    assert "GUARD-IT-001" in dec_block_ip.rule_ids or "GUARD-IT-002" in dec_block_ip.rule_ids

    # 2. Disable compromised user account
    dec_disable_user = evaluator.evaluate(
        action="disable_account",
        target="svc_backup",
        incident_id="inc_test_001",
    )
    assert dec_disable_user.decision == "allow"
    assert "GUARD-AUTH-001" in dec_disable_user.rule_ids

    # 3. Kill process on IT host
    dec_kill_proc = evaluator.evaluate(
        action="kill_process",
        target="10.10.1.20",  # file-srv
        incident_id="inc_test_001",
    )
    assert dec_kill_proc.decision == "allow"
    assert "GUARD-PROC-001" in dec_kill_proc.rule_ids


def test_guard_critical_isolation_during_normal_state_needs_human():
    """Verify that isolating a process-critical asset even during normal operational baseline requires human confirmation."""
    evaluator = GuardEvaluator()

    normal_plc_state = {
        "flag": "normal",
        "tank_level": 50.0,
        "valve_open": True,
    }

    dec = evaluator.evaluate(
        action="isolate_host",
        target="plc-sim",
        incident_id="inc_test_001",
        plc_state=normal_plc_state,
    )
    assert dec.decision == "needs_human"
    assert "GUARD-OT-002" in dec.rule_ids


def test_guard_decision_persistence():
    """Verify that guard decisions are persisted to SQLite."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        conn = init_db(db_path)

        evaluator = GuardEvaluator(db=conn)
        dec = evaluator.evaluate(
            action="block_ip",
            target="10.10.1.5",
            incident_id="inc_persist_001",
        )

        rows = list_guard_decisions(conn)
        assert len(rows) == 1
        assert rows[0].decision_id == dec.decision_id
        assert rows[0].target == "10.10.1.5"
        assert rows[0].decision == "allow"
