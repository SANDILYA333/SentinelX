#!/usr/bin/env python3
"""SentinelX Response Safety Guard Policy Evaluation Suite.

Evaluates proposed containment actions across the entire GuardAction catalog,
testing varied target asset criticalities and PLC operational states.
Generates the comprehensive Guard Policy Decision Table and validates DoD criteria:
1. Denied mid-process with safer alternative explicitly suggested.
2. Sensibly allowed actions on IT assets and accounts.
"""

import sys
from pathlib import Path

# Add engine to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.guard.evaluator import GuardEvaluator  # noqa: E402
from sentinelx.schemas.guard import GuardAction  # noqa: E402


def run_guard_evaluation():
    evaluator = GuardEvaluator()

    test_cases: list[dict] = [
        # Process Critical Mid-Manipulation (Deny with alternative suggested)
        {
            "action": "isolate_host",
            "target": "plc-sim",
            "plc_state": {"flag": "manipulated", "tank_level": 88.0},
            "desc": "Isolate PLC controller while mid-manipulation",
            "expected_decision": "deny",
            "expected_rule": "GUARD-OT-001",
        },
        {
            "action": "block_modbus_write",
            "target": "plc-sim",
            "plc_state": {"flag": "emergency_stop", "tank_level": 94.0},
            "desc": "Block Modbus writes during emergency stop state",
            "expected_decision": "deny",
            "expected_rule": "GUARD-OT-001",
        },
        # Process Critical Baseline State (Needs Human Operator Confirmation)
        {
            "action": "isolate_host",
            "target": "plc-sim",
            "plc_state": {"flag": "normal", "tank_level": 50.0},
            "desc": "Isolate PLC controller during normal operation",
            "expected_decision": "needs_human",
            "expected_rule": "GUARD-OT-002",
        },
        {
            "action": "block_modbus_write",
            "target": "plc-sim",
            "plc_state": {"flag": "normal", "tank_level": 50.0},
            "desc": "Filter Modbus writes during normal operation",
            "expected_decision": "needs_human",
            "expected_rule": "GUARD-OT-003",
        },
        # Safe IT Containment (Allowed)
        {
            "action": "block_ip",
            "target": "10.10.1.5",
            "plc_state": {"flag": "normal"},
            "desc": "Block external attacker IP at firewall boundary",
            "expected_decision": "allow",
            "expected_rule": "GUARD-IT-001",
        },
        {
            "action": "isolate_host",
            "target": "attacker",
            "plc_state": {"flag": "normal"},
            "desc": "Isolate untrusted attacker machine",
            "expected_decision": "allow",
            "expected_rule": "GUARD-IT-001",
        },
        {
            "action": "isolate_host",
            "target": "file-srv",
            "plc_state": {"flag": "normal"},
            "desc": "Isolate compromised medium-criticality file server",
            "expected_decision": "allow",
            "expected_rule": "GUARD-IT-001",
        },
        {
            "action": "disable_account",
            "target": "svc_backup",
            "plc_state": {"flag": "normal"},
            "desc": "Revoke compromised service account credentials",
            "expected_decision": "allow",
            "expected_rule": "GUARD-AUTH-001",
        },
        {
            "action": "disable_account",
            "target": "svc_dbadmin",
            "plc_state": {"flag": "normal"},
            "desc": "Revoke honeytoken decoy credential",
            "expected_decision": "allow",
            "expected_rule": "GUARD-AUTH-001",
        },
        {
            "action": "kill_process",
            "target": "file-srv",
            "plc_state": {"flag": "normal"},
            "desc": "Terminate suspicious process on file server",
            "expected_decision": "allow",
            "expected_rule": "GUARD-PROC-001",
        },
        # Ambiguous / High-Risk IT Escalation (Needs Human)
        {
            "action": "isolate_host",
            "target": "jump-host",
            "plc_state": {"flag": "normal"},
            "desc": "Isolate enterprise core jump host (high criticality)",
            "expected_decision": "needs_human",
            "expected_rule": "GUARD-DEFAULT",
        },
    ]

    print("\n" + "=" * 125)
    print("RESPONSE SAFETY GUARD POLICY EVALUATION TABLE")
    print("=" * 125)
    header = (
        f"{'Action':<19} | {'Target':<12} | {'Criticality':<16} | "
        f"{'Decision':<11} | {'Rule ID':<13} | {'Reason Summary & Alternative'}"
    )
    print(header)
    print("-" * 125)

    all_passed = True

    for tc in test_cases:
        action: GuardAction = tc["action"]
        target = tc["target"]
        plc_state = tc["plc_state"]

        decision = evaluator.evaluate(
            action=action,
            target=target,
            incident_id="inc_eval_001",
            plc_state=plc_state,
        )

        crit_str = decision.asset_criticality or "unknown"
        rule_str = decision.rule_ids[0] if decision.rule_ids else "NONE"
        reason_first = decision.reasons[0] if decision.reasons else ""
        if len(decision.reasons) > 2 and "alternative" in decision.reasons[2].lower():
            reason_summary = f"{reason_first} | {decision.reasons[2]}"
        else:
            reason_summary = reason_first

        # Check expectation
        passed = (decision.decision == tc["expected_decision"]) and (
            tc["expected_rule"] in decision.rule_ids
        )
        if not passed:
            all_passed = False

        status_marker = " " if passed else "X"
        row_str = (
            f"{status_marker}{action:<18} | {target:<12} | {crit_str:<16} | "
            f"{decision.decision.upper():<11} | {rule_str:<13} | {reason_summary}"
        )
        print(row_str)

    print("=" * 125)

    if not all_passed:
        print("\nERROR: One or more guard evaluation test cases failed expectations!")
        sys.exit(1)
    else:
        print("\nALL GUARD POLICY EVALUATION CHECKS PASSED SUCCESSFULLY!\n")


if __name__ == "__main__":
    run_guard_evaluation()
