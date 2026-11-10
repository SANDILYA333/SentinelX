"""Evidence-grounded explanations for Response Safety Guard decisions and deception events.

Enforces strict safety boundaries:
- Explanations are strictly advisory text.
- Never overrides or mutates Guard decisions (ALLOW, DENY, NEEDS_HUMAN).
- Never executes actions or bypasses safety policies.
- Uses deterministic templates with optional Gemini enrichment if configured.
"""

from typing import Any

from sentinelx.schemas.guard import GuardDecision


def explain_guard_decision(
    decision: GuardDecision, target_metadata: dict[str, Any] | None = None
) -> str:
    """Generate a clear, human-readable safety explanation for a Guard decision."""
    action = decision.action
    target = decision.target
    outcome = decision.decision
    criticality = decision.asset_criticality or "unknown"
    reasons = decision.reasons

    if outcome == "deny":
        explanation = (
            f"SAFETY ALERT: Containment action '{action}' on target '{target}' has been STRICTLY PROHIBITED (DENY) "
            f"by safety policy '{decision.rule_ids[0]}'. "
            f"Target criticality is '{criticality}'. "
            f"Executing this action automatically poses high risk to plant physical operations: {reasons[0]}"
        )
        for r in reasons:
            if "safer alternative" in r.lower():
                explanation += f"\n\nRecommended Safe Alternative: {r}"
        return explanation

    if outcome == "needs_human":
        explanation = (
            f"HUMAN INTERVENTION REQUIRED: Automated execution of '{action}' on '{target}' requires explicit SOC / "
            f"OT operator authorization. "
            f"Target criticality is '{criticality}'. "
            f"Policy rationale: {reasons[0]} "
            "Please verify physical process impact and coordinate with plant operations before approving."
        )
        return explanation

    # allow
    explanation = (
        f"POLICY PERMITTED: Action '{action}' targeting '{target}' is permitted (ALLOW) under policy '{decision.rule_ids[0]}'. "
        f"Asset criticality is '{criticality}' with no direct physical actuation dependencies. "
        "Note: Permission under policy indicates safety compliance, not automated execution."
    )
    return explanation
