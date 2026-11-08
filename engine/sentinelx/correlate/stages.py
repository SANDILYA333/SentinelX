"""Kill-chain stage taxonomy definitions and classification."""

from sentinelx.schemas.signal import Signal

STAGE_ORDER: list[str] = [
    "initial_access",
    "discovery",
    "credential_access",
    "lateral_movement",
    "ot_impact",
]

STAGE_BASE_WEIGHTS: dict[str, float] = {
    "initial_access": 0.20,
    "discovery": 0.15,
    "credential_access": 0.25,
    "lateral_movement": 0.25,
    "ot_impact": 0.30,
}


def classify_signal_stage(signal: Signal) -> str:
    """Classify a signal into the 5-stage SentinelX kill-chain taxonomy."""
    rule_id = (signal.rule_id or "").upper()

    if rule_id in ("RULE-AUTH-001", "RULE-SHELL-001"):
        return "initial_access"
    if rule_id in ("GRAPH-SCAN-001",):
        return "discovery"
    if rule_id in ("RULE-CRED-001", "RULE-DECOY-001"):
        return "credential_access"
    if rule_id in ("RULE-NET-001", "GRAPH-PATH-001", "GRAPH-EDGE-001"):
        return "lateral_movement"
    if rule_id in ("RULE-OT-001",):
        return "ot_impact"

    if signal.detector == "deception":
        return "credential_access"

    # Evaluate MITRE techniques
    for tech in signal.techniques:
        tactic_slug = tech.tactic.lower().replace("-", "_").replace(" ", "_")
        if "initial_access" in tactic_slug:
            return "initial_access"
        if "discovery" in tactic_slug:
            return "discovery"
        if "credential" in tactic_slug:
            return "credential_access"
        if "lateral" in tactic_slug:
            return "lateral_movement"
        if "impact" in tactic_slug or "inhibit_response_function" in tactic_slug:
            return "ot_impact"

    if signal.detector in ("anomaly", "baseline", "graph"):
        return "discovery"

    return "discovery"
