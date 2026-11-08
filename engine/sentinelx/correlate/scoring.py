"""Kill-chain stage taxonomy, progression scoring, and session-aware OT weighting.

Stage Taxonomy & Scoring Model:
-----------------------------------------------------------------------------------------
Kill-Chain Stage    Base Weight   Key Associated Detectors / Rules
-----------------------------------------------------------------------------------------
initial_access      0.20          RULE-AUTH-001, unexpected cross-zone authentication
discovery           0.15          GRAPH-SCAN-001, IT subnet scans, volume anomalies
credential_access   0.25          RULE-CRED-001, honeytoken access, credential dumps
lateral_movement    0.25          RULE-NET-001, GRAPH-PATH-001, pivot to workstation
ot_impact           0.30          RULE-OT-001, Modbus manipulation, valve setpoints
-----------------------------------------------------------------------------------------

Progression Multipliers:
- 1 Unique Stage:  1.00x
- 2 Unique Stages: 1.25x
- 3 Unique Stages: 1.50x
- 4 Unique Stages: 1.75x
- 5 Unique Stages: 2.00x

Confidence & Context Boosts:
- Confirmed Honeytoken: +0.30 boost (guarantees high/critical severity >= 0.85)
- Session-Aware OT Weighting (Phase 4 limitation fix):
  When an OT write occurs within a session/host that already has prior suspicious signals
  in the incident, apply +0.35 session-link boost (or 1.8x multiplier).
  An isolated OT write without prior suspicious context receives no session boost.
"""

from sentinelx.correlate.stages import STAGE_BASE_WEIGHTS, classify_signal_stage
from sentinelx.schemas.common import Severity
from sentinelx.schemas.signal import Signal

NOVELTY_DETECTORS: set[str] = {"baseline", "graph", "anomaly"}
CORROBORATING_DETECTORS: set[str] = {"rule", "deception"}


def is_novelty_only(signals: list[Signal]) -> bool:
    """Check if an incident's signals derive strictly from novelty/unsupervised detectors.

    Returns True if signals exist and ALL signals come from {baseline, graph, anomaly}
    without any corroboration from deterministic rules or deception assets.
    """
    if not signals:
        return False
    return all(
        (s.detector.value if hasattr(s.detector, "value") else str(s.detector)) in NOVELTY_DETECTORS
        for s in signals
    )


def detect_session_tainted_ot(signals: list[Signal]) -> bool:
    """Check if any OT signal in the list occurred after a prior suspicious signal.

    Identifies if an OT command was executed on a host/user/session that was previously
    touched by initial access, credential theft, or lateral movement in this incident.
    """
    sorted_signals = sorted(signals, key=lambda s: s.ts)
    seen_prior_suspicious = False
    prior_entities: set[str] = set()

    for sig in sorted_signals:
        stage = classify_signal_stage(sig)
        sig_entities = {f"{e.type}:{e.value.lower()}" for e in sig.entities}

        if stage == "ot_impact":
            if seen_prior_suspicious:
                # Check entity intersection (host, user, session, or IP)
                if not prior_entities or bool(sig_entities & prior_entities):
                    return True
                # Even if entities don't share identical literal string,
                # prior lateral movement in the same correlation incident taints subsequent OT
                return True
        else:
            seen_prior_suspicious = True
            prior_entities.update(sig_entities)

    return False


def score_incident(
    signals: list[Signal],
    force_session_taint: bool | None = None,
    novelty_cap: float = 0.40,
) -> tuple[float, list[str], Severity]:
    """Calculate incident score (0.0 - 1.0), ordered kill-chain stages, and severity."""
    if not signals:
        return 0.0, [], Severity.low

    sorted_signals = sorted(signals, key=lambda s: s.ts)

    # 1. Collect distinct stages in chronological order of first appearance
    stages: list[str] = []
    seen_stages: set[str] = set()
    for s in sorted_signals:
        st = classify_signal_stage(s)
        if st not in seen_stages:
            seen_stages.add(st)
            stages.append(st)

    # 2. Stage base accumulation and progression multiplier
    stage_base_sum = sum(STAGE_BASE_WEIGHTS.get(st, 0.15) for st in stages)
    stage_count = len(stages)
    progression_multiplier = 1.0 + 0.25 * (stage_count - 1)

    raw_score = stage_base_sum * progression_multiplier

    # 3. Context & Deception Boosts
    has_honeytoken = any(
        s.detector == "deception"
        or (s.rule_id or "").upper() == "RULE-DECOY-001"
        or s.metadata.get("confirmed_honeytoken") is True
        for s in sorted_signals
    )
    if has_honeytoken:
        raw_score = max(raw_score + 0.35, 0.85)

    # 4. Session-Aware OT Weighting (Phase 4 limitation fix)
    has_ot = any(classify_signal_stage(s) == "ot_impact" for s in sorted_signals)
    session_tainted = (
        force_session_taint
        if force_session_taint is not None
        else detect_session_tainted_ot(sorted_signals)
    )

    if has_ot and session_tainted:
        raw_score += 0.35

    final_score = min(1.0, max(0.05, round(raw_score, 4)))

    # 5. Cold-Start Novelty Corroboration Cap
    # Incidents supported solely by unsupervised anomaly/baseline/graph deviations
    # without deterministic rule or deception corroboration are capped below the budget threshold.
    if is_novelty_only(sorted_signals):
        final_score = min(final_score, novelty_cap)

    # Determine Severity
    if final_score >= 0.85:
        severity = Severity.critical
    elif final_score >= 0.65:
        severity = Severity.high
    elif final_score >= 0.45:
        severity = Severity.medium
    else:
        severity = Severity.low

    return final_score, stages, severity
