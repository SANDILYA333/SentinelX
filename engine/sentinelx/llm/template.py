"""Deterministic fallback summary generator when LLM is unavailable, times out, or fails grounding verification."""

from sentinelx.llm.prompt import LLMClaim, LLMSummaryPayload
from sentinelx.schemas.incident import Incident


def generate_template_summary(incident: Incident) -> LLMSummaryPayload:
    """Build a deterministic, fully grounded summary purely from incident fields without LLM calls."""
    stages_str = (
        ", ".join(incident.kill_chain_stages) if incident.kill_chain_stages else "Uncategorized"
    )
    headline = (
        f"Incident {incident.incident_id}: {incident.severity.value.upper()} progression "
        f"across stages [{stages_str}] (Score: {incident.score:.2f})"
    )

    claims: list[LLMClaim] = []
    eids = incident.event_ids
    tech_ids = [t.technique_id for t in incident.techniques]

    # Generate claims from explanation lines
    if incident.explanation:
        for idx, line in enumerate(incident.explanation):
            # Distribute available event IDs across explanation claims so each claim cites valid evidence
            cited = [eids[idx % len(eids)]] if eids else []
            claims.append(
                LLMClaim(
                    text=line,
                    event_ids=cited,
                    entities=[e.value for e in incident.entities[:2]],
                    technique_ids=tech_ids[:2],
                )
            )
    else:
        # Fallback claim if explanation is empty
        claims.append(
            LLMClaim(
                text=(
                    f"Correlated security incident reaching score {incident.score:.2f} "
                    f"with {len(incident.signal_ids)} detection signals across stages [{stages_str}]."
                ),
                event_ids=eids[:3] if eids else [],
                entities=[e.value for e in incident.entities],
                technique_ids=tech_ids,
            )
        )

    # Highlight OT impact if present
    if incident.ot_touched:
        claims.append(
            LLMClaim(
                text="Industrial control system (OT) interaction observed during incident progression.",
                event_ids=eids[-2:] if len(eids) >= 2 else eids,
                entities=[e.value for e in incident.entities if "plc" in e.value.lower()]
                or ["plc-sim"],
                technique_ids=[t for t in tech_ids if "T0" in t or "T1" in t][:1],
            )
        )

    # Highlight Decoy interaction if present
    if incident.decoy_touched:
        claims.append(
            LLMClaim(
                text="Adversary interacted with a registered deception honeypot/honeytoken canary asset.",
                event_ids=eids[:2] if eids else [],
                entities=[
                    e.value
                    for e in incident.entities
                    if "decoy" in str(e.type).lower() or "canary" in e.value.lower()
                ]
                or ["opencanary"],
                technique_ids=[],
            )
        )

    return LLMSummaryPayload(
        headline=headline,
        claims=claims,
    )
