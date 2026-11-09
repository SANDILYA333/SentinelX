"""Deterministic Python verifier for LLM summary claims against incident evidence.

IMPORTANT: This verifier strictly validates structural grounding of event IDs,
entities, IP addresses, known hostnames, and numbers against observed telemetry fields.
It does NOT perform natural-language semantic entailment or verify narrative truthfulness.
"""

import re
from typing import Any

from sentinelx.llm.prompt import LLMClaim, LLMSummaryPayload
from sentinelx.normalize.assets import get_assets
from sentinelx.schemas.event import Event
from sentinelx.schemas.incident import Incident

RE_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
RE_NUMBERS = re.compile(r"\b\d+\b")


class VerificationResult:
    """Detailed result of verifying claims against incident evidence."""

    def __init__(
        self,
        headline: str,
        verified_claims: list[LLMClaim],
        dropped_claims: list[dict[str, Any]],
        total_count: int,
        verified_count: int,
        dropped_count: int,
        passed_ratio_check: bool,
    ):
        self.headline = headline
        self.verified_claims = verified_claims
        self.dropped_claims = dropped_claims
        self.total_count = total_count
        self.verified_count = verified_count
        self.dropped_count = dropped_count
        self.passed_ratio_check = passed_ratio_check

    @property
    def is_valid(self) -> bool:
        """True if >=50% of claims verified and at least one verified claim exists."""
        return self.passed_ratio_check and self.verified_count > 0


def _extract_all_numbers(text_or_obj: Any) -> set[str]:
    """Recursively or string-based extract all numeric digit tokens."""
    return set(RE_NUMBERS.findall(str(text_or_obj)))


def verify_claim(
    claim: LLMClaim,
    incident: Incident,
    events_by_id: dict[str, Event],
    known_hosts: set[str],
) -> tuple[bool, str | None]:
    """Verify a single claim against the 4 structural grounding rules (V1-V4).

    Returns (is_valid, failure_reason).
    """
    # (V1) Must cite at least one event_id, and all cited IDs must be in this incident
    if not claim.event_ids:
        return False, "V1_FAILED: Claim does not cite any event_ids"

    incident_eids = set(incident.event_ids)
    for eid in claim.event_ids:
        if eid not in incident_eids:
            return False, f"V1_FAILED: Cited event_id '{eid}' is not in incident evidence set"
        if eid not in events_by_id:
            return False, f"V1_FAILED: Cited event_id '{eid}' was not provided in telemetry lookup"

    cited_events = [events_by_id[eid] for eid in claim.event_ids]

    # (V2) Each entity string in claim.entities must appear in at least one cited event's fields
    for entity in claim.entities:
        ent_str = entity.strip().lower()
        if not ent_str:
            continue
        found = False
        for ev in cited_events:
            ev_fields = [
                ev.host,
                ev.user,
                ev.src_ip,
                ev.dst_ip,
                ev.process,
                ev.action,
            ]
            if any(f and ent_str in f.lower() for f in ev_fields):
                found = True
                break
            if isinstance(ev.raw, dict) and ent_str in str(ev.raw).lower():
                found = True
                break
        if not found:
            return (
                False,
                f"V2_FAILED: Entity '{entity}' not grounded in cited events {claim.event_ids}",
            )

    # (V3) technique_ids must be a subset of the incident's correlated techniques
    incident_techs = {t.technique_id.upper() for t in incident.techniques}
    for tid in claim.technique_ids:
        if tid.upper() not in incident_techs:
            return (
                False,
                f"V3_FAILED: Technique '{tid}' is not present in incident techniques {sorted(incident_techs)}",
            )

    # (V4) Grounding of IPv4 addresses, known hostnames, and numbers in claim text
    text = claim.text

    # (V4-a) IPv4 addresses in text must be present in cited events
    text_ips = set(RE_IPV4.findall(text))
    cited_ips: set[str] = set()
    for ev in cited_events:
        if ev.src_ip:
            cited_ips.add(ev.src_ip)
        if ev.dst_ip:
            cited_ips.add(ev.dst_ip)
        if isinstance(ev.raw, dict):
            cited_ips.update(RE_IPV4.findall(str(ev.raw)))

    for ip in text_ips:
        if ip not in cited_ips:
            return (
                False,
                f"V4_FAILED: IPv4 address '{ip}' in claim text not present in cited events",
            )

    # (V4-b) Known asset hostnames in text must appear in cited events
    for host in known_hosts:
        # Check whole-word presence
        if re.search(r"\b" + re.escape(host) + r"\b", text, re.IGNORECASE):
            host_in_events = False
            for ev in cited_events:
                if ev.host and host.lower() == ev.host.lower():
                    host_in_events = True
                    break
                if isinstance(ev.raw, dict) and host.lower() in str(ev.raw).lower():
                    host_in_events = True
                    break
            if not host_in_events:
                return (
                    False,
                    f"V4_FAILED: Known host '{host}' in claim text not present in cited events",
                )

    # (V4-c) Numbers in claim text must appear in cited events or incident metadata
    allowed_numbers: set[str] = set()
    for ev in cited_events:
        allowed_numbers.update(_extract_all_numbers(ev.model_dump()))
        if isinstance(ev.raw, dict):
            allowed_numbers.update(_extract_all_numbers(ev.raw))

    # Also allow numbers from incident metadata (e.g. stage indices, scores, technique IDs)
    allowed_numbers.update(_extract_all_numbers(incident.model_dump()))

    text_numbers = set(RE_NUMBERS.findall(text))
    for num in text_numbers:
        if num not in allowed_numbers:
            return (
                False,
                f"V4_FAILED: Number '{num}' in claim text not found in cited events or incident fields",
            )

    return True, None


def verify_summary(
    payload: LLMSummaryPayload,
    incident: Incident,
    events: list[Event],
) -> VerificationResult:
    """Verify all claims in an LLM summary payload against incident evidence.

    Unverified claims are dropped. If <50% of claims verify, result is marked invalid.
    """
    events_by_id = {e.event_id: e for e in events}

    assets = get_assets()
    known_hosts = {h.name.lower() for h in assets.hosts}

    verified_claims: list[LLMClaim] = []
    dropped_claims: list[dict[str, Any]] = []

    for idx, claim in enumerate(payload.claims):
        passed, reason = verify_claim(claim, incident, events_by_id, known_hosts)
        if passed:
            verified_claims.append(claim)
        else:
            dropped_claims.append(
                {
                    "claim_index": idx,
                    "text": claim.text,
                    "event_ids": claim.event_ids,
                    "reason": reason,
                }
            )

    total_count = len(payload.claims)
    verified_count = len(verified_claims)
    dropped_count = len(dropped_claims)

    passed_ratio_check = total_count > 0 and (verified_count / total_count >= 0.50)

    return VerificationResult(
        headline=payload.headline,
        verified_claims=verified_claims,
        dropped_claims=dropped_claims,
        total_count=total_count,
        verified_count=verified_count,
        dropped_count=dropped_count,
        passed_ratio_check=passed_ratio_check,
    )
