"""Orchestrator for incident summarization with caching, verification, and template fallback."""

import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timezone

from sentinelx.llm.client import GeminiClient, LLMClient
from sentinelx.llm.evidence import build_evidence_packet
from sentinelx.llm.prompt import SYSTEM_INSTRUCTION, LLMSummaryPayload, build_user_prompt
from sentinelx.llm.template import generate_template_summary
from sentinelx.llm.verifier import verify_summary
from sentinelx.schemas.api_models import IncidentSummaryResponse, SummaryClaim
from sentinelx.schemas.event import Event
from sentinelx.schemas.incident import Incident
from sentinelx.store.sqlite import (
    get_incident_summary,
    upsert_incident,
    upsert_incident_summary,
)

logger = logging.getLogger("sentinelx.llm.summarizer")


def compute_evidence_hash(incident: Incident) -> str:
    """Compute deterministic SHA-256 evidence hash for incident state."""
    sorted_eids = sorted(incident.event_ids)
    raw = f"{incident.incident_id}|{sorted_eids}|{incident.score:.4f}|{incident.updated_at.isoformat()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def summarize_incident(
    incident: Incident,
    events: list[Event],
    db: sqlite3.Connection | None = None,
    client: LLMClient | None = None,
    refresh: bool = False,
    model: str | None = None,
    timeout: float = 12.0,
) -> IncidentSummaryResponse:
    """Generate or retrieve a verified analyst summary for an incident.

    Safety Guarantee:
    1. The LLM output is strictly advisory text. It NEVER mutates or influences incident.score,
       incident.severity, incident.status, budget thresholds, or response safety guard decisions.
    2. All claims are verified against incident evidence in pure Python.
    3. If verification fails (<50% verified), LLM call times out (8s), or fails, deterministic
       template fallback is applied.
    """
    evidence_hash = compute_evidence_hash(incident)

    # 1. Check sidecar cache if database is available and refresh is not requested
    if db is not None and not refresh:
        cached_row = get_incident_summary(db, incident.incident_id, evidence_hash)
        if cached_row:
            claims_data = json.loads(cached_row["claims_json"])
            claims = [SummaryClaim(**c) for c in claims_data]
            covered_eids = set()
            for c in claims:
                if c.event_ids:
                    covered_eids.update(c.event_ids)
            return IncidentSummaryResponse(
                incident_id=cached_row["incident_id"],
                evidence_hash=cached_row["evidence_hash"],
                mode=cached_row["mode"],
                headline=cached_row["text"],
                claims=claims,
                verified_count=cached_row["verified"],
                total_count=cached_row["total"],
                dropped_count=cached_row["dropped"],
                model=cached_row["model"],
                generated_at=cached_row["generated_at"],
                headline_source=cached_row.get("headline_source", "llm"),
                is_stale=False,
                events_covered=len(covered_eids),
                total_events=len(incident.event_ids),
            )

    # 2. Determine mode and model
    selected_model = model or os.environ.get("GEMINI_MODEL") or "template"
    api_key_set = bool(os.environ.get("GEMINI_API_KEY"))

    payload: LLMSummaryPayload | None = None
    mode = "template"
    headline_source = "template"
    dropped_count = 0
    total_count = 0
    verified_count = 0

    # 3. Attempt LLM generation if client provided or API key available
    active_client = client
    if active_client is None and api_key_set and selected_model != "template":
        try:
            active_client = GeminiClient(model=selected_model)
        except Exception as exc:
            logger.info("GeminiClient initialization deferred to template: %s", exc)
            active_client = None

    if active_client is not None:
        try:
            packet = build_evidence_packet(incident, events)
            prompt = build_user_prompt(incident, packet)

            # Bounded timeout with no retry storm
            response_json = active_client.generate(
                prompt=prompt,
                system_instruction=SYSTEM_INSTRUCTION,
                timeout=timeout,
            )

            raw_obj = json.loads(response_json)
            if isinstance(raw_obj, list) and len(raw_obj) > 0 and isinstance(raw_obj[0], dict):
                raw_obj = raw_obj[0]
            parsed_payload = LLMSummaryPayload.model_validate(raw_obj)

            # Run deterministic verification (V1-V6, including headline V4/V5)
            verification = verify_summary(parsed_payload, incident, events)
            setattr(active_client, "last_verification", verification)

            if verification.is_valid:
                mode = "llm"
                # Check headline validity
                if verification.headline_valid:
                    final_headline = verification.headline
                    headline_source = "llm"
                else:
                    template_fallback = generate_template_summary(incident)
                    final_headline = template_fallback.headline
                    headline_source = "template"
                    logger.info(
                        "LLM headline for incident %s rejected by verifier (%s); using deterministic template headline.",
                        incident.incident_id,
                        verification.headline_fail_reason,
                    )

                payload = LLMSummaryPayload(
                    headline=final_headline,
                    claims=verification.verified_claims,
                )
                verified_count = verification.verified_count
                total_count = verification.total_count
                dropped_count = verification.dropped_count
                logger.info(
                    "LLM summary for incident %s verified successfully (%d/%d claims verified, %d dropped, headline_source=%s)",
                    incident.incident_id,
                    verified_count,
                    total_count,
                    dropped_count,
                    headline_source,
                )
            else:
                logger.warning(
                    "LLM summary for incident %s failed verification check (%d/%d claims verified, %d dropped). Discarding output and falling back to template.",
                    incident.incident_id,
                    verification.verified_count,
                    verification.total_count,
                    verification.dropped_count,
                )
                payload = None
        except Exception as exc:
            logger.warning(
                "LLM generation failed for incident %s (%s). Falling back to template summary.",
                incident.incident_id,
                exc,
            )
            payload = None

    # 4. Fallback to deterministic template if payload is missing or rejected
    if payload is None:
        mode = "template"
        selected_model = "deterministic-template"
        headline_source = "template"
        payload = generate_template_summary(incident)
        total_count = len(payload.claims)
        verified_count = 0  # deterministic template claims are not marked verified
        dropped_count = 0

    # 5. Build response claims and summary text
    response_claims = [
        SummaryClaim(
            text=c.text,
            event_ids=c.event_ids,
            entities=c.entities,
            technique_ids=c.technique_ids,
            verified=(mode == "llm"),
            deterministic=(mode == "template"),
        )
        for c in payload.claims
    ]

    generated_at = datetime.now(timezone.utc).isoformat()
    claims_json = json.dumps([c.model_dump() for c in response_claims])

    # 6. Format Incident.summary and gather unique citations
    citations_set: set[str] = set()
    summary_lines = [payload.headline, ""]
    for idx, c in enumerate(response_claims, 1):
        summary_lines.append(f"{idx}. {c.text}")
        citations_set.update(c.event_ids)

    formatted_summary = "\n".join(summary_lines).strip()
    sorted_citations = sorted(citations_set)

    # 7. Update Incident core schema fields and persist sidecar record
    incident.summary = formatted_summary
    incident.summary_citations = sorted_citations

    if db is not None:
        upsert_incident_summary(
            db=db,
            incident_id=incident.incident_id,
            evidence_hash=evidence_hash,
            mode=mode,
            text=payload.headline,
            claims_json=claims_json,
            verified=verified_count,
            total=total_count,
            dropped=dropped_count,
            model=selected_model,
            generated_at=generated_at,
            headline_source=headline_source,
        )
        upsert_incident(db, incident)

    return IncidentSummaryResponse(
        incident_id=incident.incident_id,
        evidence_hash=evidence_hash,
        mode=mode,
        headline=payload.headline,
        claims=response_claims,
        verified_count=verified_count,
        total_count=total_count,
        dropped_count=dropped_count,
        model=selected_model,
        generated_at=generated_at,
        headline_source=headline_source,
        is_stale=False,
        events_covered=len(sorted_citations),
        total_events=len(incident.event_ids),
    )
