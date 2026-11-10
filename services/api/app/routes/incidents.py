"""REST endpoints for security incidents, attack graph inspection, and guard action testing.

Phase A — Task 5: Incident API filtering
  - GET /api/v1/incidents defaults to min_score = active budget threshold (actionable feed).
  - Pass all_scores=true or min_score=0 explicitly to retrieve sub-threshold/forensic records.
  - The effective threshold comes from the single authoritative source: BudgetController.
"""

import json
import logging
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sentinelx.budget.controller import DEFAULT_INCIDENT_THRESHOLD
from sentinelx.correlate.graph import build_incident_graph, build_incident_timeline
from sentinelx.llm.summarizer import compute_evidence_hash, summarize_incident
from sentinelx.schemas.api_models import IncidentSummaryResponse, SummaryClaim
from sentinelx.schemas.event import Event
from sentinelx.schemas.guard import GuardAction, GuardDecision
from sentinelx.schemas.incident import Incident, TimelineEvent
from sentinelx.schemas.signal import Signal
from sentinelx.store.sqlite import (
    get_event_by_id,
    get_incident_by_id,
    get_latest_incident_summary,
    get_signal_by_id,
    list_incidents,
)

from app.db import get_db
from app.pipeline_state import get_correlation_pipeline, get_guard_evaluator
from app.ws import manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["incidents"])


def _effective_threshold() -> float:
    """Return the active alert budget threshold from the pipeline, or the compiled default.

    This is the single authoritative source for the alert threshold used by the API.
    """
    try:
        pipeline = get_correlation_pipeline()
        return pipeline.budget.threshold
    except Exception:
        return DEFAULT_INCIDENT_THRESHOLD


class IncidentWithEvidence(Incident):
    """Correlated security incident with full signals and telemetry events inlined."""

    signals: list[Signal] = Field(default_factory=list)
    evidence_events: list[Event] = Field(default_factory=list)


class GuardActionRequest(BaseModel):
    """Payload to evaluate a containment response action against response safety guard."""

    action: GuardAction
    target: str
    requested_by: str = "analyst"


@router.get("/incidents", response_model=list[Incident])
async def get_incidents(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    status: Annotated[str | None, Query()] = None,
    min_score: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    all_scores: Annotated[
        bool,
        Query(
            description="Set true to include sub-threshold forensic records (overrides default threshold filter)"
        ),
    ] = False,
    since: Annotated[str | None, Query()] = None,
) -> list[Incident]:
    """Retrieve correlated security incidents, sorted by recency and score.

    Default behaviour (actionable feed):
      Returns only incidents whose score >= the active alert budget threshold.
      This prevents sub-threshold noise from appearing in the main incident feed.

    Forensic / sub-threshold retrieval:
      Pass all_scores=true to retrieve all records regardless of score.
      Pass an explicit min_score value (including 0.0) to override the threshold.

    The applied threshold is sourced exclusively from the BudgetController — there is
    no second hardcoded threshold value in this endpoint.
    """
    # Determine effective min_score:
    # Priority: explicit min_score > all_scores flag > active budget threshold
    if min_score is not None:
        effective_min_score: float | None = min_score
    elif all_scores:
        effective_min_score = None  # forensic mode: no score filter
    else:
        effective_min_score = _effective_threshold()

    logger.debug(
        "GET /incidents: effective_min_score=%s all_scores=%s explicit_min_score=%s",
        effective_min_score,
        all_scores,
        min_score,
    )

    return list_incidents(
        db,
        limit=limit,
        status=status,
        min_score=effective_min_score,
        since=since,
    )


@router.get("/incidents/{incident_id}", response_model=IncidentWithEvidence)
async def get_incident_detail(
    incident_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> IncidentWithEvidence:
    """Retrieve full incident details with inlined detection signals, raw evidence events, and timeline."""
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    # Inline signals
    signals: list[Signal] = []
    for sid in incident.signal_ids:
        s = get_signal_by_id(db, sid)
        if s:
            signals.append(s)

    # Inline raw events
    events: list[Event] = []
    for eid in incident.event_ids:
        ev = get_event_by_id(db, eid)
        if ev:
            events.append(ev)

    # Generate or enrich attack graph and chronological timeline
    enriched_graph = build_incident_graph(signals, events) if signals or events else incident.graph
    timeline = build_incident_timeline(incident_id, events, signals)

    inc_data = incident.model_dump()
    inc_data["graph"] = enriched_graph
    inc_data["timeline"] = timeline

    return IncidentWithEvidence(
        **inc_data,
        signals=signals,
        evidence_events=events,
    )


@router.get("/incidents/{incident_id}/timeline", response_model=list[TimelineEvent])
async def get_incident_timeline_endpoint(
    incident_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> list[TimelineEvent]:
    """Retrieve the chronologically reconstructed attack timeline for an incident."""
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    signals: list[Signal] = []
    for sid in incident.signal_ids:
        s = get_signal_by_id(db, sid)
        if s:
            signals.append(s)

    events: list[Event] = []
    for eid in incident.event_ids:
        ev = get_event_by_id(db, eid)
        if ev:
            events.append(ev)

    return build_incident_timeline(incident_id, events, signals)


@router.post("/incidents/{incident_id}/guard-action", response_model=GuardDecision)
async def evaluate_incident_guard_action(
    incident_id: str,
    payload: GuardActionRequest,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> GuardDecision:
    """Evaluate a proposed containment action for an incident against the Response Safety Guard."""
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    evaluator = get_guard_evaluator(db)
    decision = evaluator.evaluate(
        action=payload.action,
        target=payload.target,
        incident_id=incident_id,
        requested_by=payload.requested_by,
    )

    # Broadcast guard decision
    await manager.broadcast_guard(decision)

    return decision


@router.get("/incidents/{incident_id}/summary", response_model=IncidentSummaryResponse)
async def get_incident_summary_endpoint(
    incident_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> IncidentSummaryResponse:
    """Retrieve the cached analyst summary for an incident."""
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    cached_row = get_latest_incident_summary(db, incident_id)
    if not cached_row:
        raise HTTPException(status_code=404, detail=f"No summary found for incident {incident_id}")

    current_hash = compute_evidence_hash(incident)
    is_stale = cached_row["evidence_hash"] != current_hash

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
        is_stale=is_stale,
        events_covered=len(covered_eids),
        total_events=len(incident.event_ids),
    )


@router.post("/incidents/{incident_id}/summary", response_model=IncidentSummaryResponse)
async def generate_incident_summary_endpoint(
    incident_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    refresh: Annotated[bool, Query()] = False,
) -> IncidentSummaryResponse:
    """Generate or retrieve a verified analyst summary for an incident."""
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    events: list[Event] = []
    for eid in incident.event_ids:
        ev = get_event_by_id(db, eid)
        if ev:
            events.append(ev)

    summary_resp = summarize_incident(
        incident=incident,
        events=events,
        db=db,
        refresh=refresh,
    )
    return summary_resp
