"""REST endpoints for security incidents, attack graph inspection, and guard action testing."""

import json
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sentinelx.llm.summarizer import compute_evidence_hash, summarize_incident
from sentinelx.schemas.api_models import IncidentSummaryResponse, SummaryClaim
from sentinelx.schemas.event import Event
from sentinelx.schemas.guard import GuardAction, GuardDecision
from sentinelx.schemas.incident import Incident
from sentinelx.schemas.signal import Signal
from sentinelx.store.sqlite import (
    get_event_by_id,
    get_incident_by_id,
    get_latest_incident_summary,
    get_signal_by_id,
    list_incidents,
)

from app.db import get_db
from app.pipeline_state import get_guard_evaluator
from app.ws import manager

router = APIRouter(prefix="/api/v1", tags=["incidents"])


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
    since: Annotated[str | None, Query()] = None,
) -> list[Incident]:
    """Retrieve correlated security incidents, sorted by recency and score."""
    return list_incidents(
        db,
        limit=limit,
        status=status,
        min_score=min_score,
        since=since,
    )


@router.get("/incidents/{incident_id}", response_model=IncidentWithEvidence)
async def get_incident_detail(
    incident_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> IncidentWithEvidence:
    """Retrieve full incident details with inlined detection signals and raw evidence events."""
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

    return IncidentWithEvidence(
        **incident.model_dump(),
        signals=signals,
        evidence_events=events,
    )


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
