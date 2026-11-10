"""REST endpoints for response safety guard evaluation, decision history, and approval workflow."""

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sentinelx.schemas.guard import (
    ApprovalActionRequest,
    GuardAction,
    GuardDecision,
    ResponseRecommendation,
)
from sentinelx.store.sqlite import (
    get_event_by_id,
    get_guard_decision_by_id,
    get_incident_by_id,
    list_guard_decisions,
)

from app.db import get_db
from app.pipeline_state import get_guard_evaluator
from app.ws import manager

router = APIRouter(prefix="/api/v1/guard", tags=["guard"])


class EvaluateGuardRequest(BaseModel):
    action: GuardAction
    target: str
    incident_id: str | None = None
    requested_by: str = "analyst"
    plc_state: dict[str, Any] | None = None


@router.post("/evaluate", response_model=GuardDecision)
async def evaluate_action(
    payload: EvaluateGuardRequest,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> GuardDecision:
    """Evaluate a proposed containment action against the Response Safety Guard."""
    evaluator = get_guard_evaluator(db)
    decision = evaluator.evaluate(
        action=payload.action,
        target=payload.target,
        incident_id=payload.incident_id,
        requested_by=payload.requested_by,
        plc_state=payload.plc_state,
    )

    await manager.broadcast_guard(decision)
    return decision


@router.get("/decisions", response_model=list[GuardDecision])
async def get_decisions(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    incident_id: Annotated[str | None, Query()] = None,
) -> list[GuardDecision]:
    """Retrieve recent safety guard decisions."""
    return list_guard_decisions(db, limit=limit, incident_id=incident_id)


@router.get("/decisions/{decision_id}", response_model=GuardDecision)
async def get_decision_detail(
    decision_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> GuardDecision:
    """Retrieve an individual Guard decision by decision_id."""
    decision = get_guard_decision_by_id(db, decision_id)
    if not decision:
        raise HTTPException(status_code=404, detail=f"Guard decision {decision_id} not found")
    return decision


@router.post("/decisions/{decision_id}/approve", response_model=GuardDecision)
async def approve_guard_decision(
    decision_id: str,
    payload: ApprovalActionRequest,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> GuardDecision:
    """Authorize a response action that requires human review.

    Constraint: Human approval cannot override an explicit DENY.
    """
    evaluator = get_guard_evaluator(db)
    try:
        updated = evaluator.approve_decision(
            decision_id=decision_id,
            actor=payload.effective_actor,
            notes=payload.notes,
        )
        await manager.broadcast_guard(updated)
        return updated
    except ValueError as e:
        status = 404 if "not found" in str(e).lower() else 400
        raise HTTPException(status_code=status, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to record approval: {e}")


@router.post("/decisions/{decision_id}/reject", response_model=GuardDecision)
async def reject_guard_decision(
    decision_id: str,
    payload: ApprovalActionRequest,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> GuardDecision:
    """Reject a proposed response action during human review."""
    evaluator = get_guard_evaluator(db)
    try:
        updated = evaluator.reject_decision(
            decision_id=decision_id,
            actor=payload.effective_actor,
            notes=payload.notes,
        )
        await manager.broadcast_guard(updated)
        return updated
    except ValueError as e:
        status = 404 if "not found" in str(e).lower() else 400
        raise HTTPException(status_code=status, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to record rejection: {e}")


@router.get("/recommendations/{incident_id}", response_model=list[ResponseRecommendation])
async def get_incident_recommendations(
    incident_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> list[ResponseRecommendation]:
    """Retrieve candidate containment response recommendations for an incident, pre-evaluated by the Guard."""
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    events = [get_event_by_id(db, eid) for eid in incident.event_ids[:20]]
    events = [e for e in events if e is not None]

    evaluator = get_guard_evaluator(db)
    return evaluator.generate_incident_recommendations(
        incident=incident,
        events=events,
    )
