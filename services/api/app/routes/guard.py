"""REST endpoints for response safety guard evaluation and decision history."""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sentinelx.schemas.guard import GuardAction, GuardDecision
from sentinelx.store.sqlite import list_guard_decisions

from app.db import get_db
from app.pipeline_state import get_guard_evaluator
from app.ws import manager

router = APIRouter(prefix="/api/v1/guard", tags=["guard"])


class EvaluateGuardRequest(BaseModel):
    action: GuardAction
    target: str
    incident_id: str | None = None
    requested_by: str = "analyst"


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
