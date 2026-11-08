"""REST endpoints for detection signals and evidence exploration."""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field
from sentinelx.schemas.event import Event
from sentinelx.schemas.signal import Signal
from sentinelx.store.sqlite import get_event_by_id, get_signal_by_id, list_signals

from app.db import get_db

router = APIRouter(prefix="/api/v1", tags=["signals"])


class SignalWithEvidence(Signal):
    """Detection signal with full evidence event details inlined for UI forensic drilldown."""

    evidence_events: list[Event] = Field(default_factory=list)


@router.get("/signals", response_model=list[Signal])
async def get_signals(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    before: Annotated[str | None, Query()] = None,
    since: Annotated[str | None, Query()] = None,
    detector: Annotated[str | None, Query()] = None,
    entity: Annotated[str | None, Query()] = None,
    min_confidence: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
) -> list[Signal]:
    """Retrieve detection signals with multi-criteria filtering, newest first."""
    return list_signals(
        db,
        limit=limit,
        before=before,
        since=since,
        detector=detector,
        entity=entity,
        min_confidence=min_confidence,
    )


@router.get("/signals/{signal_id}", response_model=SignalWithEvidence)
async def get_signal_detail(
    signal_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> SignalWithEvidence:
    """Retrieve full Signal detail with associated evidence telemetry events inlined."""
    sig = get_signal_by_id(db, signal_id=signal_id)
    if not sig:
        raise HTTPException(status_code=404, detail=f"Signal '{signal_id}' not found")

    evidence_events: list[Event] = []
    for eid in sig.evidence_event_ids:
        ev = get_event_by_id(db, event_id=eid)
        if ev:
            evidence_events.append(ev)

    sig_data = sig.model_dump()
    return SignalWithEvidence(**sig_data, evidence_events=evidence_events)
