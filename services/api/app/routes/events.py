"""REST endpoints for telemetry events and aggregate statistics."""

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sentinelx.schemas.event import Event
from sentinelx.store.sqlite import get_event_by_id, get_stats, list_events

from app.db import get_db

router = APIRouter(prefix="/api/v1", tags=["events"])


@router.get("/events", response_model=list[Event])
async def get_events(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    before: Annotated[str | None, Query()] = None,
    since: Annotated[str | None, Query()] = None,
    source_tool: Annotated[str | None, Query()] = None,
    domain: Annotated[str | None, Query()] = None,
    category: Annotated[str | None, Query()] = None,
    host: Annotated[str | None, Query()] = None,
    user: Annotated[str | None, Query()] = None,
    ip: Annotated[str | None, Query()] = None,
    before_ts: Annotated[str | None, Query()] = None,  # Backward compatibility
) -> list[Event]:
    """Retrieve telemetry events with flexible filtering, newest first."""
    return list_events(
        db,
        limit=limit,
        before=before,
        since=since,
        source_tool=source_tool,
        domain=domain,
        category=category,
        host=host,
        user=user,
        ip=ip,
        before_ts=before_ts,
    )


@router.get("/events/{event_id}", response_model=Event)
async def get_event(
    event_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> Event:
    """Retrieve full event detail including raw payloads for forensic provenance."""
    event = get_event_by_id(db, event_id=event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")
    return event


@router.get("/stats")
async def get_telemetry_stats(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    window_seconds: Annotated[int, Query(ge=10, le=86400)] = 300,
) -> dict[str, Any]:
    """Retrieve aggregate telemetry event metrics over the specified time window."""
    return get_stats(db, window_seconds=window_seconds)
