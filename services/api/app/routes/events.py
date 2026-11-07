"""REST endpoints for telemetry events."""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sentinelx.schemas.event import Event
from sentinelx.store.sqlite import list_events

from app.db import get_db

router = APIRouter(prefix="/api/v1", tags=["events"])


@router.get("/events", response_model=list[Event])
async def get_events(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    before_ts: Annotated[str | None, Query()] = None,
) -> list[Event]:
    """Retrieve newest telemetry events validated through the frozen Event model."""
    return list_events(db, limit=limit, before_ts=before_ts)
