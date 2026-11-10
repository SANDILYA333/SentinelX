"""REST endpoints for deception intelligence, canary activity feed, and decoy asset inventory."""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sentinelx.deception.service import (
    get_deception_activity,
    get_deception_assets,
    get_deception_overview,
    list_deception_activities,
)
from sentinelx.schemas.deception import (
    DeceptionActivity,
    DeceptionAssetSummary,
    DeceptionOverview,
)

from app.db import get_db

router = APIRouter(prefix="/api/v1/deception", tags=["deception"])


@router.get("/overview", response_model=DeceptionOverview)
async def get_overview(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> DeceptionOverview:
    """Retrieve high-level deception intelligence overview, metrics, and recent activities."""
    return get_deception_overview(db)


@router.get("/activities", response_model=list[DeceptionActivity])
async def get_activities(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    incident_id: Annotated[
        str | None, Query(description="Filter by associated incident ID")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[DeceptionActivity]:
    """Retrieve classified chronological deception activities from canary telemetry."""
    return list_deception_activities(
        db,
        incident_id=incident_id,
        limit=limit,
        offset=offset,
    )


@router.get("/activities/{activity_id}", response_model=DeceptionActivity)
async def get_activity_detail(
    activity_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> DeceptionActivity:
    """Retrieve detailed information and raw evidence references for a single deception activity."""
    act = get_deception_activity(db, activity_id)
    if not act:
        raise HTTPException(status_code=404, detail=f"Deception activity {activity_id} not found")
    return act


@router.get("/assets", response_model=list[DeceptionAssetSummary])
async def get_assets_inventory(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> list[DeceptionAssetSummary]:
    """Retrieve configured deception canary assets populated with runtime interaction statistics."""
    return get_deception_assets(db)
