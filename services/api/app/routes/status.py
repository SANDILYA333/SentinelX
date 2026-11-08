"""REST endpoint for SentinelX system status and replay progress."""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends
from sentinelx.schemas.api_models import SystemStatusResponse

from app.config import settings
from app.db import get_db
from app.ingest import get_ingestor
from app.pipeline_state import get_correlation_pipeline

router = APIRouter(prefix="/api/v1/status", tags=["status"])


@router.get("", response_model=SystemStatusResponse)
async def get_system_status(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> SystemStatusResponse:
    """Retrieve runtime status, pipeline mode, and live entity counts."""
    ingestor = get_ingestor()
    pipeline = get_correlation_pipeline(db)

    # Event count
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    events_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM signals")
    signals_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM incidents")
    incidents_count = cur.fetchone()[0]

    return SystemStatusResponse(
        status="ok",
        env=settings.SENTINELX_ENV,
        ingest_mode=settings.SENTINELX_INGEST_MODE,
        replay_speed=str(settings.SENTINELX_REPLAY_SPEED),
        ingest_running=ingestor.running if ingestor else False,
        db_connected=True,
        events_count=events_count,
        signals_count=signals_count,
        incidents_count=incidents_count,
        budget_threshold=pipeline.budget.threshold,
    )
