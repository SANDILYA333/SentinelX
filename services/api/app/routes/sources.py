"""REST endpoint for telemetry sources health monitoring."""

from typing import Any

from fastapi import APIRouter

from app.ingest import get_ingestor

router = APIRouter(prefix="/api/v1/sources", tags=["sources"])


@router.get("/health")
async def get_sources_health() -> list[dict[str, Any]]:
    """Retrieve per-source ingestion counters, last event timestamp, and health status."""
    ingestor = get_ingestor()
    return ingestor.get_sources_health()
