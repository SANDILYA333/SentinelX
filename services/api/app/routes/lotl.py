"""REST endpoints for Living-off-the-Land (LotL) Deception Engine."""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sentinelx.deception.lotl.health import LureHealthMonitor
from sentinelx.deception.lotl.manager import LureManager
from sentinelx.deception.lotl.registry import LureRegistry
from sentinelx.schemas.deception import (
    LotLAnalytics,
    LotLHealthStatus,
    LotLInteraction,
    LotLLure,
)
from sentinelx.store.sqlite import (
    get_lotl_analytics,
    get_lotl_lure,
    list_lotl_interactions,
    list_lotl_lures,
    set_lotl_lure_enabled,
)

from app.db import get_db

router = APIRouter(prefix="/api/v1/deception/lotl", tags=["lotl-deception"])


def get_lure_registry(db: Annotated[sqlite3.Connection, Depends(get_db)]) -> LureRegistry:
    """Dependency provider for LureRegistry."""
    return LureRegistry(db)


def get_lure_manager(
    registry: Annotated[LureRegistry, Depends(get_lure_registry)],
) -> LureManager:
    """Dependency provider for LureManager."""
    return LureManager(registry)


def get_lure_health_monitor(
    registry: Annotated[LureRegistry, Depends(get_lure_registry)],
    manager: Annotated[LureManager, Depends(get_lure_manager)],
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> LureHealthMonitor:
    """Dependency provider for LureHealthMonitor."""
    return LureHealthMonitor(registry, manager, db)


@router.get("/lures", response_model=list[LotLLure])
async def get_lures(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    host: Annotated[str | None, Query(description="Filter by host")] = None,
    lure_type: Annotated[str | None, Query(description="Filter by lure type")] = None,
    status: Annotated[str | None, Query(description="Filter by status")] = None,
    enabled: Annotated[bool | None, Query(description="Filter by enabled")] = None,
) -> list[LotLLure]:
    """List registered deception artifacts with optional filtering."""
    # Ensure registry seeded
    LureRegistry(db)
    return list_lotl_lures(db, host=host, lure_type=lure_type, status=status, enabled=enabled)


@router.get("/lures/{lure_id}", response_model=LotLLure)
async def get_lure_detail(
    lure_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> LotLLure:
    """Retrieve details for a single deception artifact."""
    LureRegistry(db)
    lure = get_lotl_lure(db, lure_id)
    if not lure:
        raise HTTPException(status_code=404, detail=f"Lure '{lure_id}' not found")
    return lure


@router.post("/lures/{lure_id}/enable", response_model=LotLLure)
async def enable_lure(
    lure_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> LotLLure:
    """Administratively enable a deception artifact."""
    LureRegistry(db)
    updated = set_lotl_lure_enabled(db, lure_id, True)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Lure '{lure_id}' not found")
    return updated


@router.post("/lures/{lure_id}/disable", response_model=LotLLure)
async def disable_lure(
    lure_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> LotLLure:
    """Administratively disable a deception artifact."""
    LureRegistry(db)
    updated = set_lotl_lure_enabled(db, lure_id, False)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Lure '{lure_id}' not found")
    return updated


@router.get("/interactions", response_model=list[LotLInteraction])
async def get_interactions(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    lure_id: Annotated[str | None, Query(description="Filter by lure ID")] = None,
    host: Annotated[str | None, Query(description="Filter by host")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[LotLInteraction]:
    """Retrieve chronologically ordered interactions with LotL deception artifacts."""
    return list_lotl_interactions(db, lure_id=lure_id, host=host, limit=limit, offset=offset)


@router.get("/health", response_model=LotLHealthStatus)
async def get_health(
    monitor: Annotated[LureHealthMonitor, Depends(get_lure_health_monitor)],
) -> LotLHealthStatus:
    """Retrieve overall health state of the deception infrastructure and sensors."""
    return monitor.check_health()


@router.get("/analytics", response_model=LotLAnalytics)
async def get_analytics(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> LotLAnalytics:
    """Retrieve aggregated telemetry analytics and interaction distribution for LotL deception."""
    return get_lotl_analytics(db)


@router.post("/deploy")
async def deploy_all_lures(
    manager: Annotated[LureManager, Depends(get_lure_manager)],
) -> dict:
    """Safely deploy and verify all active LotL deception artifacts in the lab environment."""
    result = manager.deploy_all()
    return {
        "status": "success",
        "total_attempted": result.total_attempted,
        "deployed": result.deployed,
        "verified": result.verified,
        "failed": result.failed,
        "skipped": result.skipped,
        "unsupported": result.unsupported,
        "details": result.details,
    }


@router.post("/verify")
async def verify_all_lures(
    manager: Annotated[LureManager, Depends(get_lure_manager)],
) -> dict:
    """Verify physical artifact presence and sha256 integrity on lab hosts."""
    statuses = manager.verify_all()
    return {"status": "success", "lure_statuses": statuses}

