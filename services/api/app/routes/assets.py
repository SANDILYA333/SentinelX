"""REST endpoint for asset inventory exploration."""

from fastapi import APIRouter, HTTPException
from sentinelx.normalize.assets import get_assets
from sentinelx.schemas.api_models import AssetResponse

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


@router.get("", response_model=list[AssetResponse])
async def get_assets_list() -> list[AssetResponse]:
    """Retrieve full asset inventory including criticality, zone, and decoy markings."""
    assets = get_assets()
    responses: list[AssetResponse] = []
    for h in assets.hosts:
        responses.append(
            AssetResponse(
                name=h.name,
                hostname=h.hostname,
                role=h.role,
                zone=h.zone,
                ips=h.ips,
                is_decoy=h.is_decoy,
                process_critical=h.process_critical,
                criticality=h.criticality,
                allowed_ot_writers=h.allowed_ot_writers,
            )
        )
    return responses


@router.get("/{name}", response_model=AssetResponse)
async def get_asset_detail(name: str) -> AssetResponse:
    """Retrieve asset details by hostname or asset name."""
    assets = get_assets()
    host = assets.get_host_by_name(name)
    if not host:
        raise HTTPException(status_code=404, detail=f"Asset '{name}' not found")

    return AssetResponse(
        name=host.name,
        hostname=host.hostname,
        role=host.role,
        zone=host.zone,
        ips=host.ips,
        is_decoy=host.is_decoy,
        process_critical=host.process_critical,
        criticality=host.criticality,
        allowed_ot_writers=host.allowed_ot_writers,
    )
