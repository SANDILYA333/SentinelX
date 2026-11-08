"""REST endpoint for MITRE ATT&CK and ATT&CK-ICS technique catalog."""

from fastapi import APIRouter, HTTPException
from sentinelx.enrich.mitre import load_mitre_catalog
from sentinelx.schemas.common import Technique

router = APIRouter(prefix="/api/v1/mitre", tags=["mitre"])


@router.get("/techniques", response_model=list[Technique])
async def get_all_techniques() -> list[Technique]:
    """Retrieve all cataloged MITRE ATT&CK techniques with tactics and names."""
    catalog = load_mitre_catalog()
    return catalog.all_techniques()


@router.get("/techniques/{technique_id}", response_model=Technique)
async def get_technique_by_id(technique_id: str) -> Technique:
    """Retrieve specific MITRE technique by ID."""
    catalog = load_mitre_catalog()
    tech = catalog.get(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail=f"MITRE Technique '{technique_id}' not found")
    return tech
