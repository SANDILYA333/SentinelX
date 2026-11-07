"""Health check endpoint."""

from fastapi import APIRouter
from pydantic import BaseModel
from sentinelx.schemas.common import SCHEMA_VERSION

from app.config import settings

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    schema_version: str
    env: str


@router.get("/health", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    """Return platform operational health, active schema version, and environment."""
    return HealthResponse(
        status="ok",
        schema_version=SCHEMA_VERSION,
        env=settings.SENTINELX_ENV,
    )
