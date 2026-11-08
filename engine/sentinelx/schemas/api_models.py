"""API response models for extended read-only frontend data contracts."""

from pydantic import BaseModel, Field


class AssetResponse(BaseModel):
    """Network, computing, or industrial asset representation."""

    name: str
    hostname: str | None = None
    role: str
    zone: str
    ips: dict[str, str] = Field(default_factory=dict)
    is_decoy: bool = False
    process_critical: bool = False
    criticality: str
    allowed_ot_writers: list[str] = Field(default_factory=list)


class CalibrationPoint(BaseModel):
    """Precision/recall calibration operating point from cross-validation."""

    threshold: float
    fp_per_24h: float
    recall: float
    recommendation: str


class BudgetStatusResponse(BaseModel):
    """Alert budget operational threshold, FP estimates, and calibration matrix."""

    threshold: float
    fp_per_24h_estimate: float = 0.0
    attack_recall_estimate: float = 1.0
    status: str = "calibrated"
    calibration_method: str = "leave_one_out_cross_validation"
    calibration_points: list[CalibrationPoint] = Field(default_factory=list)


class SystemStatusResponse(BaseModel):
    """Platform system status, telemetry pipeline mode, and live counts."""

    status: str
    env: str
    ingest_mode: str
    replay_speed: str
    ingest_running: bool
    db_connected: bool
    events_count: int
    signals_count: int
    incidents_count: int
    budget_threshold: float
