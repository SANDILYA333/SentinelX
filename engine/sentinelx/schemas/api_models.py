"""API response models for extended read-only frontend data contracts."""

from typing import Any

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


class CaptureEvalRow(BaseModel):
    """Evaluation summary metrics for a single capture dataset."""

    name: str
    scenario_type: str
    display_type: str
    hours: str
    events: int
    signals: int
    incidents: int
    score: float | None = None
    severity: str | None = None
    ttfma_seconds: float | None = Field(
        default=None,
        description="Event-time TTFMA: difference between event timestamps (event.ts), NOT processing latency; processing latency not measured in replay; measured live in the demo rehearsal (Phase 8)",
    )
    ttfma_from_first_signal_seconds: float | None = Field(
        default=None,
        description="Event-time TTFMA from first signal: difference between event timestamps, NOT processing latency",
    )
    ttfma_from_attack_start_seconds: float | None = Field(
        default=None,
        description="Event-time TTFMA from attack start: difference between event timestamps, NOT processing latency",
    )
    status: str
    decoy_touched: bool = False
    ot_touched: bool = False
    kill_chain_stages: list[str] = Field(default_factory=list)


class EvalSummaryResponse(BaseModel):
    """Aggregate benchmark matrix across all 8 verified captures."""

    captures: list[CaptureEvalRow]
    benign_fp_per_24h: float
    benign_hours_total: float = 25.0
    benign_simulated_days: float = 25.0 / 24.0
    benign_fp_upper_bound_95: float = 2.88
    attack_recall: float
    mean_ttfma_seconds: float | None = Field(
        default=None,
        description="Mean event-time TTFMA: difference between event timestamps (event.ts), NOT processing latency; processing latency not measured in replay; measured live in the demo rehearsal (Phase 8)",
    )
    mean_ttfma_from_first_signal_seconds: float | None = Field(
        default=None,
        description="Mean event-time TTFMA from first signal: difference between event timestamps, NOT processing latency",
    )
    mean_ttfma_from_attack_start_seconds: float | None = Field(
        default=None,
        description="Mean event-time TTFMA from attack start: difference between event timestamps, NOT processing latency",
    )
    guard_ot_interlock: str = "100% Deterministic"
    evaluated_at: str
    threshold: float = 0.50
    headline: dict[str, Any] | None = None
    ablation: list[dict[str, Any]] | None = None
    threshold_curve: list[dict[str, Any]] | None = None
    detector_ranking: list[dict[str, Any]] | None = None
    organizer_test: dict[str, Any] | None = None
    score_margin: float | None = None
    loo_benign_summary: list[dict[str, Any]] | None = None


class SummaryClaim(BaseModel):
    """Individual grounded forensic claim in an analyst summary."""

    text: str
    event_ids: list[str] = Field(default_factory=list, title="ClaimEventIds")
    entities: list[str] = Field(default_factory=list, title="ClaimEntities")
    technique_ids: list[str] = Field(default_factory=list, title="ClaimTechniqueIds")
    verified: bool = False
    deterministic: bool = False


class IncidentSummaryResponse(BaseModel):
    """Advisory LLM / deterministic template summary response for an incident."""

    incident_id: str
    evidence_hash: str
    mode: str  # 'llm' or 'template'
    headline: str = Field(title="IncidentHeadline")
    claims: list[SummaryClaim] = Field(default_factory=list)
    verified_count: int
    total_count: int
    dropped_count: int
    model: str
    generated_at: str
    grounding_note: str = "grounding verified by code, not semantics"
