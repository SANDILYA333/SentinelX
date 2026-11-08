"""Rule models and condition specification for SentinelX detection engine."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SeverityLevel = Literal["low", "medium", "high", "critical"]


class RuleFilter(BaseModel):
    """Event pre-filter criteria for fast indexing."""

    model_config = ConfigDict(extra="forbid")

    source_tool: str | None = None
    category: str | None = None
    domain: str | None = None
    action: str | None = None


class RuleContext(BaseModel):
    """Optional contextual constraints (time of day, asset properties, maintenance window)."""

    model_config = ConfigDict(extra="forbid")

    maintenance_window_only: bool | None = None
    outside_maintenance_window: bool | None = None
    authorized_sources: list[str] = Field(default_factory=list)
    forbidden_sources: list[str] = Field(default_factory=list)
    require_honey_match: bool | None = None
    track_session_history: bool | None = None


class RuleDefinition(BaseModel):
    """Declarative detection rule definition."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    severity_hint: SeverityLevel = "medium"
    score: float = Field(default=0.7, ge=0.0, le=1.0)
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    applies_to: list[RuleFilter] = Field(default_factory=list)
    condition: dict[str, Any]
    technique_ids: list[str] = Field(min_length=1)
    explanation_template: str
    context: RuleContext | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
