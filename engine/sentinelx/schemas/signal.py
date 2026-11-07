"""Detection signal schema emitted by SentinelX detection engines."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinelx.schemas.common import Entity, Technique, UtcDatetime

DetectorType = Literal["rule", "baseline", "anomaly", "graph", "deception"]


class Signal(BaseModel):
    """Detection signal emitted by detectors (detectors emit signals, never raw alerts)."""

    model_config = ConfigDict(extra="forbid")

    signal_id: str
    ts: UtcDatetime
    detector: DetectorType
    rule_id: str
    title: str
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    entities: list[Entity]
    evidence_event_ids: list[str] = Field(min_length=1)
    techniques: list[Technique]
    explanation: str
    metadata: dict[str, Any] = Field(default_factory=dict)
