"""Correlated security incident and graph schema for SentinelX."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinelx.schemas.common import Entity, Severity, Technique, UtcDatetime

IncidentStatus = Literal["open", "closed", "suppressed"]


class GraphNode(BaseModel):
    """Node in an incident correlation graph."""

    model_config = ConfigDict(extra="forbid")

    id: str
    type: str
    label: str


class GraphEdge(BaseModel):
    """Edge connecting nodes in an incident correlation graph."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    label: str
    ts: UtcDatetime
    event_ids: list[str]


class IncidentGraph(BaseModel):
    """Correlated entity and attack chain graph representation."""

    model_config = ConfigDict(extra="forbid")

    nodes: list[GraphNode]
    edges: list[GraphEdge]


class Incident(BaseModel):
    """Correlated attack incident reconstructed across IT/OT domains."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    status: IncidentStatus
    created_at: UtcDatetime
    updated_at: UtcDatetime
    first_signal_ts: UtcDatetime
    first_meaningful_alert_ts: UtcDatetime | None = None
    ttfma_seconds: float | None = None
    score: float
    severity: Severity
    entities: list[Entity]
    signal_ids: list[str]
    event_ids: list[str]
    kill_chain_stages: list[str]
    techniques: list[Technique]
    decoy_touched: bool
    ot_touched: bool
    novelty_only: bool = False
    explanation: list[str]
    summary: str | None = None
    summary_citations: list[str] = Field(default_factory=list)
    graph: IncidentGraph | None = None
