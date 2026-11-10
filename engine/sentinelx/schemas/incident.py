"""Correlated security incident and graph schema for SentinelX."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinelx.schemas.common import Entity, Severity, Technique, UtcDatetime

IncidentStatus = Literal["open", "closed", "suppressed"]
ProvenanceType = Literal["observed", "inferred", "configured"]
NetworkZone = Literal["it", "dmz", "ot", "mgmt", "external", "unknown"]


class GraphNode(BaseModel):
    """Node in an incident correlation graph representing a verified or observed entity."""

    model_config = ConfigDict(extra="forbid")

    id: str
    entity_id: str | None = None
    type: str = Field(title="GraphEntityType", description="Observable entity type for graph node")
    label: str
    hostname: str | None = None
    ip_address: str | None = None
    network_zone: NetworkZone = "unknown"
    network_zones: list[NetworkZone] = Field(default_factory=list)
    first_seen: UtcDatetime | None = None
    last_seen: UtcDatetime | None = None
    first_observed_event_id: str | None = None
    last_observed_event_id: str | None = None
    status: str = "active"
    risk_level: str = "low"
    evidence_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """Edge connecting nodes in an incident correlation graph with explicit provenance."""

    model_config = ConfigDict(extra="forbid")

    id: str | None = None
    source: str
    target: str
    label: str
    relationship_type: str = "network_connection"
    ts: UtcDatetime
    first_observed_at: UtcDatetime | None = None
    last_observed_at: UtcDatetime | None = None
    event_ids: list[str] = Field(default_factory=list)
    confidence: float = 1.0
    provenance: ProvenanceType = "observed"
    observation_status: ProvenanceType = "observed"
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentGraph(BaseModel):
    """Correlated entity and attack chain graph representation."""

    model_config = ConfigDict(extra="forbid")

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    """Chronological reconstructed event in an attack incident timeline."""

    model_config = ConfigDict(extra="forbid")

    id: str
    event_id: str
    signal_id: str | None = None
    incident_id: str
    timestamp: UtcDatetime
    event_type: str
    category: str
    title: str
    description: str
    source_node_id: str | None = None
    target_node_id: str | None = None
    severity: Severity = "low"
    evidence_reference: str
    provenance: ProvenanceType = "observed"
    mitre_technique: Technique | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    """Correlated attack incident reconstructed across IT/OT domains."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    status: IncidentStatus
    created_at: UtcDatetime
    updated_at: UtcDatetime
    first_signal_ts: UtcDatetime
    first_meaningful_alert_ts: UtcDatetime | None = None
    ttfma_seconds: float | None = Field(
        default=None,
        description=(
            "Event-time TTFMA: elapsed event-time seconds from the first adversary action "
            "to the signal that caused the incident score to reach/cross the alert threshold. "
            "Never substitutes processing latency for event-time delta. "
            "None when the incident has not yet crossed the threshold or timestamps are unavailable."
        ),
    )
    # Phase A — TTFMA provenance fields (additive, backward-compatible with None defaults)
    first_adversary_event_ts: UtcDatetime | None = Field(
        default=None,
        description="Timestamp of the earliest qualifying adversary event in this incident.",
    )
    threshold_crossing_event_ts: UtcDatetime | None = Field(
        default=None,
        description=(
            "Timestamp of the event whose signal caused the incident score to reach or exceed "
            "the configured alert threshold for the first time."
        ),
    )
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
    timeline: list[TimelineEvent] = Field(default_factory=list)
