"""Deception intelligence and canary telemetry activity schemas."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinelx.schemas.common import Outcome, Severity, UtcDatetime

DeceptionInteractionType = Literal[
    "ssh_connection",
    "ssh_login_attempt",
    "ssh_login_success",
    "ssh_command_input",
    "ssh_file_transfer",
    "session_closed",
    "service_discovery",
    "port_probe",
    "http_interaction",
    "mysql_login_attempt",
    "modbus_discovery",
    "modbus_read",
    "modbus_write_attempt",
    "unauthorized_interaction",
]


class DeceptionActivity(BaseModel):
    """Normalized, classified attacker interaction with a deceptive canary asset."""

    model_config = ConfigDict(extra="forbid")

    activity_id: str
    event_id: str
    incident_id: str | None = None
    signal_id: str | None = None
    decoy_asset: str
    decoy_hostname: str | None = None
    decoy_type: str
    sensor_tool: str
    network_zone: str
    src_ip: str | None = None
    attacker_role: str | None = None
    interaction_type: DeceptionInteractionType
    title: str
    description: str
    ts: UtcDatetime
    outcome: Outcome
    severity: Severity
    provenance: Literal["observed", "inferred", "configured"] = "observed"
    mitre_technique: str | None = None
    raw_evidence_ref: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeceptionAssetSummary(BaseModel):
    """Configured deception asset with aggregated runtime interaction statistics."""

    model_config = ConfigDict(extra="forbid")

    name: str
    hostname: str | None = None
    role: str
    zone: str
    ips: dict[str, str] = Field(default_factory=dict)
    total_interactions: int = 0
    unique_source_ips: list[str] = Field(default_factory=list)
    last_seen: UtcDatetime | None = None
    associated_incident_ids: list[str] = Field(default_factory=list)
    status: Literal["active", "untouched", "degraded", "unknown"] = Field(
        "untouched", title="DecoyStatus"
    )


class DeceptionOverview(BaseModel):
    """Aggregated deception intelligence overview metrics and activity stream."""

    model_config = ConfigDict(extra="forbid")

    total_interactions: int = 0
    incident_count: int = 0
    unique_sources: list[str] = Field(default_factory=list)
    top_decoys: list[dict[str, Any]] = Field(default_factory=list)
    category_counts: dict[str, int] = Field(default_factory=dict)
    recent_activities: list[DeceptionActivity] = Field(default_factory=list)
    deception_interpretations: list[str] = Field(default_factory=list)
