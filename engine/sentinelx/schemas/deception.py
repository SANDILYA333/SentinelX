"""Deception intelligence, canary telemetry activity, and LotL deception schemas."""

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
    # LotL Deception interaction types
    "shell_history_read",
    "ssh_key_read",
    "ssh_config_read",
    "canary_credential_presented",
    "canary_variable_read",
    "config_file_read",
    "share_enumerated",
    "share_file_read",
    "decoy_file_modified",
    "decoy_task_modified",
]

LotLLureType = Literal[
    "shell_history",
    "ssh_key",
    "ssh_config",
    "canary_env",
    "config_file",
    "decoy_share",
    "scheduled_task",
    "powershell_history",
]

LotLLureStatus = Literal[
    "active",
    "disabled",
    "missing",
    "tampered",
    "unsupported",
    "error",
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


# ==============================================================================
# Living-off-the-Land (LotL) Deception Engine Contracts
# ==============================================================================


class LotLLure(BaseModel):
    """Registry definition and state for an administrative deception artifact."""

    model_config = ConfigDict(extra="forbid")

    lure_id: str
    name: str
    lure_type: LotLLureType
    platform: Literal["linux", "windows", "cross_platform"] = "linux"
    host: str
    path: str
    status: LotLLureStatus = "active"
    created_at: UtcDatetime
    last_interaction: UtcDatetime | None = None
    total_interactions: int = 0
    expected_interactions: list[str] = Field(default_factory=list)
    decoy_destination: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    severity: Severity = Severity.high
    enabled: bool = True
    sha256_hash: str | None = None
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class LotLInteraction(BaseModel):
    """Observed attacker interaction with a Living-off-the-Land deception artifact."""

    model_config = ConfigDict(extra="forbid")

    interaction_id: str
    lure_id: str
    lure_name: str
    lure_type: LotLLureType
    interaction_type: DeceptionInteractionType
    host: str
    user: str | None = None
    process: str | None = None
    cmdline: str | None = None
    target: str
    ts: UtcDatetime
    event_id: str
    severity: Severity = Severity.high
    evidence_source: str
    provenance: Literal["observed", "inferred", "configured"] = "observed"
    mitre_technique: str | None = None
    outcome: Outcome = Outcome.success
    incident_id: str | None = None
    raw_ref: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LotLHealthStatus(BaseModel):
    """Overall health state of the Living-off-the-Land deception infrastructure."""

    model_config = ConfigDict(extra="forbid")

    total_lures: int = 0
    active_lures: int = 0
    missing_lures: int = 0
    tampered_lures: int = 0
    disabled_lures: int = 0
    unsupported_lures: int = 0
    sensors_healthy: bool = True
    last_sensor_heartbeat: UtcDatetime | None = None
    details: list[dict[str, Any]] = Field(default_factory=list)


class LotLAnalytics(BaseModel):
    """Aggregated metrics and interaction breakdown across all LotL deception lures."""

    model_config = ConfigDict(extra="forbid")

    total_active_lures: int = 0
    total_discovered_lures: int = 0
    total_interactions: int = 0
    canary_presentations: int = 0
    decoy_authentications: int = 0
    file_modifications: int = 0
    interacting_hosts: list[str] = Field(default_factory=list)
    interactions_by_type: dict[str, int] = Field(default_factory=dict)
    interactions_by_lure: dict[str, int] = Field(default_factory=dict)
