"""SentinelX common schema definitions, enums, and validators."""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict

SCHEMA_VERSION: str = "1.0"


def validate_utc_datetime(v: datetime) -> datetime:
    """Validate that datetime is timezone-aware and normalize to UTC."""
    if v.tzinfo is None or v.utcoffset() is None:
        raise ValueError("Datetime must be timezone-aware UTC; naive datetimes are rejected")
    return v.astimezone(UTC)


UtcDatetime = Annotated[datetime, AfterValidator(validate_utc_datetime)]


def new_id(prefix: str) -> str:
    """Generate a prefixed unique identifier (e.g. 'evt_' + 16 hex chars)."""
    clean_prefix = prefix.rstrip("_")
    return f"{clean_prefix}_{uuid.uuid4().hex[:16]}"


class SourceTool(StrEnum):
    """Telemetry collection and deception source tools."""

    wazuh = "wazuh"
    zeek = "zeek"
    cowrie = "cowrie"
    opencanary = "opencanary"
    modbus = "modbus"
    evtx = "evtx"
    generic = "generic"


class Domain(StrEnum):
    """Network and asset operational domain."""

    it = "it"
    ot = "ot"
    decoy = "decoy"


class Outcome(StrEnum):
    """Action execution outcome."""

    success = "success"
    failure = "failure"
    unknown = "unknown"


class Severity(StrEnum):
    """Alert and incident severity levels."""

    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EntityType(StrEnum):
    """Observable entity types for graph and correlation analysis."""

    user = "user"
    host = "host"
    ip = "ip"
    session = "session"
    process = "process"
    device = "device"


class Entity(BaseModel):
    """Observable entity instance."""

    model_config = ConfigDict(extra="forbid")

    type: EntityType
    value: str


class Technique(BaseModel):
    """MITRE ATT&CK technique mapping."""

    model_config = ConfigDict(extra="forbid")

    framework: Literal["enterprise", "ics"]
    technique_id: str
    name: str
    tactic: str


class WSMessage(BaseModel):
    """Typed WebSocket envelope for real-time messaging."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["hello", "event", "signal", "incident", "guard", "health"]
    ts: UtcDatetime
    payload: dict[str, Any]
