"""Normalized telemetry event schema for SentinelX."""

import warnings
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinelx.schemas.common import Domain, Outcome, SourceTool, UtcDatetime

warnings.filterwarnings(
    "ignore",
    message='Field name "register" in "OTFields" shadows an attribute in parent "BaseModel"',
    category=UserWarning,
)

EventCategory = Literal[
    "authentication",
    "process",
    "network",
    "file",
    "dns",
    "http",
    "ot_command",
    "ot_state",
    "decoy_interaction",
    "other",
]


class OTFields(BaseModel):
    """Operational Technology (OT/ICS) specific telemetry attributes."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    unit_id: int | None = None
    device_id: str | None = None
    function_code: int | None = None
    register: int | None = None
    value: Any | None = None
    is_write: bool


class Event(BaseModel):
    """Normalized security event schema produced by all telemetry adapters."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    ts: UtcDatetime
    ingested_at: UtcDatetime
    source_tool: SourceTool
    domain: Domain
    category: EventCategory
    action: str
    outcome: Outcome
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    user: str | None = None
    process: str | None = None
    parent_process: str | None = None
    cmdline: str | None = None
    session_id: str | None = None
    ot: OTFields | None = None
    raw_ref: dict[str, Any]
    raw: dict[str, Any]
    tags: list[str] = Field(default_factory=list)
