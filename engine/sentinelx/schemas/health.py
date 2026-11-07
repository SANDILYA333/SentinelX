"""Frozen data contracts for source health and telemetry statistics."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from sentinelx.schemas.common import UtcDatetime


class SourceHealth(BaseModel):
    """Health status and telemetry volume counters for an ingestion source."""

    model_config = ConfigDict(extra="forbid")

    source_key: str
    source_tool: str
    relative_path: str
    status: Literal["live", "idle", "stale", "error"]
    expected_active: bool
    lines_read: int
    events_emitted: int
    ignored: dict[str, int]
    unparsed: int
    errors: int
    last_event_ts: UtcDatetime | None = None
    last_event_age_sec: float | None = None
    last_error: str | None = None


class TelemetryStats(BaseModel):
    """Aggregate telemetry event metrics computed over a sliding time window."""

    model_config = ConfigDict(extra="forbid")

    window_seconds: int
    total_events: int
    events_per_sec: float
    by_source: dict[str, int]
    by_category: dict[str, int]
    by_domain: dict[str, int]
