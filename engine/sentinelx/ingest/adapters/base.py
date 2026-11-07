"""Base adapter protocol, registry decorator, and normalization helpers."""

import hashlib
from datetime import UTC, datetime
from typing import Any, Protocol

from sentinelx.ingest.tailer import SourceContext
from sentinelx.schemas.event import Event

ADAPTER_REGISTRY: dict[str, type] = {}


def register_adapter(name: str):
    """Decorator to register an adapter class by source type name."""

    def decorator(cls):
        ADAPTER_REGISTRY[name] = cls
        return cls

    return decorator


def get_adapter(name: str) -> Any:
    """Retrieve an instantiated adapter from the registry."""
    if name not in ADAPTER_REGISTRY:
        raise KeyError(f"No adapter registered under name '{name}'")
    return ADAPTER_REGISTRY[name]()


class BaseAdapter(Protocol):
    """Adapter interface protocol."""

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        """Parse raw line into a list of Events, or None if intentionally ignored."""
        ...


def make_event_id(source_tool: str, source_key: str, offset_or_hash: Any) -> str:
    """Generate a deterministic event_id in format evt_<16 hex chars>."""
    raw_key = f"{source_tool}|{source_key}|{offset_or_hash}"
    digest = hashlib.sha1(raw_key.encode("utf-8")).hexdigest()[:16]
    return f"evt_{digest}"


def parse_utc_timestamp(ts_val: Any) -> datetime:
    """Parse various timestamp representations into a timezone-aware UTC datetime."""
    if isinstance(ts_val, (int, float)):
        # Epoch timestamp (e.g. from Zeek or Modbus)
        return datetime.fromtimestamp(float(ts_val), tz=UTC)

    if isinstance(ts_val, str):
        ts_str = ts_val.strip()
        # Check if numeric string
        try:
            epoch = float(ts_str)
            return datetime.fromtimestamp(epoch, tz=UTC)
        except ValueError:
            pass

        # Wazuh format: e.g. "2026-11-07T16:45:55.598+0000" or ISO with Z
        # Python's fromisoformat in 3.11+ parses "+0000", "+00:00", "Z", etc.
        cleaned = ts_str.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)
        except ValueError:
            # Fallback for OpenCanary: "2026-11-07 16:43:14.484481" (naive UTC)
            for fmt in (
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(ts_str, fmt)
                    return dt.replace(tzinfo=UTC)
                except ValueError:
                    continue

    return datetime.now(UTC)
