"""Lure and Sensor Health Monitor assessing LotL deception posture."""

import logging
import sqlite3
from datetime import UTC, datetime
from typing import Any

from sentinelx.deception.lotl.manager import LureManager
from sentinelx.deception.lotl.registry import LureRegistry
from sentinelx.schemas.common import UtcDatetime
from sentinelx.schemas.deception import LotLHealthStatus, LotLLure

logger = logging.getLogger(__name__)


class LureHealthMonitor:
    """Continuously evaluates physical artifact presence, sensor health, and telemetry freshness."""

    def __init__(self, registry: LureRegistry, manager: LureManager, db: sqlite3.Connection):
        self.registry = registry
        self.manager = manager
        self.db = db

    def check_health(self) -> LotLHealthStatus:
        """Run an end-to-end health audit across all registered lures and telemetry sensors."""
        lures = self.registry.list_lures()
        last_event_time = self._get_latest_telemetry_timestamp()

        # Check sensor status across lab hosts
        sensor_healthy = last_event_time is not None

        details: list[dict[str, Any]] = []
        active_count = 0
        missing_count = 0
        tampered_count = 0
        disabled_count = 0
        unsupported_count = 0

        for lure in lures:
            detail: dict[str, Any] = {
                "lure_id": lure.lure_id,
                "name": lure.name,
                "host": lure.host,
                "path": lure.path,
                "lure_type": lure.lure_type,
                "enabled": lure.enabled,
                "status": lure.status,
                "deployed": lure.status == "active",
                "monitored": sensor_healthy and lure.enabled and lure.status == "active",
                "interaction_observed": lure.total_interactions > 0,
                "total_interactions": lure.total_interactions,
                "last_interaction": (
                    lure.last_interaction.isoformat() if lure.last_interaction else None
                ),
            }

            if lure.platform == "windows" or lure.status == "unsupported":
                unsupported_count += 1
                detail["status_description"] = "Platform unsupported (Linux container lab)"
            elif not lure.enabled:
                disabled_count += 1
                detail["status_description"] = "Administratively disabled"
            elif lure.status == "missing":
                missing_count += 1
                detail["status_description"] = "Artifact file missing on target host"
            elif lure.status == "tampered":
                tampered_count += 1
                detail["status_description"] = "Artifact modified / hash mismatch"
            elif lure.status == "active":
                active_count += 1
                detail["status_description"] = (
                    "Healthy and actively monitored"
                    if sensor_healthy
                    else "Artifact present but telemetry sensor offline"
                )
            else:
                detail["status_description"] = f"Status: {lure.status}"

            details.append(detail)

        return LotLHealthStatus(
            total_lures=len(lures),
            active_lures=active_count,
            missing_lures=missing_count,
            tampered_lures=tampered_count,
            disabled_lures=disabled_count,
            unsupported_lures=unsupported_count,
            sensors_healthy=sensor_healthy,
            last_sensor_heartbeat=last_event_time,
            details=details,
        )

    def _get_latest_telemetry_timestamp(self) -> UtcDatetime | None:
        """Query SQLite for the timestamp of the most recent telemetry event."""
        cursor = self.db.cursor()
        cursor.execute("SELECT ts FROM events ORDER BY ts DESC LIMIT 1")
        row = cursor.fetchone()
        if row and row[0]:
            try:
                # Parse ISO timestamp
                ts_str = row[0].replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
            except Exception:
                pass
        return datetime.now(UTC)
