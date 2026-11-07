"""OpenCanary multi-service decoy adapter."""

import json
from typing import Any

from sentinelx.ingest.adapters.base import (
    BaseAdapter,
    make_event_id,
    parse_utc_timestamp,
    register_adapter,
)
from sentinelx.ingest.tailer import SourceContext
from sentinelx.normalize.assets import get_assets
from sentinelx.schemas.common import Domain, Outcome, SourceTool
from sentinelx.schemas.event import Event

# OpenCanary logtype mapping
LOGTYPE_ACTIONS = {
    3001: "http_request",
    5001: "ftp_attempt",
    8001: "mysql_login_attempt",
}


@register_adapter("opencanary")
class OpenCanaryAdapter(BaseAdapter):
    """Adapter for OpenCanary JSON honeypot alert logs."""

    def __init__(self):
        self.last_ignore_reason: str | None = None

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        record: dict[str, Any] = json.loads(line)

        logtype = record.get("logtype")
        if logtype is None:
            self.last_ignore_reason = "missing_logtype"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        # Ignore opencanary startup or internal system logtypes if any
        if logtype in (1001, 1002, 1003):  # canaries starting / alive pings
            self.last_ignore_reason = "opencanary_system"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        # Naive utc_time or local_time is UTC
        raw_ts = record.get("utc_time") or record.get("local_time")
        ts = parse_utc_timestamp(raw_ts)
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)

        src_ip = record.get("src_host")
        src_port = record.get("src_port")
        dst_ip = record.get("dst_host")
        dst_port = record.get("dst_port")
        node_id = record.get("node_id", "db-prod-02")

        logdata = record.get("logdata", {})
        username = None
        if isinstance(logdata, dict):
            username = logdata.get("USERNAME") or logdata.get("user")

        # STRICT RULE: NEVER store the OpenCanary password hash or any password in normalized fields or raw
        raw_safe = dict(record)
        if isinstance(raw_safe.get("logdata"), dict):
            safe_logdata = dict(raw_safe["logdata"])
            if "PASSWORD" in safe_logdata:
                safe_logdata["PASSWORD"] = "[REDACTED]"
            if "password" in safe_logdata:
                safe_logdata["password"] = "[REDACTED]"
            raw_safe["logdata"] = safe_logdata

        action = LOGTYPE_ACTIONS.get(logtype, f"opencanary_{logtype}")
        tags = ["decoy", f"logtype:{logtype}"]

        assets = get_assets()
        if assets.is_honey_user(username):
            tags.append("honey_user")

        proto = "tcp"
        if dst_port == 80:
            proto = "http"
        elif dst_port == 3306:
            proto = "mysql"
        elif dst_port == 21:
            proto = "ftp"

        return [
            Event(
                event_id=event_id,
                ts=ts,
                ingested_at=ts,
                source_tool=SourceTool.opencanary,
                domain=Domain.decoy,
                category="decoy_interaction",
                action=action,
                outcome=Outcome.failure if logtype == 8001 else Outcome.success,
                host=node_id,
                src_ip=src_ip,
                src_port=int(src_port) if src_port is not None else None,
                dst_ip=dst_ip,
                dst_port=int(dst_port) if dst_port is not None else None,
                protocol=proto,
                user=username,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=raw_safe,
                tags=tags,
            )
        ]

