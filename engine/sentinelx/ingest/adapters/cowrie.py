"""Cowrie SSH decoy interaction adapter."""

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


@register_adapter("cowrie")
class CowrieAdapter(BaseAdapter):
    """Adapter for Cowrie JSON honeypot audit logs."""

    def __init__(self):
        self.last_ignore_reason: str | None = None

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        record: dict[str, Any] = json.loads(line)

        eventid = record.get("eventid", "")
        if not eventid:
            self.last_ignore_reason = "missing_eventid"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        ts = parse_utc_timestamp(record.get("timestamp"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)

        src_ip = record.get("src_ip")
        src_port = record.get("src_port")
        dst_ip = record.get("dst_ip")
        dst_port = record.get("dst_port", 22)
        session_id = record.get("session")
        username = record.get("username")
        sensor = record.get("sensor", "backup-srv-02")

        # Strip password from stored raw record if present
        raw_safe = dict(record)
        if "password" in raw_safe:
            raw_safe["password"] = "[REDACTED]"

        tags = ["decoy", f"eventid:{eventid}"]
        assets = get_assets()
        if assets.is_honey_user(username):
            tags.append("honey_user")

        cmdline = None
        action = eventid.replace("cowrie.", "").replace(".", "_")
        outcome = Outcome.success

        if eventid == "cowrie.login.success":
            action = "ssh_login_success"
            outcome = Outcome.success
        elif eventid == "cowrie.login.failed":
            action = "ssh_login_failed"
            outcome = Outcome.failure
        elif eventid == "cowrie.command.input":
            action = "command_input"
            cmdline = record.get("input")
            outcome = Outcome.success
        elif eventid == "cowrie.session.connect":
            action = "session_connect"
        elif eventid == "cowrie.session.closed":
            action = "session_closed"
        elif "download" in eventid or "upload" in eventid:
            action = "file_transfer"

        return [
            Event(
                event_id=event_id,
                ts=ts,
                ingested_at=ts,
                source_tool=SourceTool.cowrie,
                domain=Domain.decoy,
                category="decoy_interaction",
                action=action,
                outcome=outcome,
                host=sensor,
                src_ip=src_ip,
                src_port=int(src_port) if src_port is not None else None,
                dst_ip=dst_ip,
                dst_port=int(dst_port) if dst_port is not None else None,
                protocol="ssh",
                user=username,
                cmdline=cmdline,
                session_id=str(session_id) if session_id else None,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=raw_safe,
                tags=tags,
            )
        ]
