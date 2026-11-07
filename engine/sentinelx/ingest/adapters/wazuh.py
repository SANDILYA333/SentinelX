"""Wazuh archives adapter parsing sshd auth, command auditing, and FIM syscheck events."""

import json
import re
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

# Regexes for sshd authentication lines
RE_ACCEPTED = re.compile(
    r"Accepted\s+(?P<method>publickey|password)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
RE_FAILED = re.compile(
    r"Failed\s+(?P<method>\S+)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
RE_INVALID_USER = re.compile(
    r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
RE_DISCONNECTED = re.compile(
    r"Disconnected\s+from\s+(?:authenticating\s+user\s+)?(?P<user>\S+)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)


@register_adapter("wazuh_archives")
class WazuhArchivesAdapter(BaseAdapter):
    """Adapter for Wazuh /var/ossec/logs/archives/archives.json events."""

    def __init__(self):
        self.last_ignore_reason: str | None = None

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        try:
            record: dict[str, Any] = json.loads(line)
        except Exception:
            self.last_ignore_reason = "json_decode_error"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        # Check if direct cmd.jsonl format
        if "cmd" in record and ("mode" in record or "cwd" in record):
            cmd_adapter = CmdJsonlAdapter()
            return cmd_adapter.parse(line, ctx)

        location = record.get("location", "")
        agent = record.get("agent", {})
        host_name = agent.get("name") if isinstance(agent, dict) else None

        # Filter by location
        if "auth.log" in location:
            return self._parse_auth_log(record, ctx, host_name)
        elif "cmd.jsonl" in location:
            return self._parse_cmd_jsonl(record, ctx, host_name)
        elif "syscheck" in location:
            return self._parse_syscheck(record, ctx, host_name)
        else:
            reason = "wazuh_internal"
            self.last_ignore_reason = reason
            ctx.ignore_reason = reason
            return None

    def _parse_auth_log(
        self, record: dict[str, Any], ctx: SourceContext, host_name: str | None
    ) -> list[Event] | None:
        full_log = record.get("full_log", "").strip()
        if not full_log:
            self.last_ignore_reason = "empty_full_log"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        # Ignore known sshd key-lookup or session closure noise
        if full_log.startswith("Accepted key ") or "found at /" in full_log:
            self.last_ignore_reason = "sshd_noise"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        if any(
            noise in full_log
            for noise in (
                "Connection closed by",
                "Received disconnect from",
                "pam_unix(sshd:session): session opened",
                "pam_unix(sshd:session): session closed",
                "pam_unix(sshd:auth): check pass",
                "Server listening on",
            )
        ):
            self.last_ignore_reason = "sshd_noise"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        event_time = parse_utc_timestamp(record.get("timestamp"))
        ingested_at = parse_utc_timestamp(record.get("timestamp"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)

        # 1. Accepted publickey / password
        m = RE_ACCEPTED.search(full_log)
        if m:
            user = m.group("user")
            src_ip = m.group("ip")
            src_port = int(m.group("port"))
            return [
                Event(
                    event_id=event_id,
                    ts=event_time,
                    ingested_at=ingested_at,
                    source_tool=SourceTool.wazuh,
                    domain=Domain.it,
                    category="authentication",
                    action="ssh_login",
                    outcome=Outcome.success,
                    host=host_name,
                    src_ip=src_ip,
                    src_port=src_port,
                    protocol="ssh",
                    user=user,
                    raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                    raw=record,
                    tags=["time_from_ingest", f"auth_method:{m.group('method')}"],
                )
            ]

        # 2. Failed password / key
        m = RE_FAILED.search(full_log)
        if m:
            user = m.group("user")
            src_ip = m.group("ip")
            src_port = int(m.group("port"))
            return [
                Event(
                    event_id=event_id,
                    ts=event_time,
                    ingested_at=ingested_at,
                    source_tool=SourceTool.wazuh,
                    domain=Domain.it,
                    category="authentication",
                    action="ssh_login",
                    outcome=Outcome.failure,
                    host=host_name,
                    src_ip=src_ip,
                    src_port=src_port,
                    protocol="ssh",
                    user=user,
                    raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                    raw=record,
                    tags=["time_from_ingest", "auth_failed"],
                )
            ]

        # 3. Invalid user probe
        m = RE_INVALID_USER.search(full_log)
        if m:
            user = m.group("user")
            src_ip = m.group("ip")
            src_port = int(m.group("port"))
            return [
                Event(
                    event_id=event_id,
                    ts=event_time,
                    ingested_at=ingested_at,
                    source_tool=SourceTool.wazuh,
                    domain=Domain.it,
                    category="authentication",
                    action="ssh_login",
                    outcome=Outcome.failure,
                    host=host_name,
                    src_ip=src_ip,
                    src_port=src_port,
                    protocol="ssh",
                    user=user,
                    raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                    raw=record,
                    tags=["time_from_ingest", "invalid_user"],
                )
            ]

        # 4. Disconnected user
        m = RE_DISCONNECTED.search(full_log)
        if m:
            user = m.group("user")
            src_ip = m.group("ip")
            src_port = int(m.group("port"))
            return [
                Event(
                    event_id=event_id,
                    ts=event_time,
                    ingested_at=ingested_at,
                    source_tool=SourceTool.wazuh,
                    domain=Domain.it,
                    category="authentication",
                    action="ssh_login",
                    outcome=Outcome.failure,
                    host=host_name,
                    src_ip=src_ip,
                    src_port=src_port,
                    protocol="ssh",
                    user=user,
                    raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                    raw=record,
                    tags=["time_from_ingest", "disconnected"],
                )
            ]

        self.last_ignore_reason = "sshd_noise"
        ctx.ignore_reason = self.last_ignore_reason
        return None

    def _parse_cmd_jsonl(
        self, record: dict[str, Any], ctx: SourceContext, host_name: str | None
    ) -> list[Event] | None:
        full_log = record.get("full_log", "").strip()
        if not full_log:
            self.last_ignore_reason = "empty_cmd_log"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        try:
            inner = json.loads(full_log)
        except Exception:
            self.last_ignore_reason = "invalid_inner_json"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        event_time = parse_utc_timestamp(inner.get("ts") or record.get("timestamp"))
        ingested_at = parse_utc_timestamp(record.get("timestamp"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)

        cmd = inner.get("cmd", "")
        mode = inner.get("mode", "exec")
        action = "exec" if mode == "exec" else "shell_command"

        tokens = cmd.strip().split()
        process_name = tokens[0] if tokens else None

        return [
            Event(
                event_id=event_id,
                ts=event_time,
                ingested_at=ingested_at,
                source_tool=SourceTool.wazuh,
                domain=Domain.it,
                category="process",
                action=action,
                outcome=Outcome.success,
                host=inner.get("host") or host_name,
                src_ip=inner.get("src_ip"),
                user=inner.get("user"),
                process=process_name,
                cmdline=cmd,
                session_id=str(inner.get("session")) if inner.get("session") else None,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=record,
                tags=["audit_cmd", f"mode:{mode}"],
            )
        ]

    def _parse_syscheck(
        self, record: dict[str, Any], ctx: SourceContext, host_name: str | None
    ) -> list[Event] | None:
        syscheck = record.get("syscheck", {})
        if not syscheck:
            self.last_ignore_reason = "empty_syscheck"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        event_time = parse_utc_timestamp(record.get("timestamp"))
        ingested_at = parse_utc_timestamp(record.get("timestamp"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)

        event_type = syscheck.get("event", "modified")
        file_path = syscheck.get("path", "")

        tags = ["fim"]
        assets = get_assets()
        if assets.is_honey_file(file_path):
            tags.append("honey_file")

        # Keep path in raw metadata
        raw_data = dict(record)
        raw_data["path"] = file_path

        return [
            Event(
                event_id=event_id,
                ts=event_time,
                ingested_at=ingested_at,
                source_tool=SourceTool.wazuh,
                domain=Domain.it,
                category="file",
                action=f"file_{event_type}",
                outcome=Outcome.success,
                host=host_name,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=raw_data,
                tags=tags,
            )
        ]


@register_adapter("cmd_jsonl")
class CmdJsonlAdapter(BaseAdapter):
    """Adapter for raw /var/log/sentinelx/cmd.jsonl command audit lines."""

    def __init__(self):
        self.last_ignore_reason: str | None = None

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        line_str = line.strip()
        if not line_str:
            self.last_ignore_reason = "empty_line"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        try:
            record = json.loads(line_str)
        except Exception:
            self.last_ignore_reason = "json_decode_error"
            ctx.ignore_reason = self.last_ignore_reason
            return None

        event_time = parse_utc_timestamp(record.get("ts"))
        ingested_at = parse_utc_timestamp(record.get("ts"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)

        cmd = record.get("cmd", "")
        mode = record.get("mode", "exec")
        action = "exec" if mode == "exec" else "shell_command"

        tokens = cmd.strip().split()
        process_name = tokens[0] if tokens else None

        return [
            Event(
                event_id=event_id,
                ts=event_time,
                ingested_at=ingested_at,
                source_tool=SourceTool.wazuh,
                domain=Domain.it,
                category="process",
                action=action,
                outcome=Outcome.success,
                host=record.get("host") or "jump-host",
                src_ip=record.get("src_ip"),
                user=record.get("user"),
                process=process_name,
                cmdline=cmd,
                session_id=str(record.get("session")) if record.get("session") else None,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=record,
                tags=["audit_cmd", f"mode:{mode}"],
            )
        ]
