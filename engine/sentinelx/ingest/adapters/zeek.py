"""Zeek telemetry adapters for conn.log, dns.log, and modbus.log."""

import json
from typing import Any

from sentinelx.ingest.adapters.base import (
    BaseAdapter,
    make_event_id,
    parse_utc_timestamp,
    register_adapter,
)
from sentinelx.ingest.tailer import SourceContext
from sentinelx.schemas.common import Domain, Outcome, SourceTool
from sentinelx.schemas.event import Event, OTFields

# Connection state classification per Zeek documentation
CONN_ESTABLISHED = {"SF", "S1", "S2", "S3", "RSTO", "RSTR"}
CONN_FAILED = {"REJ", "RSTOS0", "RSTRH", "SH", "SHR"}


def _get_sensor_zone(ctx: SourceContext) -> str:
    if ctx.zone:
        return ctx.zone
    path_str = str(ctx.file_path).lower()
    if "zeek-it" in path_str:
        return "it"
    if "zeek-dmz" in path_str:
        return "dmz"
    if "zeek-ot" in path_str:
        return "ot"
    return "it"


@register_adapter("zeek_conn")
class ZeekConnAdapter(BaseAdapter):
    """Adapter for Zeek conn.log network connection events."""

    def __init__(self):
        self.last_ignore_reason: str | None = None

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        record: dict[str, Any] = json.loads(line)

        ts = parse_utc_timestamp(record.get("ts"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)
        zone = _get_sensor_zone(ctx)

        conn_state = record.get("conn_state", "")
        if conn_state in CONN_ESTABLISHED:
            outcome = Outcome.success
        elif conn_state in CONN_FAILED:
            outcome = Outcome.failure
        else:
            outcome = Outcome.unknown

        src_ip = record.get("id.orig_h")
        src_port = record.get("id.orig_p")
        dst_ip = record.get("id.resp_h")
        dst_port = record.get("id.resp_p")
        proto = record.get("proto", "tcp").lower()

        tags = [f"sensor:{zone}"]
        service = record.get("service")
        if service:
            tags.append(f"service:{service}")

        return [
            Event(
                event_id=event_id,
                ts=ts,
                ingested_at=ts,
                source_tool=SourceTool.zeek,
                domain=Domain.it,
                category="network",
                action="conn",
                outcome=outcome,
                src_ip=src_ip,
                src_port=int(src_port) if src_port is not None else None,
                dst_ip=dst_ip,
                dst_port=int(dst_port) if dst_port is not None else None,
                protocol=proto,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=record,
                tags=tags,
            )
        ]


@register_adapter("zeek_dns")
class ZeekDnsAdapter(BaseAdapter):
    """Adapter for Zeek dns.log query events."""

    def __init__(self):
        self.last_ignore_reason: str | None = None

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        record: dict[str, Any] = json.loads(line)

        ts = parse_utc_timestamp(record.get("ts"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)
        zone = _get_sensor_zone(ctx)

        rcode = record.get("rcode")
        rcode_name = record.get("rcode_name")
        outcome = (
            Outcome.success
            if (rcode == 0 or rcode_name == "NOERROR" or rcode is None)
            else Outcome.failure
        )

        src_ip = record.get("id.orig_h")
        src_port = record.get("id.orig_p")
        dst_ip = record.get("id.resp_h")
        dst_port = record.get("id.resp_p")

        query = record.get("query", "")
        tags = [f"sensor:{zone}"]
        if query:
            tags.append(f"query:{query}")

        return [
            Event(
                event_id=event_id,
                ts=ts,
                ingested_at=ts,
                source_tool=SourceTool.zeek,
                domain=Domain.it,
                category="dns",
                action="dns_query",
                outcome=outcome,
                src_ip=src_ip,
                src_port=int(src_port) if src_port is not None else None,
                dst_ip=dst_ip,
                dst_port=int(dst_port) if dst_port is not None else None,
                protocol="dns",
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=record,
                tags=tags,
            )
        ]


@register_adapter("zeek_modbus")
class ZeekModbusAdapter(BaseAdapter):
    """Adapter for Zeek modbus.log OT industrial protocol events."""

    def __init__(self):
        self.last_ignore_reason: str | None = None
        self._seen_req_keys: set[str] = set()

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        record: dict[str, Any] = json.loads(line)

        pdu_type = record.get("pdu_type", "").upper()
        uid = record.get("uid", "")
        tid = record.get("tid", "")
        trans_key = f"{uid}:{tid}"

        # Deduplication rule: If this is a RESP and we already saw the REQ for this transaction,
        # ignore the RESP to avoid double-counting commands.
        if pdu_type == "RESP":
            if trans_key in self._seen_req_keys:
                self.last_ignore_reason = "modbus_response_dedup"
                ctx.ignore_reason = self.last_ignore_reason
                return None
        elif pdu_type == "REQ":
            self._seen_req_keys.add(trans_key)
            if len(self._seen_req_keys) > 5000:
                self._seen_req_keys.clear()

        ts = parse_utc_timestamp(record.get("ts"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)
        zone = _get_sensor_zone(ctx)

        src_ip = record.get("id.orig_h")
        src_port = record.get("id.orig_p")
        dst_ip = record.get("id.resp_h")
        dst_port = record.get("id.resp_p")

        func = str(record.get("func", "UNKNOWN")).lower()
        is_write = "write" in func or "mask" in func
        action = f"modbus_{func.replace(' ', '_')}"

        unit_id = record.get("unit")
        fc_num = None
        # Attempt to extract numeric function code if function name includes it
        if "read_holding_registers" in func:
            fc_num = 3
        elif "read_input_registers" in func:
            fc_num = 4
        elif "write_single_coil" in func:
            fc_num = 5
        elif "write_single_register" in func:
            fc_num = 6
        elif "write_multiple_coils" in func:
            fc_num = 15
        elif "write_multiple_registers" in func:
            fc_num = 16

        ot_fields = OTFields(
            unit_id=int(unit_id) if unit_id is not None else None,
            function_code=fc_num,
            register=record.get("address") or record.get("register"),
            value=record.get("value"),
            is_write=is_write,
        )

        tags = [f"sensor:{zone}", f"pdu:{pdu_type.lower()}"]
        if is_write:
            tags.append("modbus_write")

        return [
            Event(
                event_id=event_id,
                ts=ts,
                ingested_at=ts,
                source_tool=SourceTool.zeek,
                domain=Domain.ot,
                category="ot_command",
                action=action,
                outcome=Outcome.success,
                src_ip=src_ip,
                src_port=int(src_port) if src_port is not None else None,
                dst_ip=dst_ip,
                dst_port=int(dst_port) if dst_port is not None else None,
                protocol="modbus",
                ot=ot_fields,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=record,
                tags=tags,
            )
        ]
