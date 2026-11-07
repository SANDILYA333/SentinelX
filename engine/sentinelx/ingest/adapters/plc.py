"""PLC simulator and decoy PLC adapters."""

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


@register_adapter("plc_writes")
class PlcWritesAdapter(BaseAdapter):
    """Adapter for plc-sim-writes.jsonl audit records."""

    def __init__(self):
        self.last_ignore_reason: str | None = None

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        record: dict[str, Any] = json.loads(line)

        ts = parse_utc_timestamp(record.get("ts"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)

        fc = record.get("function_code")
        reg = record.get("register")
        val = record.get("value")
        flag = record.get("flag_after_write", "normal")

        ot_fields = OTFields(
            unit_id=1,
            function_code=fc,
            register=reg,
            value=val,
            is_write=True,
        )

        tags = ["modbus_write", f"flag:{flag}"]

        return [
            Event(
                event_id=event_id,
                ts=ts,
                ingested_at=ts,
                source_tool=SourceTool.modbus,
                domain=Domain.ot,
                category="ot_command",
                action="modbus_write",
                outcome=Outcome.success,
                host="plc-sim",
                dst_ip="10.10.3.20",
                dst_port=502,
                protocol="modbus",
                ot=ot_fields,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=record,
                tags=tags,
            )
        ]


@register_adapter("plc_state")
class PlcStateAdapter(BaseAdapter):
    """Adapter for plc-sim-state.jsonl periodic physics telemetry."""

    def __init__(self):
        self.last_ignore_reason: str | None = None

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        record: dict[str, Any] = json.loads(line)

        ts = parse_utc_timestamp(record.get("ts"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)
        flag = record.get("flag", "normal")

        tags = [f"flag:{flag}", "physics_state"]

        ot_fields = OTFields(
            unit_id=1,
            value=record.get("tank_level_pct"),
            is_write=False,
        )

        return [
            Event(
                event_id=event_id,
                ts=ts,
                ingested_at=ts,
                source_tool=SourceTool.modbus,
                domain=Domain.ot,
                category="ot_state",
                action="plc_state",
                outcome=Outcome.success,
                host="plc-sim",
                dst_ip="10.10.3.20",
                dst_port=502,
                protocol="modbus",
                ot=ot_fields,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=record,
                tags=tags,
            )
        ]


@register_adapter("decoy_plc")
class DecoyPlcAdapter(BaseAdapter):
    """Adapter for decoy-plc.jsonl audit interaction records."""

    def __init__(self):
        self.last_ignore_reason: str | None = None

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        record: dict[str, Any] = json.loads(line)

        ts = parse_utc_timestamp(record.get("ts"))
        event_id = make_event_id(ctx.source_tool, ctx.source_key, ctx.offset)

        action_name = record.get("action", "read")
        is_write = action_name == "write"
        block_type = record.get("block_type", "")
        addr = record.get("address")
        vals = record.get("values", [])

        ot_fields = OTFields(
            unit_id=1,
            function_code=16 if is_write else 4,
            register=addr,
            value=vals,
            is_write=is_write,
        )

        tags = ["decoy", "decoy_plc", f"block:{block_type}"]

        return [
            Event(
                event_id=event_id,
                ts=ts,
                ingested_at=ts,
                source_tool=SourceTool.modbus,
                domain=Domain.decoy,
                category="decoy_interaction",
                action=f"decoy_modbus_{action_name}",
                outcome=Outcome.success,
                host="decoy-plc",
                dst_ip="10.10.3.60",
                dst_port=502,
                protocol="modbus",
                ot=ot_fields,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=record,
                tags=tags,
            )
        ]

