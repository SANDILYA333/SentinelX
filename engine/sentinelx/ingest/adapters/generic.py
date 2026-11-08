"""Generic schema-driven JSON and CSV adapter supporting external organizer logs."""

import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from sentinelx.ingest.adapters.base import (
    BaseAdapter,
    make_event_id,
    parse_utc_timestamp,
    register_adapter,
)
from sentinelx.ingest.tailer import SourceContext
from sentinelx.schemas.common import Domain, Outcome, SourceTool
from sentinelx.schemas.event import Event, OTFields


class GenericMappingConfig:
    """Loaded configuration from a YAML mapping specification."""

    def __init__(self, data: dict[str, Any]):
        self.name: str = data.get("name", "generic")
        self.format: str = data.get("format", "json").lower()
        self.source_tool: str = data.get("source_tool", "generic")
        self.domain: str = data.get("domain", "it")
        self.delimiter: str = data.get("delimiter", ",")
        self.timestamp_cfg: dict[str, Any] = data.get("timestamp", {})
        self.fields_map: dict[str, str] = data.get("fields", {})
        self.ot_fields_map: dict[str, str] = data.get("ot_fields", {})
        self.conditional_rules: list[dict[str, Any]] = data.get("conditional_rules", [])
        self.default_rule: dict[str, Any] = data.get("default", {})
        self.csv_headers: list[str] | None = data.get("csv_headers")

    @classmethod
    def load(cls, path_or_name: str | Path) -> "GenericMappingConfig":
        p = Path(path_or_name)
        if not p.is_file():
            # Check content/mappings/
            repo_root = Path(__file__).resolve().parent.parent.parent.parent.parent
            candidate = repo_root / "content" / "mappings" / f"{path_or_name}.yaml"
            if candidate.is_file():
                p = candidate
            else:
                candidate_yml = repo_root / "content" / "mappings" / f"{path_or_name}.yml"
                if candidate_yml.is_file():
                    p = candidate_yml

        if not p.is_file():
            raise FileNotFoundError(f"Mapping configuration not found: {path_or_name}")

        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data)


@register_adapter("generic_json")
@register_adapter("generic_csv")
class GenericMappingAdapter(BaseAdapter):
    """Generic mapping adapter driven by declarative YAML mapping configs."""

    def __init__(self, config: GenericMappingConfig | str | Path | None = None):
        self.last_ignore_reason: str | None = None
        if isinstance(config, GenericMappingConfig):
            self.config = config
        elif config:
            self.config = GenericMappingConfig.load(config)
        else:
            self.config = None
        self._csv_headers: list[str] | None = None

    def set_config(self, config: GenericMappingConfig | str | Path):
        if isinstance(config, GenericMappingConfig):
            self.config = config
        else:
            self.config = GenericMappingConfig.load(config)
        self._csv_headers = self.config.csv_headers

    def parse(self, line: str, ctx: SourceContext) -> list[Event] | None:
        self.last_ignore_reason = None
        if self.config is None:
            # Try to load mapping from ctx.source_key or source_tool
            mapping_name = ctx.source_key.replace("generic_", "")
            try:
                self.set_config(mapping_name)
            except Exception:
                raise ValueError(
                    f"GenericMappingAdapter requires a mapping configuration for source {ctx.source_key}"
                )

        # Parse record dictionary from line
        if self.config.format == "csv":
            record = self._parse_csv_line(line)
            if record is None:
                # Header row or empty
                self.last_ignore_reason = "csv_header_or_empty"
                ctx.ignore_reason = self.last_ignore_reason
                return None
        else:
            line_str = line.strip()
            if not line_str:
                self.last_ignore_reason = "empty_line"
                ctx.ignore_reason = self.last_ignore_reason
                return None
            try:
                record = json.loads(line_str)
            except Exception as e:
                raise ValueError(f"Invalid JSON line in generic adapter: {e}") from e

        # Extract timestamp
        ts_field = self.config.timestamp_cfg.get("field", "timestamp")
        ts_val = record.get(ts_field)
        ts = parse_utc_timestamp(ts_val)

        # Extract mapped fields
        def _get_val(target_field: str) -> Any:
            source_col = self.config.fields_map.get(target_field)
            if source_col and source_col in record:
                return record[source_col]
            return record.get(target_field)

        host = _get_val("host")
        user = _get_val("user")
        src_ip = _get_val("src_ip")
        dst_ip = _get_val("dst_ip")
        src_port = _get_val("src_port")
        dst_port = _get_val("dst_port")
        protocol = _get_val("protocol")
        cmdline = _get_val("cmdline")
        process = _get_val("process")
        parent_process = _get_val("parent_process")
        session_id = _get_val("session_id")

        # Evaluate conditional rules
        matched_rule = None
        for rule in self.config.conditional_rules:
            match_cond = rule.get("match", {})
            matched = True
            for k, expected_v in match_cond.items():
                actual_v = record.get(k)
                if str(actual_v).strip().lower() != str(expected_v).strip().lower():
                    matched = False
                    break
            if matched:
                matched_rule = rule
                break

        rule_to_apply = matched_rule or self.config.default_rule

        category = rule_to_apply.get("category", "other")
        action = rule_to_apply.get("action", "unknown_action")
        outcome_str = rule_to_apply.get("outcome", "success").lower()
        outcome = (
            Outcome.success
            if outcome_str == "success"
            else (Outcome.failure if outcome_str == "failure" else Outcome.unknown)
        )

        domain_str = self.config.domain.lower()
        domain = (
            Domain.ot
            if domain_str == "ot"
            else (Domain.decoy if domain_str == "decoy" else Domain.it)
        )

        # OT Fields
        ot_fields = None
        if self.config.ot_fields_map or "is_write" in rule_to_apply:
            is_write = bool(
                rule_to_apply.get("is_write", False)
                or str(record.get("is_write", "")).lower() in ("true", "1")
            )
            ot_fields = OTFields(
                unit_id=(
                    int(record[self.config.ot_fields_map["unit_id"]])
                    if "unit_id" in self.config.ot_fields_map
                    and record.get(self.config.ot_fields_map["unit_id"])
                    else None
                ),
                function_code=(
                    int(record[self.config.ot_fields_map["function_code"]])
                    if "function_code" in self.config.ot_fields_map
                    and record.get(self.config.ot_fields_map["function_code"])
                    else None
                ),
                register=(
                    int(record[self.config.ot_fields_map["register"]])
                    if "register" in self.config.ot_fields_map
                    and record.get(self.config.ot_fields_map["register"])
                    else None
                ),
                value=(
                    record.get(self.config.ot_fields_map.get("value", ""))
                    if "value" in self.config.ot_fields_map
                    else None
                ),
                is_write=is_write,
            )

        event_id = make_event_id(self.config.source_tool, self.config.name, ctx.offset)

        try:
            source_tool_enum = SourceTool(self.config.source_tool)
        except ValueError:
            source_tool_enum = SourceTool.generic

        return [
            Event(
                event_id=event_id,
                ts=ts,
                ingested_at=datetime.now(UTC),
                source_tool=source_tool_enum,
                domain=domain,
                category=category,
                action=action,
                outcome=outcome,
                host=str(host) if host is not None else None,
                src_ip=str(src_ip) if src_ip is not None else None,
                dst_ip=str(dst_ip) if dst_ip is not None else None,
                src_port=int(src_port)
                if src_port is not None and str(src_port).isdigit()
                else None,
                dst_port=int(dst_port)
                if dst_port is not None and str(dst_port).isdigit()
                else None,
                protocol=str(protocol) if protocol is not None else None,
                user=str(user) if user is not None else None,
                process=str(process) if process is not None else None,
                parent_process=str(parent_process) if parent_process is not None else None,
                cmdline=str(cmdline) if cmdline is not None else None,
                session_id=str(session_id) if session_id is not None else None,
                ot=ot_fields,
                raw_ref={"file": str(ctx.file_path), "offset": ctx.offset},
                raw=record,
                tags=[f"mapping:{self.config.name}"],
            )
        ]

    def _parse_csv_line(self, line: str) -> dict[str, Any] | None:
        reader = csv.reader(io.StringIO(line), delimiter=self.config.delimiter)
        try:
            row = next(reader)
        except StopIteration:
            return None

        if not row:
            return None

        # Check if first line is header
        if self._csv_headers is None:
            # Treat this first line as the header
            self._csv_headers = [col.strip() for col in row]
            return None

        # Map row to dictionary
        record: dict[str, Any] = {}
        for idx, col_name in enumerate(self._csv_headers):
            val = row[idx].strip() if idx < len(row) else ""
            record[col_name] = val

        return record
