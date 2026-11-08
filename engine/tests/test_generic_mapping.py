"""Tests for GenericMappingAdapter with declarative YAML mappings and fixtures."""

from pathlib import Path

import pytest
from sentinelx.ingest.adapters.generic import (
    GenericMappingAdapter,
    GenericMappingConfig,
)
from sentinelx.ingest.tailer import SourceContext
from sentinelx.normalize.enricher import EventEnricher

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
MAPPINGS_DIR = Path(__file__).resolve().parent.parent.parent / "content" / "mappings"


def test_windows_security_mapping():
    mapping_path = MAPPINGS_DIR / "windows_security.yaml"
    fixture_path = FIXTURES_DIR / "windows_security_sample.jsonl"
    assert mapping_path.exists()
    assert fixture_path.exists()

    cfg = GenericMappingConfig.load(mapping_path)
    adapter = GenericMappingAdapter(cfg)
    enricher = EventEnricher()
    ctx = SourceContext("win_sec", "evtx", fixture_path, 0)

    events = []
    with open(fixture_path, "r", encoding="utf-8") as f:
        for offset, line in enumerate(f):
            ctx.offset = offset
            evs = adapter.parse(line.strip(), ctx)
            if evs:
                for ev in evs:
                    events.append(enricher.enrich(ev))

    assert len(events) == 7
    # Verify logon_success
    logon_ok = next(e for e in events if e.action == "logon_success")
    assert logon_ok.user == "Administrator"
    assert logon_ok.host == "WIN-DC01"
    assert logon_ok.src_ip == "10.10.1.5"
    assert logon_ok.src_port == 49152

    # Verify process_creation
    proc = next(e for e in events if e.action == "process_creation")
    assert proc.category == "process"
    assert proc.user == "Administrator"


def test_modbus_csv_mapping():
    mapping_path = MAPPINGS_DIR / "modbus_csv.yaml"
    fixture_path = FIXTURES_DIR / "modbus_sample.csv"
    assert mapping_path.exists()
    assert fixture_path.exists()

    cfg = GenericMappingConfig.load(mapping_path)
    adapter = GenericMappingAdapter(cfg)
    enricher = EventEnricher()
    ctx = SourceContext("modbus_csv", "modbus", fixture_path, 0)

    events = []
    with open(fixture_path, "r", encoding="utf-8") as f:
        for offset, line in enumerate(f):
            ctx.offset = offset
            evs = adapter.parse(line.strip(), ctx)
            if evs:
                for ev in evs:
                    events.append(enricher.enrich(ev))

    # Header is ignored; 2 data rows parsed
    assert len(events) == 2
    write_ev = next(e for e in events if e.action == "modbus_write")
    assert write_ev.domain.value == "ot"
    assert write_ev.ot is not None
    assert write_ev.ot.register == 1
    assert write_ev.ot.is_write is True
    assert "cross_zone:it->ot" in (write_ev.tags or [])


def test_malformed_rows_resilience():
    # 1. Malformed JSON row
    cfg_json = GenericMappingConfig.load(MAPPINGS_DIR / "windows_security.yaml")
    adapter_json = GenericMappingAdapter(cfg_json)
    ctx_json = SourceContext("win_sec", "evtx", Path("test.json"), 0)

    malformed_json_line = "{ corrupt_json: true, missing_quotes }"
    with pytest.raises(ValueError, match="Invalid JSON line"):
        adapter_json.parse(malformed_json_line, ctx_json)

    # 2. Malformed CSV row (truncated columns)
    cfg_csv = GenericMappingConfig.load(MAPPINGS_DIR / "modbus_csv.yaml")
    adapter_csv = GenericMappingAdapter(cfg_csv)
    ctx_csv = SourceContext("modbus_csv", "modbus", Path("test.csv"), 0)

    # Header line initializes CSV headers
    adapter_csv.parse(
        "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,unit_id,function_code,register,value,is_write",
        ctx_csv,
    )

    # Truncated data row with fewer columns than headers
    malformed_csv_line = "2026-11-07T12:00:00Z,10.10.1.40"
    # Adapter safely fills missing fields with None instead of crashing
    evs = adapter_csv.parse(malformed_csv_line, ctx_csv)
    assert evs is not None
    assert len(evs) == 1
    assert evs[0].src_ip == "10.10.1.40"
    assert not evs[0].dst_ip


def test_windows_security_malformed_fixture_survival():
    """Verify that ingest-file processing survives malformed rows in windows fixture."""
    mapping_path = MAPPINGS_DIR / "windows_security.yaml"
    fixture_path = FIXTURES_DIR / "windows_security_malformed.jsonl"
    assert fixture_path.exists()

    cfg = GenericMappingConfig.load(mapping_path)
    adapter = GenericMappingAdapter(cfg)
    enricher = EventEnricher()
    ctx = SourceContext("win_sec", "evtx", fixture_path, 0)

    events = []
    unparsed_count = 0

    with open(fixture_path, "r", encoding="utf-8") as f:
        for offset, line in enumerate(f):
            ctx.offset = offset
            try:
                evs = adapter.parse(line.strip(), ctx)
                if evs:
                    for ev in evs:
                        events.append(enricher.enrich(ev))
            except Exception:
                unparsed_count += 1

    assert len(events) == 7
    assert unparsed_count == 1
