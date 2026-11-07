#!/usr/bin/env python3
"""CLI utility to ingest arbitrary JSON or CSV telemetry files using a YAML mapping."""

import argparse
import json
import sys
from pathlib import Path

from sentinelx.ingest.adapters.generic import (
    GenericMappingAdapter,
    GenericMappingConfig,
)
from sentinelx.ingest.tailer import SourceContext
from sentinelx.normalize.enricher import EventEnricher


def ingest_file(file_path: Path, mapping_path: Path) -> None:
    if not file_path.is_file():
        print(f"ERROR: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)
    if not mapping_path.is_file():
        # Check in content/mappings
        cand = Path(__file__).resolve().parent.parent / "content" / "mappings" / mapping_path.name
        if cand.is_file():
            mapping_path = cand
        else:
            print(f"ERROR: Mapping not found: {mapping_path}", file=sys.stderr)
            sys.exit(1)

    cfg = GenericMappingConfig.load(mapping_path)
    adapter = GenericMappingAdapter(cfg)
    enricher = EventEnricher()

    ctx = SourceContext(
        source_key=cfg.name,
        source_tool=cfg.source_tool,
        file_path=file_path,
        offset=0,
    )

    parsed_events = []
    unparsed_lines = 0
    ignored_lines = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        offset = 0
        line_no = 0
        for line in f:
            ctx.offset = offset
            ctx.line_number = line_no
            offset += len(line.encode("utf-8"))
            line_no += 1

            if not line.strip():
                continue

            try:
                evs = adapter.parse(line, ctx)
                if evs is None:
                    ignored_lines += 1
                else:
                    for ev in evs:
                        enriched = enricher.enrich(ev)
                        parsed_events.append(enriched)
            except Exception as e:
                unparsed_lines += 1
                print(
                    f"[WARN] Survived unparsed row {line_no}: {e}",
                    file=sys.stderr,
                )

    print(f"Successfully parsed {len(parsed_events)} events from {file_path}")
    print(f"Ignored: {ignored_lines} lines | Unparsed: {unparsed_lines} lines")

    if parsed_events:
        print("\n--- Sample Normalized Event ---")
        sample = parsed_events[0]
        print(json.dumps(sample.model_dump(mode="json"), indent=2))


def main():
    parser = argparse.ArgumentParser(description="Ingest files via generic mapping.")
    parser.add_argument("file", help="Path to input log/CSV file")
    parser.add_argument("mapping", help="Path or name of YAML mapping file")
    args = parser.parse_args()

    ingest_file(Path(args.file), Path(args.mapping))


if __name__ == "__main__":
    main()
