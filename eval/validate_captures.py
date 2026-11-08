#!/usr/bin/env python3
"""SentinelX Capture Validation Tooling.

Replays telemetry capture directories through Phase 2's Ingestor into isolated
scratch SQLite databases and enforces strict validation checks:
- Zero adapter crashes and zero unparsed lines.
- Complete domain & category breakdown.
- BENIGN CAPTURES: Hard-negative guarantee (0 decoy events, 0 honey_user tags, 0 honey_file tags).
- ATTACK CAPTURES: Proof of honey_user, ot.is_write=true, cross_zone tags, and per-step log evidence.
"""

import argparse
import asyncio
import json
import logging
import sqlite3
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.ingest.runtime import Ingestor  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("validate_captures")

CAPTURES_DIR = REPO_ROOT / "eval" / "captures"


async def replay_capture_to_scratch(capture_dir: Path, scratch_db_path: Path) -> dict[str, Any]:
    """Replay capture files into an isolated scratch database at max speed."""
    if scratch_db_path.exists():
        scratch_db_path.unlink()
    for extra in (f"{scratch_db_path}-wal", f"{scratch_db_path}-shm"):
        p = Path(extra)
        if p.exists():
            p.unlink()

    ingestor = Ingestor(
        log_root=capture_dir,
        db=scratch_db_path,
        mode="replay",
        speed="max",
    )
    await ingestor.start()

    # Wait for replay completion
    while ingestor._tasks and not all(t.done() for t in ingestor._tasks):
        await asyncio.sleep(0.05)
    await ingestor.stop()

    # Gather metrics
    total_lines = sum(m.lines_read for m in ingestor.metrics.values())
    total_emitted = sum(m.events_emitted for m in ingestor.metrics.values())
    total_unparsed = sum(m.unparsed for m in ingestor.metrics.values())
    total_errors = sum(m.errors for m in ingestor.metrics.values())

    return {
        "lines_read": total_lines,
        "events_emitted": total_emitted,
        "unparsed": total_unparsed,
        "errors": total_errors,
    }


def validate_capture(capture_dir: Path) -> bool:
    """Validate a single capture directory."""
    manifest_path = capture_dir / "manifest.json"
    if not manifest_path.is_file():
        logger.error(f"Missing manifest.json in {capture_dir}")
        return False

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    category = manifest.get("category", "")
    name = manifest.get("name", capture_dir.name)
    scratch_db = REPO_ROOT / "data" / f"scratch_val_{category}_{name}.db"

    print("\n" + "=" * 80)
    print(f"VALIDATING CAPTURE: {category.upper()}/{name}")
    print(f"Directory: {capture_dir}")
    print(f"Manifest : {manifest_path}")
    print("=" * 80)

    try:
        metrics = asyncio.run(replay_capture_to_scratch(capture_dir, scratch_db))
    except Exception as exc:
        logger.error(f"Replay ingestion failed on {capture_dir}: {exc}", exc_info=True)
        return False

    conn = sqlite3.connect(scratch_db)

    # 1. Pipeline Execution Health
    total_db_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print("\n--- 1. Ingestion Pipeline Health ---")
    print(f"Total Lines Read   : {metrics['lines_read']}")
    print(f"Events Emitted     : {metrics['events_emitted']}")
    print(f"Events in SQLite   : {total_db_events}")
    print(f"Unparsed Lines     : {metrics['unparsed']}")
    print(f"Adapter Errors     : {metrics['errors']}")

    if metrics["errors"] > 0 or metrics["unparsed"] > 0:
        print("[FAIL] Ingestion encountered unparsed rows or adapter errors!")
        conn.close()
        return False

    # 2. Domain & Category Breakdown
    print("\n--- 2. Telemetry Breakdown ---")
    domains = conn.execute(
        "SELECT domain, COUNT(*) FROM events GROUP BY domain ORDER BY COUNT(*) DESC"
    ).fetchall()
    print("By Domain:")
    for dom, cnt in domains:
        print(f"  {dom:<10}: {cnt}")

    categories = conn.execute(
        "SELECT category, COUNT(*) FROM events GROUP BY category ORDER BY COUNT(*) DESC"
    ).fetchall()
    print("By Category:")
    for cat, cnt in categories:
        print(f"  {cat:<18}: {cnt}")

    # 3. Category-Specific Semantic Guarantees
    all_passed = True
    if category == "benign":
        print("\n--- 3. Benign Hard-Negative Verification ---")
        # Prove ZERO decoy domain events
        decoy_cnt = conn.execute("SELECT COUNT(*) FROM events WHERE domain = 'decoy'").fetchone()[0]
        print("Query: SELECT COUNT(*) FROM events WHERE domain = 'decoy'")
        print(f"  --> Result: {decoy_cnt} (Requirement: EXACTLY 0)")
        if decoy_cnt != 0:
            print("  [FAIL] Hard-negative violation: benign capture touched decoy domain!")
            all_passed = False
        else:
            print("  [PASS] Zero decoy domain events.")

        # Prove ZERO honey_user tags
        honey_user_cnt = conn.execute(
            "SELECT COUNT(*) FROM events WHERE json_extract(json, '$.tags') LIKE '%honey_user%'"
        ).fetchone()[0]
        print("Query: SELECT COUNT(*) FROM events WHERE tags LIKE '%honey_user%'")
        print(f"  --> Result: {honey_user_cnt} (Requirement: EXACTLY 0)")
        if honey_user_cnt != 0:
            print("  [FAIL] Hard-negative violation: benign capture generated honey_user tag!")
            all_passed = False
        else:
            print("  [PASS] Zero honey_user tags.")

        # Prove ZERO honey_file tags
        honey_file_cnt = conn.execute(
            "SELECT COUNT(*) FROM events WHERE json_extract(json, '$.tags') LIKE '%honey_file%'"
        ).fetchone()[0]
        print("Query: SELECT COUNT(*) FROM events WHERE tags LIKE '%honey_file%'")
        print(f"  --> Result: {honey_file_cnt} (Requirement: EXACTLY 0)")
        if honey_file_cnt != 0:
            print("  [FAIL] Hard-negative violation: benign capture touched honey file!")
            all_passed = False
        else:
            print("  [PASS] Zero honey_file tags.")

    elif category == "attack":
        print("\n--- 3. Attack Scenario Semantic Verification ---")
        # Prove honey_user tag exists
        honey_cnt = conn.execute(
            "SELECT COUNT(*) FROM events WHERE json_extract(json, '$.tags') LIKE '%honey_user%'"
        ).fetchone()[0]
        print(f"Honey User Tags (svc_dbadmin): {honey_cnt} (Expected: >= 1)")
        if honey_cnt < 1:
            print("  [FAIL] Attack capture missing honey_user tag!")
            all_passed = False
        else:
            print("  [PASS] Found honey_user tagged events.")

        # Prove OT write exists
        ot_write_cnt = conn.execute(
            "SELECT COUNT(*) FROM events WHERE json_extract(json, '$.ot.is_write') = 1"
        ).fetchone()[0]
        print(f"Modbus Physical Writes (ot.is_write=true): {ot_write_cnt} (Expected: >= 1)")
        if ot_write_cnt < 1:
            print("  [FAIL] Attack capture missing Modbus write events!")
            all_passed = False
        else:
            print("  [PASS] Found ot.is_write=true events.")

        # Prove Cross-Zone tags exist
        cross_cnt = conn.execute(
            "SELECT COUNT(*) FROM events WHERE json_extract(json, '$.tags') LIKE '%cross_zone%'"
        ).fetchone()[0]
        print(f"Cross-Zone Tagged Events: {cross_cnt} (Expected: >= 1)")
        if cross_cnt < 1:
            print("  [FAIL] Attack capture missing cross_zone tagged events!")
            all_passed = False
        else:
            print("  [PASS] Found cross_zone tagged events.")

        # Step-by-Step Scenario Evidence Proofs
        print("\n--- 4. Kill Chain Step-by-Step Evidence ---")
        # Step 1: Jump host initial access
        step1_ev = conn.execute(
            "SELECT event_id, json_extract(json, '$.action'), json_extract(json, '$.host') "
            "FROM events WHERE source_tool = 'wazuh' AND category = 'authentication' "
            "AND json_extract(json, '$.user') = 'svc_backup'"
        ).fetchone()
        print(f"  Step 1 (Initial Access / svc_backup) : {step1_ev or 'NOT FOUND'}")
        if not step1_ev:
            all_passed = False

        # Step 2: Discovery
        step2_ev = conn.execute(
            "SELECT event_id, json_extract(json, '$.action'), json_extract(json, '$.src_ip'), json_extract(json, '$.dst_ip') "
            "FROM events WHERE source_tool = 'zeek' AND category = 'network' "
            "AND json_extract(json, '$.dst_ip') LIKE '10.10.1.%'"
        ).fetchone()
        print(f"  Step 2 (IT Subnet Discovery Scan)    : {step2_ev or 'NOT FOUND'}")
        if not step2_ev:
            all_passed = False

        # Step 3: Credential theft
        step3_ev = conn.execute(
            "SELECT event_id, json_extract(json, '$.action'), json_extract(json, '$.cmdline') "
            "FROM events WHERE category = 'process' "
            "AND json_extract(json, '$.cmdline') LIKE '%.db_creds%'"
        ).fetchone()
        print(f"  Step 3 (Credential Theft / .db_creds): {step3_ev or 'NOT FOUND'}")
        if not step3_ev:
            all_passed = False

        # Step 4: Cowrie + OpenCanary Decoy Pivot
        step4_cowrie = conn.execute(
            "SELECT event_id, json_extract(json, '$.action'), json_extract(json, '$.host') "
            "FROM events WHERE source_tool = 'cowrie' AND json_extract(json, '$.user') = 'svc_dbadmin'"
        ).fetchone()
        step4_canary = conn.execute(
            "SELECT event_id, json_extract(json, '$.action'), json_extract(json, '$.host') "
            "FROM events WHERE source_tool = 'opencanary' AND json_extract(json, '$.user') = 'svc_dbadmin'"
        ).fetchone()
        print(f"  Step 4 (Cowrie SSH Decoy Pivot)      : {step4_cowrie or 'NOT FOUND'}")
        print(f"  Step 4 (OpenCanary MySQL Decoy Pivot): {step4_canary or 'NOT FOUND'}")
        if not step4_cowrie or not step4_canary:
            all_passed = False

        # Step 5: Lateral movement to eng-ws
        step5_ev = conn.execute(
            "SELECT event_id, json_extract(json, '$.action'), json_extract(json, '$.host'), json_extract(json, '$.dst_ip') "
            "FROM events WHERE json_extract(json, '$.host') = 'eng-ws' AND json_extract(json, '$.user') = 'svc_backup'"
        ).fetchone()
        print(f"  Step 5 (Lateral Move to eng-ws)      : {step5_ev or 'NOT FOUND'}")
        if not step5_ev:
            all_passed = False

        # Step 6: OT manipulation
        step6_ev = conn.execute(
            "SELECT event_id, json_extract(json, '$.action'), json_extract(json, '$.host'), "
            "json_extract(json, '$.ot.register'), json_extract(json, '$.ot.value') "
            "FROM events WHERE source_tool = 'modbus' "
            "AND json_extract(json, '$.ot.register') = 1 AND json_extract(json, '$.ot.value') = 0"
        ).fetchone()
        print(f"  Step 6 (Modbus Valve Manipulation)   : {step6_ev or 'NOT FOUND'}")
        if not step6_ev:
            all_passed = False

        # Step 7: Decoy PLC read
        step7_ev = conn.execute(
            "SELECT event_id, json_extract(json, '$.action'), json_extract(json, '$.host'), json_extract(json, '$.dst_ip') "
            "FROM events WHERE domain = 'decoy' AND json_extract(json, '$.host') = 'decoy-plc'"
        ).fetchone()
        print(f"  Step 7 (Decoy PLC Reconnaissance)    : {step7_ev or 'NOT FOUND'}")
        if not step7_ev:
            all_passed = False

    conn.close()

    # Clean up scratch DB
    if scratch_db.exists():
        scratch_db.unlink()
    for extra in (f"{scratch_db}-wal", f"{scratch_db}-shm"):
        p = Path(extra)
        if p.exists():
            p.unlink()

    status_str = "[PASS]" if all_passed else "[FAIL]"
    print(f"\n--> Capture {category}/{name} Validation Result: {status_str}\n")
    return all_passed


def main():
    parser = argparse.ArgumentParser(description="SentinelX Capture Validation Tooling")
    parser.add_argument("--capture", default=None, help="Path to single capture directory")
    args = parser.parse_args()

    if args.capture:
        target = Path(args.capture)
        if not target.is_dir():
            print(f"Error: Directory not found: {target}", file=sys.stderr)
            sys.exit(1)
        ok = validate_capture(target)
        sys.exit(0 if ok else 1)

    # Validate all captures under eval/captures
    targets = []
    for cat in ("benign", "attack"):
        cat_dir = CAPTURES_DIR / cat
        if cat_dir.is_dir():
            for item in sorted(cat_dir.iterdir()):
                if item.is_dir() and (item / "manifest.json").is_file():
                    targets.append(item)

    if not targets:
        print("No captures with manifest.json found under eval/captures/", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(targets)} capture bundles to validate:")
    for t in targets:
        print(f"  - {t.relative_to(CAPTURES_DIR)}")

    results = {}
    for t in targets:
        results[str(t.relative_to(CAPTURES_DIR))] = validate_capture(t)

    print("\n" + "=" * 80)
    print("ALL CAPTURE VALIDATIONS SUMMARY")
    print("=" * 80)
    for name, res in results.items():
        print(f"  {name:<35}: {'PASS' if res else 'FAIL'}")

    all_ok = all(results.values())
    print("=" * 80)
    print(f"Final Status: {'ALL PASSED' if all_ok else 'SOME FAILED'}\n")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
