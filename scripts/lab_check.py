#!/usr/bin/env python3
"""SentinelX Lab Telemetry Verification Script (stdlib only, PASSIVE).

Verifies telemetry sources according to passive freshness rules:
- Active sources (Wazuh archives, Zeek IT conn, Zeek OT modbus, PLC sim state, Jump-host cmd.jsonl):
  PASS if last line age <= 60s.
- Decoy sources (Cowrie, OpenCanary, Zeek DMZ conn, Decoy PLC):
  PASS if file exists, is readable, and producing container is healthy/running ("idle-ok").
This script NEVER generates stimulus or network traffic.
"""

import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = REPO_ROOT / "data" / "logs"


def parse_timestamp(line: str) -> float | None:
    """Extract epoch timestamp from a log line or JSON record."""
    try:
        data = json.loads(line)
        ts_val = data.get("ts") or data.get("timestamp") or data.get("utc_time") or data.get("time")
        if isinstance(ts_val, (int, float)):
            return float(ts_val)
        if isinstance(ts_val, str):
            clean_ts = ts_val.replace("Z", "+00:00")
            if len(clean_ts) >= 5 and (clean_ts[-5] in ("+", "-")) and clean_ts[-3] != ":":
                clean_ts = clean_ts[:-2] + ":" + clean_ts[-2:]
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.timestamp()
    except Exception:
        pass
    return None


def get_last_line_from_docker(
    container: str, container_path: str
) -> tuple[str | None, float | None]:
    """Read last non-empty line via docker exec without generating traffic."""
    try:
        cmd = ["docker", "exec", container, "tail", "-n", "1", container_path]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            last_line = res.stdout.strip().splitlines()[-1]
            return last_line, time.time()
    except Exception:
        pass
    return None, None


def get_last_line_from_file(file_path: Path) -> tuple[str | None, float | None]:
    """Read last non-empty line and modification time from local file."""
    if not file_path.exists() or file_path.stat().st_size == 0:
        if "wazuh" in str(file_path):
            return get_last_line_from_docker(
                "sentinelx-wazuh-manager", "/var/ossec/logs/archives/archives.json"
            )
        return None, None

    mtime = file_path.stat().st_mtime
    last_line = None
    try:
        with open(file_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            buffer_size = min(8192, size)
            f.seek(size - buffer_size)
            lines = f.read().decode("utf-8", errors="replace").splitlines()
            for line in reversed(lines):
                if line.strip():
                    last_line = line.strip()
                    break
    except Exception:
        if "wazuh" in str(file_path):
            return get_last_line_from_docker(
                "sentinelx-wazuh-manager", "/var/ossec/logs/archives/archives.json"
            )

    return last_line, mtime


def get_container_health(container: str) -> tuple[bool, str]:
    """Check if the container is running and healthy."""
    try:
        res = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                container,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            status = res.stdout.strip()
            is_healthy = status in ("healthy", "running")
            return is_healthy, status
    except Exception as e:
        return False, str(e)
    return False, "unknown"


def check_source(
    name: str, ctype: str, path_or_target: str, is_decoy: bool = False, container: str = ""
) -> dict:
    now_epoch = datetime.now(UTC).timestamp()
    result = {
        "name": name,
        "target": path_or_target,
        "status": "FAIL",
        "age_sec": None,
        "detail": "",
    }

    last_line = None
    file_mtime = None

    if ctype == "file":
        p = Path(path_or_target)
        if not p.is_absolute():
            p = REPO_ROOT / path_or_target

        # Check file existence and readability
        if not p.exists():
            # Check for nested wazuh archives if applicable
            if "archives.json" in path_or_target:
                matches = list(p.parent.rglob("archives.json"))
                if matches:
                    p = matches[0]

        file_exists = p.exists()
        file_readable = os.access(p, os.R_OK) if file_exists else False

        if file_exists and file_readable:
            last_line, file_mtime = get_last_line_from_file(p)

        if is_decoy:
            c_healthy, c_status = get_container_health(container)
            if not file_exists or not file_readable:
                result["detail"] = (
                    f"File missing/unreadable ({p}), container {container}: {c_status}"
                )
                return result
            if not c_healthy:
                result["detail"] = f"Producing container {container} is {c_status}"
                return result

            # Decoy is idle-ok
            result["status"] = "PASS"
            if last_line:
                ts = parse_timestamp(last_line)
                age = (now_epoch - ts) if ts else (now_epoch - (file_mtime or now_epoch))
                result["age_sec"] = age
                result["detail"] = f"idle-ok (last line: {age:.1f}s ago)"
            else:
                result["detail"] = "idle-ok (0 events / empty file)"
            return result

        if not file_exists or not file_readable or last_line is None:
            result["detail"] = f"File not found, empty, or unreadable: {p}"
            return result

    elif ctype == "docker":
        parts = path_or_target.split(":", 1)
        cname = parts[0]
        cpath = parts[1]
        last_line, file_mtime = get_last_line_from_docker(cname, cpath)

        if is_decoy:
            c_healthy, c_status = get_container_health(cname)
            if c_healthy:
                result["status"] = "PASS"
                result["detail"] = f"idle-ok (container {cname}: {c_status})"
                return result
            result["detail"] = f"Container {cname} status: {c_status}"
            return result

        if last_line is None:
            result["detail"] = f"Failed to read from container {cname}:{cpath}"
            return result

    # Active source evaluation (must have line newer than 60s)
    record_ts = parse_timestamp(last_line) if last_line else None
    if record_ts is not None:
        age = now_epoch - record_ts
    elif file_mtime is not None:
        age = now_epoch - file_mtime
    else:
        age = 999999

    result["age_sec"] = age
    if 0 <= age <= 60:
        result["status"] = "PASS"
        result["detail"] = f"Last line {age:.1f}s ago"
    else:
        result["status"] = "FAIL"
        result["detail"] = f"Stale data: {age:.1f}s ago (threshold <= 60s)"

    return result


def main():
    # Active sources: must have line newer than 60s
    # Decoy sources: idle by design, PASS if file exists, readable, and container healthy
    sources = [
        (
            "Wazuh archives.json",
            "file",
            "data/logs/wazuh/archives.json",
            False,
            "sentinelx-wazuh-manager",
        ),
        ("Zeek IT conn.log", "file", "data/logs/zeek-it/conn.log", False, "sentinelx-zeek-it"),
        ("Zeek DMZ conn.log", "file", "data/logs/zeek-dmz/conn.log", True, "sentinelx-zeek-dmz"),
        ("Zeek OT modbus.log", "file", "data/logs/zeek-ot/modbus.log", False, "sentinelx-zeek-ot"),
        ("Cowrie cowrie.json", "file", "data/logs/cowrie/cowrie.json", True, "sentinelx-cowrie"),
        (
            "OpenCanary opencanary.log",
            "file",
            "data/logs/opencanary/opencanary.log",
            True,
            "sentinelx-opencanary",
        ),
        (
            "Decoy PLC decoy-plc.jsonl",
            "file",
            "data/logs/plc/decoy-plc.jsonl",
            True,
            "sentinelx-decoy-plc",
        ),
        (
            "PLC Sim plc-sim-state.jsonl",
            "file",
            "data/logs/plc/plc-sim-state.jsonl",
            False,
            "sentinelx-plc-sim",
        ),
        (
            "Jump-host cmd.jsonl (docker)",
            "docker",
            "sentinelx-jump-host:/var/log/sentinelx/cmd.jsonl",
            False,
            "sentinelx-jump-host",
        ),
    ]

    print("=" * 80)
    print("SentinelX Telemetry Freshness Check (Passive / Non-Intrusive)")
    print("=" * 80)

    all_passed = True
    results = []
    for name, ctype, target, is_decoy, container in sources:
        res = check_source(name, ctype, target, is_decoy=is_decoy, container=container)
        results.append(res)
        if res["status"] != "PASS":
            all_passed = False

    # Format table
    header = f"{'Source':<30} | {'Status':<6} | {'Age':<10} | {'Details'}"
    print(header)
    print("-" * len(header))
    for r in results:
        age_str = f"{r['age_sec']:.1f}s" if r["age_sec"] is not None else "N/A"
        print(f"{r['name']:<30} | {r['status']:<6} | {age_str:<10} | {r['detail']}")

    print("=" * 80)
    if all_passed:
        print("ALL TELEMETRY SOURCES: PASS")
        sys.exit(0)
    else:
        print("SOME TELEMETRY SOURCES FAILED FRESHNESS CHECK")
        sys.exit(1)


if __name__ == "__main__":
    main()
