#!/usr/bin/env python3
"""SentinelX Lab Telemetry Verification Script (stdlib only).

Verifies the 8 required telemetry sources for freshness (line age <= 60s).
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = REPO_ROOT / "data" / "logs"


def parse_timestamp(line: str) -> float | None:
    """Extract epoch timestamp from a log line or JSON record."""
    try:
        data = json.loads(line)
        # Check common timestamp keys
        ts_val = data.get("ts") or data.get("timestamp") or data.get("utc_time") or data.get("time")
        if isinstance(ts_val, (int, float)):
            return float(ts_val)
        if isinstance(ts_val, str):
            # Clean up ISO strings with +0000 -> +00:00 or trailing Z
            clean_ts = ts_val.replace("Z", "+00:00")
            if len(clean_ts) >= 5 and (clean_ts[-5] in ("+", "-")) and clean_ts[-3] != ":":
                clean_ts = clean_ts[:-2] + ":" + clean_ts[-2:]
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
    except Exception:
        pass
    return None


def get_last_line_from_docker(container: str, container_path: str) -> tuple[str | None, float | None]:
    """Read last non-empty line via docker exec."""
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
            return get_last_line_from_docker("sentinelx-wazuh-manager", "/var/ossec/logs/archives/archives.json")
        return None, None

    mtime = file_path.stat().st_mtime
    last_line = None
    try:
        with open(file_path, "rb") as f:
            # Efficient tail for large files
            f.seek(0, os.SEEK_END)
            size = f.tell()
            buffer_size = min(4096, size)
            f.seek(size - buffer_size)
            lines = f.read().decode("utf-8", errors="replace").splitlines()
            for line in reversed(lines):
                if line.strip():
                    last_line = line.strip()
                    break
    except Exception:
        if "wazuh" in str(file_path):
            return get_last_line_from_docker("sentinelx-wazuh-manager", "/var/ossec/logs/archives/archives.json")

    return last_line, mtime


def probe_source_if_needed(name: str):
    """Trigger a stimulus to verify live telemetry ingestion if a decoy or bridge source is currently idle."""
    try:
        if "Zeek DMZ" in name:
            subprocess.run(
                ["docker", "exec", "sentinelx-jump-host", "mariadb", "-h", "10.10.2.30",
                 "-u", "root", "--connect-timeout=2", "-e", "SHOW DATABASES;"],
                capture_output=True, timeout=5
            )
        elif "Cowrie" in name:
            subprocess.run(
                ["docker", "exec", "sentinelx-jump-host", "sshpass", "-p", "Winter2026!",
                 "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3",
                 "-p", "22", "svc_dbadmin@10.10.2.20", "whoami"],
                capture_output=True, timeout=5
            )
        elif "OpenCanary" in name:
            subprocess.run(
                ["docker", "exec", "sentinelx-jump-host", "mariadb", "-h", "10.10.2.30",
                 "-u", "root", "--connect-timeout=3", "-e", "SHOW DATABASES;"],
                capture_output=True, timeout=5
            )
        elif "Jump-host" in name:
            subprocess.run(
                ["docker", "exec", "sentinelx-attacker", "sshpass", "-p", "Backup2024!",
                 "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3",
                 "svc_backup@10.10.1.10", "uptime"],
                capture_output=True, timeout=5
            )
        elif "Zeek OT" in name:
            subprocess.run(
                ["docker", "exec", "sentinelx-eng-ws", "/usr/local/bin/read_plc.py", "10.10.3.20", "502", "1"],
                capture_output=True, timeout=5
            )
        elif "Zeek IT" in name:
            subprocess.run(
                ["docker", "exec", "sentinelx-benign", "su", "-", "alice", "-c",
                 "ssh -o StrictHostKeyChecking=no alice@10.10.1.20 'uptime'"],
                capture_output=True, timeout=5
            )
    except Exception:
        pass


def check_source(name: str, check_type: str, path_or_target: str, allow_probe: bool = True) -> dict:
    now_epoch = datetime.now(timezone.utc).timestamp()
    result = {
        "name": name,
        "target": path_or_target,
        "status": "FAIL",
        "age_sec": None,
        "detail": "",
    }

    last_line = None
    file_mtime = None

    if check_type == "file":
        p = Path(path_or_target)
        if not p.is_absolute():
            p = REPO_ROOT / path_or_target
        last_line, file_mtime = get_last_line_from_file(p)
        if last_line is None:
            # Check if file exists in a nested structure (e.g., wazuh archives)
            if "archives.json" in path_or_target:
                wazuh_dir = p.parent
                matches = list(wazuh_dir.rglob("archives.json"))
                if matches:
                    last_line, file_mtime = get_last_line_from_file(matches[0])
                    p = matches[0]

        if last_line is None and allow_probe:
            probe_source_if_needed(name)
            time.sleep(2.5)
            return check_source(name, check_type, path_or_target, allow_probe=False)

        if last_line is None:
            result["detail"] = f"File not found or empty: {p}"
            return result
    elif check_type == "docker":
        parts = path_or_target.split(":", 1)
        container = parts[0]
        cpath = parts[1]
        last_line, file_mtime = get_last_line_from_docker(container, cpath)

        if last_line is None and allow_probe:
            probe_source_if_needed(name)
            time.sleep(2.5)
            return check_source(name, check_type, path_or_target, allow_probe=False)

        if last_line is None:
            result["detail"] = f"Failed to read from container {container}:{cpath}"
            return result

    # Compute age
    record_ts = parse_timestamp(last_line) if last_line else None
    if record_ts is not None:
        age = now_epoch - record_ts
    elif file_mtime is not None:
        age = now_epoch - file_mtime
    else:
        age = 999999

    if age > 60 and allow_probe:
        probe_source_if_needed(name)
        time.sleep(2.5)
        return check_source(name, check_type, path_or_target, allow_probe=False)

    result["age_sec"] = age
    if 0 <= age <= 60:
        result["status"] = "PASS"
        result["detail"] = f"Last line {age:.1f}s ago"
    else:
        result["status"] = "FAIL"
        result["detail"] = f"Stale data: {age:.1f}s ago (threshold <= 60s)"

    return result


def main():
    sources = [
        ("Wazuh archives.json", "file", "data/logs/wazuh/archives.json"),
        ("Zeek IT conn.log", "file", "data/logs/zeek-it/conn.log"),
        ("Zeek DMZ conn.log", "file", "data/logs/zeek-dmz/conn.log"),
        ("Zeek OT modbus.log", "file", "data/logs/zeek-ot/modbus.log"),
        ("Cowrie cowrie.json", "file", "data/logs/cowrie/cowrie.json"),
        ("OpenCanary opencanary.log", "file", "data/logs/opencanary/opencanary.log"),
        ("PLC Sim plc-sim-state.jsonl", "file", "data/logs/plc/plc-sim-state.jsonl"),
        ("Jump-host cmd.jsonl (docker)", "docker", "sentinelx-jump-host:/var/log/sentinelx/cmd.jsonl"),
    ]

    print("=" * 80)
    print("SentinelX Telemetry Freshness Check (Threshold <= 60s)")
    print("=" * 80)

    all_passed = True
    results = []
    for name, ctype, target in sources:
        res = check_source(name, ctype, target)
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
        print("ALL 8 TELEMETRY SOURCES: PASS")
        sys.exit(0)
    else:
        print("SOME TELEMETRY SOURCES FAILED FRESHNESS CHECK")
        sys.exit(1)


if __name__ == "__main__":
    main()

