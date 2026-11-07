#!/usr/bin/env python3
"""Export real sample telemetry logs for Phase 2 adapter development.

Ensures exported samples include diverse representative records:
- Wazuh archives: Accepted ssh, Failed ssh, cmd.jsonl execution, syscheck FIM
- Cowrie: login success (svc_dbadmin) and login failure
- OpenCanary: mysql login attempt (logtype 8001)
- Zeek: conn, modbus, dns
- PLC writes & cmd.jsonl
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "eval" / "captures" / "samples"
LOGS_DIR = REPO_ROOT / "data" / "logs"

SAMPLES_DIR.mkdir(parents=True, exist_ok=True)


def extract_samples(
    src_path: Path, dest_name: str, required_patterns: list[str] | None = None, max_lines: int = 20
):
    dest_path = SAMPLES_DIR / dest_name
    if not src_path.exists():
        matches = list(src_path.parent.rglob(src_path.name))
        if matches:
            src_path = matches[0]

    if not src_path.exists():
        print(f"Warning: Source log file {src_path} not found.")
        return False

    try:
        with open(src_path, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Warning: Could not read {src_path}: {e}")
        return False

    if not lines:
        print(f"Warning: No lines found in {src_path}.")
        return False

    selected = []
    if required_patterns:
        for pat in required_patterns:
            for item in reversed(lines):
                if pat in item and item not in selected:
                    selected.append(item)
                    break

    # Fill remainder with the most recent lines
    for item in reversed(lines):
        if len(selected) >= max_lines:
            break
        if item not in selected:
            selected.append(item)

    selected.reverse()
    with open(dest_path, "w", encoding="utf-8") as f:
        f.writelines(line + "\n" for line in selected)

    print(f"Exported {len(selected)} lines -> {dest_path.relative_to(REPO_ROOT)}")
    return True


def extract_samples_from_docker(
    container: str, container_path: str, dest_name: str, max_lines: int = 20
):
    dest_path = SAMPLES_DIR / dest_name
    try:
        cmd = ["docker", "exec", container, "tail", "-n", str(max_lines), container_path]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            lines = [ln.strip() for ln in res.stdout.strip().splitlines() if ln.strip()]
            with open(dest_path, "w", encoding="utf-8") as f:
                f.writelines(line + "\n" for line in lines)
            print(
                f"Exported {len(lines)} lines from {container} -> {dest_path.relative_to(REPO_ROOT)}"
            )
            return True
    except Exception as e:
        print(f"Warning: Failed to extract from {container}:{container_path}: {e}")
    return False


def main():
    print(f"Writing sample logs to {SAMPLES_DIR.relative_to(REPO_ROOT)}...")
    success = True

    # 1. Wazuh archives: include Accepted, Failed, cmd.jsonl, and syscheck
    wazuh_archives = LOGS_DIR / "wazuh" / "archives.json"
    wazuh_patterns = ["Accepted", "Failed", "sentinelx/cmd.jsonl", "syscheck"]
    if not extract_samples(
        wazuh_archives,
        "wazuh_archives.sample.jsonl",
        required_patterns=wazuh_patterns,
        max_lines=25,
    ):
        success = False

    # 2. Zeek conn (IT bridge)
    if not extract_samples(LOGS_DIR / "zeek-it" / "conn.log", "zeek_conn.sample.jsonl"):
        success = False

    # 3. Zeek modbus (OT bridge)
    modbus_patterns = ["WRITE_SINGLE_REGISTER", "WRITE_MULTIPLE_REGISTERS", "READ"]
    if not extract_samples(
        LOGS_DIR / "zeek-ot" / "modbus.log",
        "zeek_modbus.sample.jsonl",
        required_patterns=modbus_patterns,
        max_lines=25,
    ):
        success = False

    # 4. Zeek dns
    dns_file = LOGS_DIR / "zeek-it" / "dns.log"
    if not dns_file.exists():
        matches = list(LOGS_DIR.rglob("dns.log"))
        if matches:
            dns_file = matches[0]
    extract_samples(dns_file, "zeek_dns.sample.jsonl")

    # 5. Cowrie: include login success and failure
    cowrie_patterns = ["cowrie.login.success", "cowrie.login.failed"]
    if not extract_samples(
        LOGS_DIR / "cowrie" / "cowrie.json",
        "cowrie.sample.jsonl",
        required_patterns=cowrie_patterns,
        max_lines=20,
    ):
        success = False

    # 6. OpenCanary: include mysql login attempt (logtype 8001 or svc_dbadmin)
    canary_patterns = ["8001", "svc_dbadmin", "3001"]
    if not extract_samples(
        LOGS_DIR / "opencanary" / "opencanary.log",
        "opencanary.sample.jsonl",
        required_patterns=canary_patterns,
        max_lines=20,
    ):
        success = False

    # 7. PLC writes
    if not extract_samples(LOGS_DIR / "plc" / "plc-sim-writes.jsonl", "plc_writes.sample.jsonl"):
        success = False

    # 8. Command auditing cmd.jsonl from jump-host
    if not extract_samples_from_docker(
        "sentinelx-jump-host", "/var/log/sentinelx/cmd.jsonl", "cmd.sample.jsonl"
    ):
        success = False

    if success:
        print("All sample logs successfully generated!")
        sys.exit(0)
    else:
        print(
            "Some sample files could not be generated. Ensure lab is running and has generated traffic."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
