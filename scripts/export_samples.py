#!/usr/bin/env python3
"""Export real sample telemetry logs for Phase 2 adapter development."""

from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "eval" / "captures" / "samples"
LOGS_DIR = REPO_ROOT / "data" / "logs"

SAMPLES_DIR.mkdir(parents=True, exist_ok=True)


def extract_samples_from_file(src_path: Path, dest_name: str, max_lines: int = 20):
    dest_path = SAMPLES_DIR / dest_name
    if not src_path.exists():
        # Check if file exists recursively
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
        if "wazuh" in str(src_path):
            return extract_samples_from_docker("sentinelx-wazuh-manager", "/var/ossec/logs/archives/archives.json", dest_name, max_lines)
        print(f"Warning: Could not read {src_path}: {e}")
        return False

    sample_lines = lines[-max_lines:]
    if not sample_lines:
        print(f"Warning: No lines found in {src_path}.")
        return False

    with open(dest_path, "w", encoding="utf-8") as f:
        for line in sample_lines:
            f.write(line + "\n")

    print(f"Exported {len(sample_lines)} lines -> {dest_path.relative_to(REPO_ROOT)}")
    return True


def extract_samples_from_docker(container: str, container_path: str, dest_name: str, max_lines: int = 20):
    dest_path = SAMPLES_DIR / dest_name
    try:
        cmd = ["docker", "exec", container, "tail", "-n", str(max_lines), container_path]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            lines = [l.strip() for l in res.stdout.strip().splitlines() if l.strip()]
            with open(dest_path, "w", encoding="utf-8") as f:
                for line in lines:
                    f.write(line + "\n")
            print(f"Exported {len(lines)} lines from {container} -> {dest_path.relative_to(REPO_ROOT)}")
            return True
    except Exception as e:
        print(f"Warning: Failed to extract from {container}:{container_path}: {e}")
    return False


def main():
    print(f"Writing sample logs to {SAMPLES_DIR.relative_to(REPO_ROOT)}...")
    success = True

    # 1. Wazuh archives
    wazuh_archives = LOGS_DIR / "wazuh" / "archives.json"
    if not extract_samples_from_file(wazuh_archives, "wazuh_archives.sample.jsonl"):
        # Try finding archives.json recursively in wazuh logs
        matches = list((LOGS_DIR / "wazuh").rglob("*.json"))
        if matches:
            extract_samples_from_file(matches[0], "wazuh_archives.sample.jsonl")
        else:
            success = False

    # 2. Zeek conn (IT bridge)
    if not extract_samples_from_file(LOGS_DIR / "zeek-it" / "conn.log", "zeek_conn.sample.jsonl"):
        success = False

    # 3. Zeek modbus (OT bridge)
    if not extract_samples_from_file(LOGS_DIR / "zeek-ot" / "modbus.log", "zeek_modbus.sample.jsonl"):
        success = False

    # 4. Zeek dns
    dns_file = LOGS_DIR / "zeek-it" / "dns.log"
    if not dns_file.exists():
        # Check any zeek directory for dns.log
        matches = list(LOGS_DIR.rglob("dns.log"))
        if matches:
            dns_file = matches[0]
    extract_samples_from_file(dns_file, "zeek_dns.sample.jsonl")

    # 5. Cowrie
    if not extract_samples_from_file(LOGS_DIR / "cowrie" / "cowrie.json", "cowrie.sample.jsonl"):
        success = False

    # 6. OpenCanary
    if not extract_samples_from_file(LOGS_DIR / "opencanary" / "opencanary.log", "opencanary.sample.jsonl"):
        success = False

    # 7. PLC writes
    if not extract_samples_from_file(LOGS_DIR / "plc" / "plc-sim-writes.jsonl", "plc_writes.sample.jsonl"):
        success = False

    # 8. Command auditing cmd.jsonl from jump-host
    if not extract_samples_from_docker("sentinelx-jump-host", "/var/log/sentinelx/cmd.jsonl", "cmd.sample.jsonl"):
        success = False

    if success:
        print("All sample logs successfully generated!")
        sys.exit(0)
    else:
        print("Some sample files could not be generated. Ensure lab is running and has generated traffic.")
        sys.exit(1)


if __name__ == "__main__":
    main()

