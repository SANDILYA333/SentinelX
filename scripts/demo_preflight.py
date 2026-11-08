#!/usr/bin/env python3
"""SentinelX Live Demo Preflight Readiness & Health Check.

Verifies all seven prerequisites for a smooth live demonstration:
1. Docker Lab containers healthy (jump-host, file-srv, db-srv, eng-ws, plc-sim, cowrie, opencanary, decoy-plc, wazuh-manager)
2. Host storage safety (>= 15 GB free disk space)
3. API server reachable (GET /health)
4. Telemetry sources healthy (GET /api/v1/sources/health)
5. PLC simulator state normal (tank level, flag == 'normal', emergency_stop == false)
6. Clean incident state (GET /api/v1/incidents count == 0)
7. Budget controller calibrated (GET /api/v1/budget threshold configured)
"""

import argparse
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

# Terminal ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def check_disk_space(min_gb: float = 15.0) -> tuple[bool, str]:
    """Check free disk space on root filesystem."""
    try:
        total, used, free = shutil.disk_usage("/")
        free_gb = free / (1024**3)
        if free_gb >= min_gb:
            return True, f"Free space: {free_gb:.1f} GB (>= {min_gb} GB required)"
        return (
            False,
            f"Free space: {free_gb:.1f} GB is under required {min_gb} GB! Run 'make lab-prune'",
        )
    except Exception as e:
        return False, f"Failed to check disk space: {e}"


def check_lab_containers() -> tuple[bool, str]:
    """Verify core lab and decoy containers are running and healthy."""
    target_services = [
        ("jump-host", "sentinelx-jump-host"),
        ("file-srv", "sentinelx-file-srv"),
        ("db-srv", "sentinelx-db-srv"),
        ("eng-ws", "sentinelx-eng-ws"),
        ("plc-sim", "sentinelx-plc-sim"),
        ("cowrie", "sentinelx-cowrie"),
        ("opencanary", "sentinelx-opencanary"),
        ("decoy-plc", "sentinelx-decoy-plc"),
        ("wazuh-manager", "sentinelx-wazuh-manager"),
    ]
    try:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                "lab/compose.yml",
                "ps",
                "--format",
                "{{.Service}}\t{{.Status}}\t{{.Health}}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return False, f"Docker compose command failed: {proc.stderr.strip()}"

        lines = [line.strip() for line in proc.stdout.strip().split("\n") if line.strip()]
        services_status: dict[str, tuple[str, str]] = {}
        for line in lines:
            parts = line.split("\t")
            srv = parts[0]
            status = parts[1] if len(parts) > 1 else ""
            health = parts[2] if len(parts) > 2 else ""
            services_status[srv] = (status, health)

        missing_or_bad = []
        for srv_name, _ in target_services:
            if srv_name not in services_status:
                missing_or_bad.append(f"{srv_name} (NOT RUNNING)")
            else:
                st, hl = services_status[srv_name]
                if "Up" not in st:
                    missing_or_bad.append(f"{srv_name} (Status: {st})")
                elif hl and hl.lower() not in ("healthy", ""):
                    missing_or_bad.append(f"{srv_name} (Health: {hl})")

        if missing_or_bad:
            return False, f"Unhealthy services: {', '.join(missing_or_bad)}. Run 'make lab-up'"
        return True, f"All {len(target_services)} monitored lab services are UP and healthy"
    except Exception as e:
        return False, f"Docker inspection error: {e}"


def check_api_health(api_url: str = "http://localhost:8000") -> tuple[bool, str]:
    """Check if FastAPI backend is responsive."""
    try:
        req = urllib.request.Request(
            f"{api_url}/health", headers={"User-Agent": "SentinelX-Preflight"}
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                return True, f"API responsive on {api_url} (status: {data.get('status', 'ok')})"
            return False, f"API returned HTTP {resp.status}"
    except urllib.error.URLError as e:
        return (
            False,
            f"API unreachable at {api_url}: {e.reason}. Run 'make ingest-live' or 'make api'",
        )
    except Exception as e:
        return False, f"API health check error: {e}"


def check_sources_health(api_url: str = "http://localhost:8000") -> tuple[bool, str]:
    """Check telemetry ingestion sources health."""
    try:
        req = urllib.request.Request(
            f"{api_url}/api/v1/sources/health", headers={"User-Agent": "SentinelX-Preflight"}
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            if resp.status == 200:
                sources = json.loads(resp.read().decode())
                if isinstance(sources, list) and len(sources) >= 5:
                    source_tools = {s.get("source_tool") for s in sources}
                    return (
                        True,
                        f"{len(sources)} telemetry adapters registered ({', '.join(sorted(filter(None, source_tools)))})",
                    )
                return (
                    False,
                    f"Expected >= 5 sources, got {len(sources) if isinstance(sources, list) else 0}",
                )
            return False, f"Sources health returned HTTP {resp.status}"
    except Exception as e:
        return False, f"Could not query source health: {e}"


def check_plc_state() -> tuple[bool, str]:
    """Check that PLC simulator is running with normal physical parameters."""
    state_json = None
    # 1. Try local host port 8080 if forwarded
    try:
        req = urllib.request.Request(
            "http://localhost:8080/state", headers={"User-Agent": "SentinelX-Preflight"}
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            if resp.status == 200:
                state_json = json.loads(resp.read().decode())
    except Exception:
        pass

    # 2. Try through docker exec on sentinelx-eng-ws
    if not state_json:
        try:
            res = subprocess.run(
                [
                    "docker",
                    "exec",
                    "sentinelx-eng-ws",
                    "curl",
                    "-s",
                    "http://10.10.3.20:8080/state",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout.strip():
                state_json = json.loads(res.stdout.strip())
        except Exception:
            pass

    # 3. Try through docker exec on sentinelx-plc-sim
    if not state_json:
        try:
            res = subprocess.run(
                [
                    "docker",
                    "exec",
                    "sentinelx-plc-sim",
                    "python3",
                    "-c",
                    'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8080/state").read().decode())',
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout.strip():
                state_json = json.loads(res.stdout.strip())
        except Exception:
            pass

    if not state_json:
        return (
            False,
            "Could not contact PLC simulator at 10.10.3.20:8080. Check 'sentinelx-plc-sim' container.",
        )

    flag = state_json.get("flag", "unknown")
    tank_level = state_json.get("tank_level_pct", 0.0)
    estop = state_json.get("emergency_stop", False)

    if flag != "normal" or estop:
        return (
            False,
            f"PLC not in baseline state: flag={flag}, level={tank_level}%, estop={estop}. Run 'make plc-reset'",
        )
    return True, f"PLC state NORMAL: tank_level={tank_level:.1f}%, flag={flag}, estop={estop}"


def check_incident_count(api_url: str = "http://localhost:8000") -> tuple[bool, str]:
    """Ensure clean incident slate for live demonstration."""
    try:
        req = urllib.request.Request(
            f"{api_url}/api/v1/incidents", headers={"User-Agent": "SentinelX-Preflight"}
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            if resp.status == 200:
                incidents = json.loads(resp.read().decode())
                count = len(incidents)
                if count == 0:
                    return True, "Incident store is clean (0 active incidents)"
                return (
                    False,
                    f"Found {count} existing incidents in DB! Run 'make demo-reset' to start fresh.",
                )
            return False, f"Incidents endpoint returned HTTP {resp.status}"
    except Exception as e:
        return False, f"Could not query incidents: {e}"


def check_budget_calibrated(api_url: str = "http://localhost:8000") -> tuple[bool, str]:
    """Verify budget threshold is calibrated."""
    try:
        req = urllib.request.Request(
            f"{api_url}/api/v1/budget", headers={"User-Agent": "SentinelX-Preflight"}
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            if resp.status == 200:
                b = json.loads(resp.read().decode())
                th = b.get("threshold", 0.0)
                limit = b.get("daily_budget", 0)
                if th > 0.0:
                    return (
                        True,
                        f"Budget threshold calibrated to {th:.2f} (daily target: {limit} alerts/day)",
                    )
                return (
                    False,
                    f"Budget threshold is {th} (not calibrated). Run 'make budget-calibrate'",
                )
            return False, f"Budget endpoint returned HTTP {resp.status}"
    except Exception as e:
        return False, f"Could not query budget status: {e}"


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelX Live Demo Preflight Readiness Check")
    parser.add_argument("--api-url", default="http://localhost:8000", help="SentinelX API root URL")
    args = parser.parse_args()

    print(
        f"\n{BOLD}{CYAN}========================================================================{RESET}"
    )
    print(
        f"{BOLD}{CYAN}         SentinelX Live Demo Preflight Readiness & Health Check        {RESET}"
    )
    print(
        f"{BOLD}{CYAN}========================================================================{RESET}\n"
    )

    checks = [
        ("Host Free Storage (>= 15GB)", lambda: check_disk_space(15.0)),
        ("Docker Lab Containers (9/9)", check_lab_containers),
        ("SentinelX API Reachability", lambda: check_api_health(args.api_url)),
        ("Telemetry Sources Health (5/5)", lambda: check_sources_health(args.api_url)),
        ("OT PLC Physics & Registers", check_plc_state),
        ("Clean Incident Store (0 Incidents)", lambda: check_incident_count(args.api_url)),
        ("Budget Controller Calibration", lambda: check_budget_calibrated(args.api_url)),
    ]

    all_passed = True
    for title, check_fn in checks:
        passed, msg = check_fn()
        status_badge = f"{GREEN}[ PASS ]{RESET}" if passed else f"{RED}[ FAIL ]{RESET}"
        print(f" {status_badge} {BOLD}{title:<36}{RESET} {DIM}::{RESET} {msg}")
        if not passed:
            all_passed = False

    print(
        f"\n{BOLD}{CYAN}------------------------------------------------------------------------{RESET}"
    )
    if all_passed:
        print(
            f"{GREEN}{BOLD} ✓ ALL PREFLIGHT CHECKS PASSED:{RESET} SentinelX is ready for live demonstration!"
        )
        print(f"   Launch the analyst UI at {CYAN}http://localhost:3000{RESET}")
        print(f"   Trigger the baseline attack with: {CYAN}make demo-attack{RESET}\n")
        return 0
    else:
        print(
            f"{RED}{BOLD} ✗ PREFLIGHT CHECKS FAILED:{RESET} One or more prerequisites are not satisfied."
        )
        print("   Quick fixes:")
        print(f"   1. Containers down?   -> {YELLOW}make lab-up{RESET}")
        print(f"   2. API down?          -> {YELLOW}make ingest-live{RESET}")
        print(f"   3. Dirty DB / state?  -> {YELLOW}make demo-reset{RESET}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
