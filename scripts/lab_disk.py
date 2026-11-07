#!/usr/bin/env python3
"""SentinelX Disk Safety & Telemetry Volume Inspection Script (stdlib only).

Inspects:
1. Docker system df
2. Per-container writable layer sizes (docker ps -a -s) with strict 500 MB size cap guard
3. Disk usage of all data/logs directories
"""

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = REPO_ROOT / "data" / "logs"


def parse_size_mb(size_str: str) -> float:
    """Parse human readable size string (e.g. 135MB, 1.2GB, 500kB) to megabytes."""
    s = size_str.strip()
    match = re.match(r"^([\d.]+)\s*([a-zA-Z]+)", s)
    if not match:
        return 0.0
    val = float(match.group(1))
    unit = match.group(2).upper()

    if "G" in unit:
        return val * 1024.0
    elif "M" in unit:
        return val
    elif "K" in unit:
        return val / 1024.0
    elif "B" in unit:
        return val / (1024.0 * 1024.0)
    return val


def main():
    print("=" * 80)
    print("SentinelX Lab Disk Usage & Container Storage Report")
    print("=" * 80)

    # 1. Docker System DF
    print("\n--- 1. Docker System Storage (docker system df) ---")
    try:
        res = subprocess.run(["docker", "system", "df"], capture_output=True, text=True, timeout=15)
        print(res.stdout.strip())
    except Exception as e:
        print(f"Error running docker system df: {e}")

    # 2. Per-container writable layer sizes & 500 MB guard
    print("\n--- 2. Container Writable Layer Sizes (Limit: <= 500 MB per container) ---")
    cap_failed = False
    try:
        res = subprocess.run(
            ["docker", "ps", "-a", "-s", "--filter", "name=sentinelx-", "--format", "{{.Names}}\t{{.Size}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=15
        )
        lines = [l.strip() for l in res.stdout.strip().splitlines() if l.strip()]
        header = f"{'Container Name':<28} | {'Writable Size':<15} | {'Virtual Size':<15} | {'Status'}"
        print(header)
        print("-" * len(header))

        for line in lines:
            parts = line.split("\t")
            cname = parts[0]
            size_part = parts[1] if len(parts) > 1 else ""
            status = parts[2] if len(parts) > 2 else ""

            # Example size_part: "135MB (virtual 1.92GB)"
            writable_str = size_part.split("(")[0].strip() if "(" in size_part else size_part.strip()
            virtual_str = size_part.split("virtual")[-1].replace(")", "").strip() if "virtual" in size_part else "N/A"

            size_mb = parse_size_mb(writable_str)
            warn_tag = ""
            if size_mb > 500.0:
                warn_tag = " [EXCEEDS 500MB CAP! FAIL]"
                cap_failed = True
            elif size_mb > 200.0:
                warn_tag = " [WARN > 200MB]"

            print(f"{cname:<28} | {writable_str:<15} | {virtual_str:<15} | {status}{warn_tag}")

    except Exception as e:
        print(f"Error checking container sizes: {e}")

    # 3. Size of every data/logs directory
    print("\n--- 3. Telemetry Log Directories (data/logs/*) ---")
    if LOGS_DIR.exists():
        try:
            res = subprocess.run(["du", "-sh", *[str(p) for p in sorted(LOGS_DIR.glob("*"))]], capture_output=True, text=True, timeout=10)
            print(res.stdout.strip())
        except Exception as e:
            print(f"Error checking data/logs: {e}")
    else:
        print("data/logs directory does not exist.")

    print("\n" + "=" * 80)
    if cap_failed:
        print("DISK SAFETY CHECK FAILED: One or more containers exceeded the 500 MB writable layer cap!")
        sys.exit(1)
    else:
        print("DISK SAFETY CHECK PASSED: All containers within storage limits.")
        sys.exit(0)


if __name__ == "__main__":
    main()

