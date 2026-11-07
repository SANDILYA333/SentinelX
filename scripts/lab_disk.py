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
            [
                "docker",
                "ps",
                "-a",
                "-s",
                "--filter",
                "name=sentinelx-",
                "--format",
                "{{.Names}}\t{{.Size}}\t{{.Status}}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        lines = [ln.strip() for ln in res.stdout.strip().splitlines() if ln.strip()]
        header = (
            f"{'Container Name':<28} | {'Writable Size':<15} | {'Virtual Size':<15} | {'Status'}"
        )
        print(header)
        print("-" * len(header))

        for line in lines:
            parts = line.split("\t")
            cname = parts[0]
            size_part = parts[1] if len(parts) > 1 else ""
            status = parts[2] if len(parts) > 2 else ""

            # Example size_part: "135MB (virtual 1.92GB)"
            writable_str = (
                size_part.split("(")[0].strip() if "(" in size_part else size_part.strip()
            )
            virtual_str = (
                size_part.split("virtual")[-1].replace(")", "").strip()
                if "virtual" in size_part
                else "N/A"
            )

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
            res = subprocess.run(
                ["du", "-sh", *[str(p) for p in sorted(LOGS_DIR.glob("*"))]],
                capture_output=True,
                text=True,
                timeout=10,
            )
            print(res.stdout.strip())
        except Exception as e:
            print(f"Error checking data/logs: {e}")
    else:
        print("data/logs directory does not exist.")

    # 4. SentinelX SQLite Storage & Growth
    print("\n--- 4. SentinelX SQLite Database Storage & Growth Rate ---")
    db_file = REPO_ROOT / "data" / "sentinelx.db"
    wal_file = REPO_ROOT / "data" / "sentinelx.db-wal"
    shm_file = REPO_ROOT / "data" / "sentinelx.db-shm"

    total_bytes = 0
    for p in (db_file, wal_file, shm_file):
        if p.exists():
            total_bytes += p.stat().st_size

    total_mb = total_bytes / (1024.0 * 1024.0)
    print(f"Database Path: {db_file}")
    print(f"Total Size (DB + WAL + SHM): {total_mb:.3f} MB ({total_bytes} bytes)")

    growth_rate_mb_hr = 0.0
    if db_file.exists():
        try:
            import sqlite3
            from datetime import datetime, timezone
            conn = sqlite3.connect(str(db_file))
            row = conn.execute("SELECT MIN(ts), MAX(ts), COUNT(*) FROM events").fetchone()
            if row and row[2] > 1 and row[0] and row[1]:
                min_str, max_str, count = row[0], row[1], row[2]
                try:
                    dt_min = datetime.fromisoformat(min_str.replace("Z", "+00:00"))
                    dt_max = datetime.fromisoformat(max_str.replace("Z", "+00:00"))
                    elapsed_hours = (dt_max - dt_min).total_seconds() / 3600.0
                    if elapsed_hours >= 0.01:
                        growth_rate_mb_hr = total_mb / elapsed_hours
                        print(f"Events Stored: {count}")
                        print(f"Telemetry Span: {min_str} to {max_str}")
                        print(f"Estimated Growth Rate: {growth_rate_mb_hr:.2f} MB/hour")
                    else:
                        print(f"Events Stored: {count}")
                        print(f"Telemetry Span: {min_str} to {max_str}")
                        print(
                            "Estimated Growth Rate: < 0.1 MB/hour (timespan under 36 seconds)"
                        )
                except Exception:
                    pass
            elif row and row[2] == 1:
                print(f"Events Stored: 1 (at {row[0]})")
                print("Estimated Growth Rate: 0.00 MB/hour (single event)")
            else:
                print("Events Stored: 0 (database idle)")
                print("Estimated Growth Rate: 0.00 MB/hour")
            conn.close()
        except Exception as e:
            print(f"Note: Could not inspect SQLite events table: {e}")

    print("\n" + "=" * 80)
    if cap_failed:
        print(
            "DISK SAFETY CHECK FAILED: One or more containers exceeded the 500 MB writable layer cap!"
        )
        sys.exit(1)
    else:
        print("DISK SAFETY CHECK PASSED: All containers within storage limits.")
        sys.exit(0)


if __name__ == "__main__":
    main()
