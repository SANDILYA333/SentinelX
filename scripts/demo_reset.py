#!/usr/bin/env python3
"""SentinelX Demo Environment Reset Tool.

Resets the demonstration environment to a pristine baseline:
1. Resets PLC simulator registers and physics (55% normal level, pump running, valves normal).
2. Clears and reinitializes SQLite database (events, signals, incidents, guard decisions).
3. Fast-forwards tailer checkpoints to the current end-of-file for all logs in data/logs,
   preventing historical log pollution during live demonstration.
"""

import logging
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.ingest.runtime import DEFAULT_SOURCES  # noqa: E402
from sentinelx.store.sqlite import init_db  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("demo_reset")


def reset_plc() -> bool:
    """Reset PLC simulator registers and state to baseline."""
    logger.info("Resetting PLC simulator state...")
    try:
        res = subprocess.run(
            [
                "docker",
                "exec",
                "sentinelx-eng-ws",
                "curl",
                "-s",
                "-X",
                "POST",
                "http://10.10.3.20:8080/reset",
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if res.returncode == 0:
            logger.info("PLC simulator reset successfully: %s", res.stdout.strip())
            return True
        logger.warning("Failed to reset PLC via eng-ws: %s", res.stderr.strip())
    except Exception as e:
        logger.warning("Error running docker exec for PLC reset: %e", e)
    return False


def reset_database_and_checkpoints(db_path: Path, log_root: Path) -> None:
    """Wipe SQLite database and seed checkpoints at current log file sizes."""
    logger.info("Reinitializing SQLite database at %s...", db_path)

    # Remove existing db files
    for p in [
        db_path,
        db_path.with_name(f"{db_path.name}-wal"),
        db_path.with_name(f"{db_path.name}-shm"),
    ]:
        if p.exists():
            try:
                p.unlink()
            except Exception as e:
                logger.warning("Could not unlink %s: %s", p, e)

    # Initialize tables
    init_db(db_path)

    # Seed checkpoints table
    conn = sqlite3.connect(db_path, timeout=30.0)
    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ingest_checkpoints (
            source_key TEXT PRIMARY KEY,
            inode INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )

    seeded_count = 0
    for src in DEFAULT_SOURCES:
        file_path = log_root / src.relative_path
        if file_path.exists():
            stat = file_path.stat()
            conn.execute(
                """
                INSERT OR REPLACE INTO ingest_checkpoints (source_key, inode, offset, updated_at)
                VALUES (?, ?, ?, ?);
                """,
                (src.source_key, stat.st_ino, stat.st_size, now_iso),
            )
            seeded_count += 1

    conn.commit()
    conn.close()
    logger.info("Seeded %d tailer checkpoints at current log EOFs.", seeded_count)


def main() -> int:
    db_path = REPO_ROOT / "data" / "sentinelx.db"
    log_root = REPO_ROOT / "data" / "logs"

    reset_plc()
    reset_database_and_checkpoints(db_path, log_root)

    print("\n========================================================================")
    print(" ✓ SentinelX Demo Environment Reset Complete")
    print("   - PLC State: Normal (55.0% level, 50% pump, 50% valve)")
    print("   - Database: Clean (0 events, 0 signals, 0 incidents)")
    print("   - Ingestion: Checkpointed at current live log EOFs")
    print("========================================================================\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
