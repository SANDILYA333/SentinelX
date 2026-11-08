#!/usr/bin/env python3
"""SentinelX Telemetry Capture Tooling.

Snapshots live lab telemetry from data/logs into reproducible capture bundles
under eval/captures/<category>/<name>/ with comprehensive manifest metadata,
per-source line counts, SHA-256 integrity verification, and strict disk caps.
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Ensure engine is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

from sentinelx.attack.runner import AttackScenarioRunner, load_scenario  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("capture")

LOGS_DIR = REPO_ROOT / "data" / "logs"
CAPTURES_ROOT = REPO_ROOT / "eval" / "captures"
MIN_FREE_DISK_GB = 15.0
MAX_CAPTURE_SIZE_MB = 50.0


def check_free_disk() -> float:
    """Verify system free disk space on repository mount point."""
    stat = os.statvfs(str(REPO_ROOT))
    free_bytes = stat.f_bavail * stat.f_frsize
    free_gb = free_bytes / (1024.0**3)
    if free_gb < MIN_FREE_DISK_GB:
        raise RuntimeError(
            f"PREFLIGHT DISK SAFETY ABORT: Free disk is {free_gb:.2f} GB (< {MIN_FREE_DISK_GB} GB threshold)!"
        )
    return free_gb


def get_git_commit() -> str:
    """Retrieve current git HEAD commit hash."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "unknown"


def reset_lab():
    """Execute clean lab reset via make lab-reset."""
    logger.info("Executing clean lab reset (make lab-reset)...")
    res = subprocess.run(["make", "lab-reset"], cwd=str(REPO_ROOT), capture_output=True, text=True)
    if res.returncode != 0:
        logger.error(
            f"make lab-reset failed ({res.returncode}):\n{res.stderr.strip() or res.stdout.strip()}"
        )
        raise RuntimeError("Lab reset failed")
    logger.info("Lab reset complete. All services healthy.")


def compute_file_sha256(file_path: Path) -> str:
    """Compute hex SHA-256 digest of file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def count_lines(file_path: Path) -> int:
    """Count non-empty lines in text file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def copy_logs(dest_dir: Path) -> float:
    """Copy logs to destination directory, ignoring restricted directories and calculating size."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    total_bytes = 0

    for item in LOGS_DIR.iterdir():
        if item.is_dir():
            target_sub = dest_dir / item.name
            target_sub.mkdir(parents=True, exist_ok=True)
            for sub_file in item.iterdir():
                # Exclude rotated 2026/ subfolder or raw archives.log with restricted uid 999
                if sub_file.is_dir() or sub_file.name == "archives.log":
                    continue
                dst_file = target_sub / sub_file.name
                shutil.copy2(sub_file, dst_file)
                total_bytes += dst_file.stat().st_size
        elif item.is_file():
            dst_file = dest_dir / item.name
            shutil.copy2(item, dst_file)
            total_bytes += dst_file.stat().st_size

    total_mb = total_bytes / (1024.0 * 1024.0)
    if total_mb > MAX_CAPTURE_SIZE_MB:
        raise RuntimeError(
            f"CAPTURE SIZE VIOLATION: Captured size {total_mb:.2f} MB exceeds cap of {MAX_CAPTURE_SIZE_MB} MB!"
        )
    return total_mb


def run_capture(
    category: str,
    name: str,
    mode: str,
    scenario_name: str | None = None,
    duration: float = 60.0,
    sim_speed: float = 96.0,
    seed: int = 42,
    skip_reset: bool = False,
) -> Path:
    """Run full capture workflow: preflight -> reset -> traffic generation -> snapshot -> manifest."""
    free_gb = check_free_disk()
    logger.info(
        f"Preflight disk check: {free_gb:.2f} GB free (threshold: {MIN_FREE_DISK_GB} GB) [OK]"
    )

    if not skip_reset:
        reset_lab()

    target_dir = CAPTURES_ROOT / category / name
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    wall_start = datetime.now(UTC)
    sim_start = wall_start

    print("\n" + "=" * 80)
    print(f"RUNNING CAPTURE: {category.upper()}/{name}")
    print(f"  Mode       : {mode}")
    print(f"  Scenario   : {scenario_name or 'N/A'}")
    print(f"  Duration   : {duration:.1f}s")
    print(f"  SIM_SPEED  : {sim_speed}x")
    print(f"  Seed       : {seed}")
    print(f"  Output Dir : {target_dir}")
    print("=" * 80 + "\n")

    benign_proc = None

    try:
        # Start background benign traffic generator if benign or hybrid
        if mode in ("benign", "hybrid"):
            logger.info(
                f"Starting benign activity generator (sim_speed: {sim_speed}x, seed: {seed})..."
            )
            env = os.environ.copy()
            env["SIM_SPEED"] = str(sim_speed)
            env["BENIGN_SEED"] = str(seed)
            benign_cmd = [
                "docker",
                "exec",
                "-e",
                f"SIM_SPEED={sim_speed}",
                "-e",
                f"RANDOM_SEED={seed}",
                "sentinelx-benign",
                "python3",
                "/usr/local/bin/benign_loop.py",
                "--duration",
                str(duration + 300 if mode == "hybrid" else duration),
                "--sim-speed",
                str(sim_speed),
                "--seed",
                str(seed),
            ]
            benign_proc = subprocess.Popen(
                benign_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            if mode == "hybrid":
                # Let benign traffic settle before launching attack
                logger.info(
                    "Allowing background benign traffic to establish baseline (15s settle)..."
                )
                time.sleep(15.0)

        # Execute attack scenario if attack or hybrid
        if mode in ("attack", "hybrid") and scenario_name:
            logger.info(f"Executing attack scenario '{scenario_name}'...")
            scenario = load_scenario(scenario_name)
            attack_runner = AttackScenarioRunner(scenario)
            attack_runner.run()

            if mode == "hybrid":
                # Allow post-attack observation period
                logger.info("Allowing post-attack background observation (15s)...")
                time.sleep(15.0)

        elif mode == "benign":
            # Sleep remaining duration
            logger.info(f"Tailing benign traffic for {duration:.1f} seconds...")
            time.sleep(duration)

    finally:
        # Terminate benign generator
        if benign_proc:
            logger.info("Stopping benign generator process...")
            benign_proc.terminate()
            try:
                benign_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                benign_proc.kill()

    wall_end = datetime.now(UTC)
    wall_duration = (wall_end - wall_start).total_seconds()
    sim_duration_hours = (wall_duration * sim_speed) / 3600.0
    sim_end = sim_start + timedelta(seconds=wall_duration * sim_speed)

    # Snapshot data/logs
    logger.info(f"Snapshotting data/logs/ to {target_dir}...")
    total_size_mb = copy_logs(target_dir)

    # Compute line counts and SHA-256 for all files
    per_source_lines: dict[str, int] = {}
    file_hashes: dict[str, str] = {}

    for path in sorted(target_dir.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            rel = str(path.relative_to(target_dir))
            per_source_lines[rel] = count_lines(path)
            file_hashes[rel] = compute_file_sha256(path)

    manifest_data = {
        "git_commit": get_git_commit(),
        "category": category,
        "name": name,
        "scenario": scenario_name,
        "mode": mode,
        "seed": seed,
        "sim_speed": sim_speed,
        "wall_start": wall_start.isoformat(),
        "wall_end": wall_end.isoformat(),
        "sim_start": sim_start.isoformat(),
        "sim_end": sim_end.isoformat(),
        "total_wall_seconds": round(wall_duration, 2),
        "total_sim_hours": round(sim_duration_hours, 2),
        "total_size_mb": round(total_size_mb, 3),
        "per_source_lines": per_source_lines,
        "sha256": file_hashes,
    }

    manifest_path = target_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    logger.info(f"Capture successfully saved: {target_dir}")
    logger.info(f"Total size: {total_size_mb:.3f} MB | Manifest written: {manifest_path}")
    return target_dir


def main():
    parser = argparse.ArgumentParser(description="SentinelX Telemetry Capture Tooling")
    parser.add_argument(
        "--category", choices=["benign", "attack"], required=True, help="Capture category"
    )
    parser.add_argument(
        "--name", required=True, help="Capture bundle name (e.g. day_1, demo_baseline)"
    )
    parser.add_argument(
        "--mode",
        choices=["benign", "attack", "hybrid"],
        default=None,
        help="Capture execution mode",
    )
    parser.add_argument(
        "--scenario", default=None, help="Attack scenario name (baseline, reordered, slow_burn)"
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=60.0,
        help="Wall-clock duration in seconds (for benign/hybrid)",
    )
    parser.add_argument(
        "--sim-speed", type=float, default=96.0, help="Diurnal compression speed factor"
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--skip-reset", action="store_true", help="Skip lab reset if already clean")
    args = parser.parse_args()

    mode = args.mode
    if not mode:
        if args.category == "benign":
            mode = "benign"
        elif args.scenario:
            mode = "hybrid"
        else:
            mode = "attack"

    run_capture(
        category=args.category,
        name=args.name,
        mode=mode,
        scenario_name=args.scenario,
        duration=args.duration,
        sim_speed=args.sim_speed,
        seed=args.seed,
        skip_reset=args.skip_reset,
    )


if __name__ == "__main__":
    main()
