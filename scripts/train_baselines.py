#!/usr/bin/env python3
"""SentinelX Baseline, Anomaly, and Graph Training Script.

Trains per-entity behavioral profiles, Isolation Forest anomaly models, and known interaction
edges exclusively on benign captures (day_101 through day_105) while enforcing startup-burst
exclusion for pristine baselines.
"""

import argparse
import logging
import sys
from pathlib import Path

# Add engine to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.detect.anomaly.trainer import (  # noqa: E402
    save_anomaly_bundle,
    train_anomaly_model,
)
from sentinelx.detect.baseline.trainer import train_baseline_model  # noqa: E402
from sentinelx.detect.graph.trainer import train_graph_model  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_baselines")


def main():
    parser = argparse.ArgumentParser(
        description="Train SentinelX detection models on benign captures."
    )
    parser.add_argument(
        "--captures-dir",
        type=Path,
        default=REPO_ROOT / "eval" / "captures" / "benign",
        help="Path to benign captures directory",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "data" / "models",
        help="Path to directory for persisting model artifacts",
    )
    parser.add_argument(
        "--exclude-sim-hours",
        type=float,
        default=1.0,
        help="Initial simulated hours to exclude as startup burst artifact",
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    benign_dirs = sorted([d for d in args.captures_dir.glob("day_*") if d.is_dir()])
    if not benign_dirs:
        logger.error(f"No benign captures found in {args.captures_dir}")
        sys.exit(1)

    logger.info(
        f"Found {len(benign_dirs)} benign captures: {[d.name for d in benign_dirs]}. "
        f"Training with startup-burst exclusion = {args.exclude_sim_hours} sim-hour(s)..."
    )

    # 1. Train Baseline Profiles
    logger.info("--> [1/3] Training per-entity behavioral baselines...")
    baseline_model = train_baseline_model(
        capture_dirs=benign_dirs,
        exclude_startup_sim_hours=args.exclude_sim_hours,
    )
    baseline_file = args.output_dir / "baseline_stats.json"
    baseline_model.save(baseline_file)
    logger.info(
        f"    Saved BaselineModel to {baseline_file} "
        f"({len(baseline_model.known_users)} users, {len(baseline_model.known_hosts)} hosts, "
        f"{len(baseline_model.profiles)} profiles)"
    )

    # 2. Train Isolation Forest Anomaly Model
    logger.info("--> [2/3] Training Isolation Forest windowed anomaly detector...")
    anomaly_bundle = train_anomaly_model(
        capture_dirs=benign_dirs,
        exclude_startup_sim_hours=args.exclude_sim_hours,
        window_sec=300.0,
        contamination=0.01,
    )
    anomaly_file = args.output_dir / "isolation_forest.joblib"
    save_anomaly_bundle(anomaly_bundle, anomaly_file)
    logger.info(
        f"    Saved Isolation Forest bundle to {anomaly_file} "
        f"(features: {anomaly_bundle['feature_names']}, max: {anomaly_bundle['max_feats']})"
    )

    # 3. Train Graph Known Edges
    logger.info("--> [3/3] Training interaction graph known edges...")
    graph_model = train_graph_model(
        capture_dirs=benign_dirs,
        exclude_startup_sim_hours=args.exclude_sim_hours,
    )
    graph_file = args.output_dir / "known_edges.json"
    graph_model.save(graph_file)
    logger.info(
        f"    Saved GraphModel to {graph_file} "
        f"({len(graph_model.known_edges)} known benign interaction edges)"
    )

    logger.info("All detection models successfully trained and persisted.")


if __name__ == "__main__":
    main()
