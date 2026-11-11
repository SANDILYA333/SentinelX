#!/usr/bin/env python3
"""Validation utility for SentinelX Ground Truth Evaluation Datasets."""

import json
import sys
from pathlib import Path

# Add repo root and engine to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "engine"))

from sentinelx.schemas.eval import GroundTruthDataset

DATASET_PATH = REPO_ROOT / "eval" / "scenarios" / "ground_truth.json"


def validate_dataset(path: Path = DATASET_PATH) -> GroundTruthDataset:
    """Validate ground truth dataset JSON file and return GroundTruthDataset model."""
    if not path.exists():
        raise FileNotFoundError(f"Ground truth dataset not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Validate schema
    dataset = GroundTruthDataset.model_validate(data)

    # Invariant checks
    scenario_ids = set()
    for sc in dataset.scenarios:
        if sc.scenario_id in scenario_ids:
            raise ValueError(f"Duplicate scenario_id detected: {sc.scenario_id}")
        scenario_ids.add(sc.scenario_id)

        if sc.is_malicious:
            if not sc.expected_detections and not sc.expected_attack_stages:
                raise ValueError(
                    f"Malicious scenario {sc.scenario_id} must have expected detections or attack stages."
                )
        else:
            if sc.expected_detections:
                raise ValueError(
                    f"Benign scenario {sc.scenario_id} must not specify expected malicious detections."
                )

    # Verify split distributions
    dev = dataset.by_split("dev")
    val = dataset.by_split("validation")
    test = dataset.by_split("test")

    print(f"Dataset '{dataset.description}' (v{dataset.version}) validated successfully.")
    print(f"Total scenarios: {len(dataset.scenarios)}")
    print(f"  - Dev split: {len(dev)} (Malicious: {len([s for s in dev if s.is_malicious])}, Benign: {len([s for s in dev if not s.is_malicious])})")
    print(f"  - Validation split: {len(val)} (Malicious: {len([s for s in val if s.is_malicious])}, Benign: {len([s for s in val if not s.is_malicious])})")
    print(f"  - Test split: {len(test)} (Malicious: {len([s for s in test if s.is_malicious])}, Benign: {len([s for s in test if not s.is_malicious])})")

    return dataset


if __name__ == "__main__":
    try:
        validate_dataset()
        sys.exit(0)
    except Exception as e:
        print(f"Dataset validation failed: {e}", file=sys.stderr)
        sys.exit(1)

