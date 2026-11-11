"""Unit tests for SentinelX ground truth evaluation dataset validation and schema constraints."""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sentinelx.schemas.eval import (  # noqa: E402
    EvaluationScenario,
    ExpectedDetection,
    GroundTruthDataset,
)

from scripts.validate_evaluation_dataset import validate_dataset  # noqa: E402


def test_ground_truth_dataset_integrity():
    """Verify ground_truth.json passes all schema and semantic invariants."""
    dataset = validate_dataset(REPO_ROOT / "eval" / "scenarios" / "ground_truth.json")
    assert dataset.version == "1.0.0"
    assert len(dataset.scenarios) >= 15

    # Check that both malicious and benign scenarios exist
    malicious = dataset.malicious_scenarios()
    benign = dataset.benign_scenarios()
    assert len(malicious) > 0
    assert len(benign) > 0

    # Check splits
    dev = dataset.by_split("dev")
    val = dataset.by_split("validation")
    test = dataset.by_split("test")
    assert len(dev) > 0
    assert len(val) > 0
    assert len(test) > 0

    # Check categories coverage
    categories = {sc.category for sc in dataset.scenarios}
    assert "authentication" in categories
    assert "lateral_movement" in categories
    assert "endpoint" in categories
    assert "deception" in categories
    assert "industrial_ot" in categories
    assert "benign" in categories


def test_ground_truth_scenario_lookups():
    """Verify lookup methods on GroundTruthDataset."""
    dataset = validate_dataset(REPO_ROOT / "eval" / "scenarios" / "ground_truth.json")
    sc = dataset.get_scenario("SCEN-OT-001")
    assert sc is not None
    assert sc.is_malicious is True
    assert sc.category == "industrial_ot"
    assert any(ed.rule_id == "RULE-OT-001" for ed in sc.expected_detections)

    assert dataset.get_scenario("NON-EXISTENT-ID") is None


def test_invalid_benign_scenario_rejection():
    """Benign scenarios must not define expected malicious detections."""
    with pytest.raises(Exception):
        GroundTruthDataset(
            version="1.0.0",
            description="Test Invalid",
            scenarios=[
                EvaluationScenario(
                    scenario_id="INVALID-BENIGN",
                    name="Invalid Benign",
                    description="Should fail",
                    category="benign",
                    split="dev",
                    is_malicious=False,
                    expected_detections=[
                        ExpectedDetection(rule_id="RULE-OT-001", description="Illegal on benign")
                    ],
                )
            ],
        )
