#!/usr/bin/env python3
"""Export Pydantic v2 data contracts to JSON Schema files."""

import json
from pathlib import Path

from sentinelx.schemas import (
    BudgetEvaluationMetric,
    DeceptionActivity,
    DeceptionAssetSummary,
    DeceptionOverview,
    DetectorEvaluationMetric,
    Entity,
    EvaluationRunSummary,
    Event,
    GroundTruthDataset,
    GuardDecision,
    Incident,
    LatencyMetrics,
    MetricScores,
    ResponseRecommendation,
    RuleEvaluationMetric,
    ScenarioEvaluationResult,
    Signal,
    SourceHealth,
    Technique,
    TelemetryStats,
    TimelineEvent,
    WSMessage,
)
from sentinelx.schemas.api_models import (
    AssetResponse,
    BudgetStatusResponse,
    EvalSummaryResponse,
    IncidentSummaryResponse,
    SystemStatusResponse,
)

MODELS = {
    "Event": Event,
    "Signal": Signal,
    "Incident": Incident,
    "TimelineEvent": TimelineEvent,
    "GuardDecision": GuardDecision,
    "ResponseRecommendation": ResponseRecommendation,
    "DeceptionActivity": DeceptionActivity,
    "DeceptionAssetSummary": DeceptionAssetSummary,
    "DeceptionOverview": DeceptionOverview,
    "WSMessage": WSMessage,
    "Entity": Entity,
    "Technique": Technique,
    "SourceHealth": SourceHealth,
    "TelemetryStats": TelemetryStats,
    "AssetResponse": AssetResponse,
    "BudgetStatusResponse": BudgetStatusResponse,
    "SystemStatusResponse": SystemStatusResponse,
    "EvalSummaryResponse": EvalSummaryResponse,
    "IncidentSummaryResponse": IncidentSummaryResponse,
    "EvaluationRunSummary": EvaluationRunSummary,
    "ScenarioEvaluationResult": ScenarioEvaluationResult,
    "DetectorEvaluationMetric": DetectorEvaluationMetric,
    "RuleEvaluationMetric": RuleEvaluationMetric,
    "MetricScores": MetricScores,
    "LatencyMetrics": LatencyMetrics,
    "BudgetEvaluationMetric": BudgetEvaluationMetric,
    "GroundTruthDataset": GroundTruthDataset,
}


def export_schemas() -> None:
    """Generate JSON schema files for all core SentinelX models."""
    output_dir = Path(__file__).resolve().parent.parent / "packages" / "contracts" / "schemas"
    output_dir.mkdir(parents=True, exist_ok=True)

    for name, model in MODELS.items():
        schema = model.model_json_schema()
        # Set title if not already present
        schema["title"] = name
        target_file = output_dir / f"{name}.json"
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)
            f.write("\n")
        print(f"Exported schema: {target_file}")


if __name__ == "__main__":
    export_schemas()
