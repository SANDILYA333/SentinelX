"""Schemas for SentinelX detection evaluation, ground truth datasets, and metrics."""

from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinelx.schemas.common import Severity, UtcDatetime
from sentinelx.schemas.signal import DetectorType

ScenarioCategory = Literal[
    "authentication",
    "lateral_movement",
    "endpoint",
    "deception",
    "industrial_ot",
    "benign",
]

DatasetSplit = Literal["dev", "validation", "test"]

ClassificationType = Literal["TP", "FP", "FN", "TN"]


class ExpectedDetection(BaseModel):
    """Specification of a detection expected from a scenario."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str | None = None
    detector: DetectorType | None = None
    severity: Severity | None = None
    technique_id: str | None = None
    target_asset: str | None = None
    description: str | None = None


class EvaluationScenario(BaseModel):
    """A ground truth evaluation scenario representing either an attack step or benign activity."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    name: str
    description: str
    category: ScenarioCategory
    split: DatasetSplit
    is_malicious: bool
    capture_name: str | None = None
    target_assets: list[str] = Field(default_factory=list)
    expected_detections: list[ExpectedDetection] = Field(default_factory=list)
    expected_attack_stages: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_scenario_invariants(self) -> "EvaluationScenario":
        if not self.is_malicious:
            if self.expected_detections:
                raise ValueError("Benign scenarios must not specify expected detections")
            if self.expected_attack_stages:
                raise ValueError("Benign scenarios must not specify expected attack stages")
        return self


class GroundTruthDataset(BaseModel):
    """Collection of evaluation scenarios with filter and lookup operations."""

    model_config = ConfigDict(extra="forbid")

    version: str = "1.0.0"
    description: str
    scenarios: list[EvaluationScenario] = Field(default_factory=list)

    def get_scenario(self, scenario_id: str) -> EvaluationScenario | None:
        """Find a scenario by its unique identifier."""
        for sc in self.scenarios:
            if sc.scenario_id == scenario_id:
                return sc
        return None

    def by_split(self, split: DatasetSplit) -> list[EvaluationScenario]:
        """Filter scenarios by train/val/test split."""
        return [sc for sc in self.scenarios if sc.split == split]

    def by_category(self, category: ScenarioCategory) -> list[EvaluationScenario]:
        """Filter scenarios by domain category."""
        return [sc for sc in self.scenarios if sc.category == category]

    def malicious_scenarios(self) -> list[EvaluationScenario]:
        """Return all attack scenarios."""
        return [sc for sc in self.scenarios if sc.is_malicious]

    def benign_scenarios(self) -> list[EvaluationScenario]:
        """Return all benign scenarios."""
        return [sc for sc in self.scenarios if not sc.is_malicious]


class ScenarioEvaluationResult(BaseModel):
    """Evaluation result for a single scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    name: str
    category: ScenarioCategory
    split: DatasetSplit
    is_malicious: bool
    detected: bool
    classification: ClassificationType
    score: float = 0.0
    time_to_detect_ms: float | None = None
    matched_signals: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    matched_detectors: list[str] = Field(default_factory=list)
    notes: str = ""
    evidence_events: list[str] = Field(default_factory=list)


class MetricScores(BaseModel):
    """Standard evaluation metrics with explicit zero-division handling."""

    model_config = ConfigDict(extra="forbid")

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    accuracy: float | None = None
    fpr: float | None = None
    fnr: float | None = None


class DetectorEvaluationMetric(BaseModel):
    """Evaluation metrics for an individual detector engine."""

    model_config = ConfigDict(extra="forbid")

    detector: str
    metrics: MetricScores
    total_signals: int = 0
    attack_signals: int = 0
    benign_signals: int = 0


class RuleEvaluationMetric(BaseModel):
    """Evaluation metrics for an individual detection rule."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    title: str
    detector: str = "rule"
    metrics: MetricScores
    total_fires: int = 0
    attack_fires: int = 0
    benign_fires: int = 0


class PercentileDistribution(BaseModel):
    """Percentile summary for latency distributions in milliseconds."""

    model_config = ConfigDict(extra="forbid")

    p50: float = 0.0
    p90: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    min_ms: float = 0.0
    mean_ms: float = 0.0
    max_ms: float = 0.0
    count: int = 0


class LatencyMetrics(BaseModel):
    """Breakdown of processing and detection latencies."""

    model_config = ConfigDict(extra="forbid")

    ingest_latency: PercentileDistribution
    detector_latency: PercentileDistribution
    correlator_latency: PercentileDistribution
    end_to_end_latency: PercentileDistribution
    time_to_detect: PercentileDistribution


class BudgetEvaluationMetric(BaseModel):
    """Assessment of Alert Budget Controller performance."""

    model_config = ConfigDict(extra="forbid")

    total_signals_emitted: int = 0
    admitted_signals: int = 0
    suppressed_signals: int = 0
    suppression_ratio: float = 0.0
    critical_signals_admitted: int = 0
    critical_signals_suppressed: int = 0
    high_severity_preservation_rate: float = 1.0
    incidents_formed: int = 0
    active_incidents: int = 0
    budget_admitted_without_suppressing_attacks: bool = True


class EvaluationRunSummary(BaseModel):
    """Complete summary of an evaluation run across all metrics and granularities."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    created_at: UtcDatetime
    git_commit: str = "unknown"
    dataset_version: str = "1.0.0"
    splits_evaluated: list[DatasetSplit] = Field(default_factory=lambda: ["dev", "validation", "test"])
    headline: MetricScores
    event_level: MetricScores
    scenario_level: MetricScores
    incident_level: MetricScores
    detectors: list[DetectorEvaluationMetric] = Field(default_factory=list)
    rules: list[RuleEvaluationMetric] = Field(default_factory=list)
    latency: LatencyMetrics
    budget: BudgetEvaluationMetric
    scenarios: list[ScenarioEvaluationResult] = Field(default_factory=list)
    false_positives: list[dict[str, Any]] = Field(default_factory=list)
    false_negatives: list[dict[str, Any]] = Field(default_factory=list)
    throughput_eps: float = 0.0
