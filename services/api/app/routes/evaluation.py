"""REST endpoints for SentinelX detection evaluation, metrics, and latency performance."""

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sentinelx.eval.engine import DetectionEvaluationEngine
from sentinelx.schemas.eval import (
    DatasetSplit,
    DetectorEvaluationMetric,
    EvaluationRunSummary,
    ScenarioEvaluationResult,
)
from sentinelx.store.sqlite import (
    get_evaluation_run,
    get_latest_evaluation_run,
    list_evaluation_runs,
    save_evaluation_run,
)

from app.db import get_db

router = APIRouter(prefix="/api/v1/evaluation", tags=["evaluation"])


class RunEvaluationRequest(BaseModel):
    splits: list[DatasetSplit] = Field(default_factory=lambda: ["dev", "validation", "test"])
    budget_threshold: float = Field(default=0.50, ge=0.0, le=1.0)


async def _get_or_create_latest_run(db: sqlite3.Connection) -> EvaluationRunSummary:
    """Retrieve latest evaluation run, or automatically execute a baseline evaluation if none exist."""
    run = get_latest_evaluation_run(db)
    if run is not None:
        return run

    engine = DetectionEvaluationEngine()
    run = await engine.run_full_evaluation(splits=["dev", "validation", "test"])
    save_evaluation_run(db, run)
    return run


@router.get("/overview")
async def get_evaluation_overview(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> dict[str, Any]:
    """Retrieve high-level overview of the latest evaluation run and dataset statistics."""
    run = await _get_or_create_latest_run(db)
    history = list_evaluation_runs(db, limit=10)

    return {
        "latest_run_id": run.run_id,
        "created_at": run.created_at.isoformat(),
        "git_commit": run.git_commit,
        "dataset_version": run.dataset_version,
        "splits_evaluated": run.splits_evaluated,
        "headline": run.headline.model_dump(),
        "event_level": run.event_level.model_dump(),
        "scenario_level": run.scenario_level.model_dump(),
        "incident_level": run.incident_level.model_dump(),
        "throughput_eps": run.throughput_eps,
        "p95_latency_ms": run.latency.end_to_end_latency.p95,
        "total_historical_runs": len(history),
    }


@router.get("/runs")
def list_runs(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[dict[str, Any]]:
    """List historical evaluation runs with summary scores."""
    return list_evaluation_runs(db, limit=limit)


@router.get("/runs/{run_id}", response_model=EvaluationRunSummary)
def get_run_details(
    run_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> EvaluationRunSummary:
    """Retrieve full details of a specific evaluation run."""
    run = get_evaluation_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Evaluation run '{run_id}' not found.")
    return run


@router.get("/runs/{run_id}/detectors")
def get_run_detectors(
    run_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> list[DetectorEvaluationMetric]:
    """Retrieve per-detector evaluation breakdown for a specific run."""
    run = get_evaluation_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Evaluation run '{run_id}' not found.")
    return run.detectors


@router.get("/runs/{run_id}/scenarios")
def get_run_scenarios(
    run_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    category: Annotated[str | None, Query()] = None,
    split: Annotated[str | None, Query()] = None,
    classification: Annotated[str | None, Query()] = None,
) -> list[ScenarioEvaluationResult]:
    """Retrieve scenario-level evaluation results with optional filtering."""
    run = get_evaluation_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Evaluation run '{run_id}' not found.")

    scenarios = run.scenarios
    if category:
        scenarios = [s for s in scenarios if s.category == category]
    if split:
        scenarios = [s for s in scenarios if s.split == split]
    if classification:
        scenarios = [s for s in scenarios if s.classification == classification]

    return scenarios


@router.get("/runs/{run_id}/false-positives")
def get_run_false_positives(
    run_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> list[dict[str, Any]]:
    """Retrieve false positive occurrences with contextual root-cause evidence."""
    run = get_evaluation_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Evaluation run '{run_id}' not found.")
    return run.false_positives


@router.get("/runs/{run_id}/false-negatives")
def get_run_false_negatives(
    run_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> list[dict[str, Any]]:
    """Retrieve false negative occurrences with missed rule expectations and tactics."""
    run = get_evaluation_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Evaluation run '{run_id}' not found.")
    return run.false_negatives


@router.get("/runs/{run_id}/performance")
def get_run_performance(
    run_id: str,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> dict[str, Any]:
    """Retrieve latency distributions, percentiles, and throughput metrics."""
    run = get_evaluation_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Evaluation run '{run_id}' not found.")
    return {
        "latency": run.latency.model_dump(),
        "throughput_eps": run.throughput_eps,
        "budget": run.budget.model_dump(),
    }


@router.get("/history")
def get_evaluation_history(
    db: Annotated[sqlite3.Connection, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> list[dict[str, Any]]:
    """Retrieve historical score trajectory for regression tracking."""
    return list_evaluation_runs(db, limit=limit)


@router.post("/run", response_model=EvaluationRunSummary)
async def trigger_evaluation_run(
    req: RunEvaluationRequest,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
) -> EvaluationRunSummary:
    """Execute a new evaluation run on demand and persist results in SQLite."""
    engine = DetectionEvaluationEngine()
    run = await engine.run_full_evaluation(
        splits=req.splits,
        budget_threshold=req.budget_threshold,
    )
    save_evaluation_run(db, run)
    return run
