"""REST endpoints for evaluation metrics and benchmark summaries."""

import json
from pathlib import Path

from fastapi import APIRouter
from sentinelx.schemas.api_models import EvalSummaryResponse

router = APIRouter(prefix="/api/v1/eval", tags=["eval"])

REPO_ROOT = Path(__file__).resolve().parents[4]
CACHE_FILE = REPO_ROOT / "eval" / "reports" / "incident_eval_summary.json"


@router.get("/summary", response_model=EvalSummaryResponse)
def get_eval_summary() -> EvalSummaryResponse:
    """Retrieve full evaluation benchmark summary across all 8 verified captures."""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return EvalSummaryResponse.model_validate(data)
        except Exception:
            pass

    # If cache not present, import and execute evaluation
    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from scripts.incident_eval import get_or_run_eval_summary

    data = get_or_run_eval_summary(cache_path=CACHE_FILE)
    return EvalSummaryResponse.model_validate(data)
