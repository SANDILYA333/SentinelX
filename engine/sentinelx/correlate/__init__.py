"""SentinelX security incident correlation and scoring package."""

from sentinelx.correlate.correlator import Correlator
from sentinelx.correlate.graph import build_incident_graph
from sentinelx.correlate.pipeline import CorrelationPipeline
from sentinelx.correlate.scoring import classify_signal_stage, score_incident

__all__ = [
    "Correlator",
    "CorrelationPipeline",
    "score_incident",
    "classify_signal_stage",
    "build_incident_graph",
]
