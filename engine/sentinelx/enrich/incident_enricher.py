"""Enrichment service for correlated incidents (MITRE rollup, TTFMA, and narrative explanation).

TTFMA — Authoritative Definition (Phase A)
===========================================
Event-Time TTFMA = threshold_crossing_event_ts − first_adversary_event_ts

Where:
  first_adversary_event_ts       — timestamp of the earliest qualifying adversary action
                                   in the correlated campaign (i.e. the first signal's event ts).
  threshold_crossing_event_ts    — timestamp of the event whose associated signal causes
                                   the incident score to reach or exceed the configured alert
                                   threshold for the first time.

This measures dwell time visible in event-time telemetry, NOT processing latency.
A genuine 0.0s TTFMA is valid when the first adversary action itself causes the threshold crossing.
None is returned when the incident has never crossed the threshold or timestamps are unavailable.
"""

import logging

from sentinelx.correlate.scoring import score_incident
from sentinelx.schemas.common import Technique, UtcDatetime
from sentinelx.schemas.signal import Signal

logger = logging.getLogger(__name__)

# Meaningful alert threshold: high confidence (>= 0.85) or high-fidelity detector (rule/deception)
MEANINGFUL_CONFIDENCE_THRESHOLD: float = 0.85
MEANINGFUL_DETECTORS: set[str] = {"rule", "deception"}


def compute_technique_rollup(signals: list[Signal]) -> list[Technique]:
    """Deduplicated union of all MITRE ATT&CK and ATT&CK-ICS techniques across signals."""
    seen_ids: set[str] = set()
    techniques: list[Technique] = []

    for s in signals:
        for tech in s.techniques:
            tid = tech.technique_id.strip().upper()
            if tid not in seen_ids:
                seen_ids.add(tid)
                techniques.append(tech)

    return techniques


def compute_ttfma(
    signals: list[Signal],
    alert_threshold: float,
    novelty_cap: float = 0.40,
) -> tuple[UtcDatetime | None, UtcDatetime | None, UtcDatetime | None, float | None]:
    """Calculate Time To First Meaningful Alert (TTFMA) using the documented event-time definition.

    Definition:
      Event-Time TTFMA = threshold_crossing_event_ts − first_adversary_event_ts

      first_adversary_event_ts    — ts of the earliest signal (sorted by event ts).
      threshold_crossing_event_ts — ts of the signal that first causes the cumulative
                                    incident score to reach or exceed alert_threshold.

    Returns a 4-tuple:
      (first_signal_ts, first_meaningful_alert_ts, threshold_crossing_event_ts, ttfma_seconds)

    first_meaningful_alert_ts is kept for backward-compatible API field population; it refers
    to the same threshold_crossing_event_ts event.

    None values are returned for any field that cannot be determined from available data.
    Processing latency is never substituted for event-time delta.
    """
    if not signals:
        return None, None, None, None

    # Sort by event timestamp — handle duplicate or reordered events correctly.
    sorted_signals = sorted(signals, key=lambda s: s.ts)

    first_signal_ts: UtcDatetime = sorted_signals[0].ts

    # Walk signals in event-time order and replay scoring to find the threshold crossing moment.
    # We accumulate signals incrementally and re-score after each addition.
    threshold_crossing_event_ts: UtcDatetime | None = None
    first_meaningful_alert_ts: UtcDatetime | None = None

    for idx in range(1, len(sorted_signals) + 1):
        prefix = sorted_signals[:idx]
        current_signal = sorted_signals[idx - 1]

        # Compute incident score using the same scorer as the correlator
        # to stay in sync with actual threshold crossing semantics.
        score, _stages, _sev = score_incident(prefix, novelty_cap=novelty_cap)

        if score >= alert_threshold:
            threshold_crossing_event_ts = current_signal.ts
            first_meaningful_alert_ts = current_signal.ts
            break

    if threshold_crossing_event_ts is None:
        # Incident has never crossed the threshold — TTFMA is not available.
        logger.debug(
            "Incident has not crossed alert threshold %.2f with %d signals; TTFMA unavailable.",
            alert_threshold,
            len(signals),
        )
        return first_signal_ts, None, None, None

    # Compute delta in event-time seconds.
    try:
        dt_diff = (threshold_crossing_event_ts - first_signal_ts).total_seconds()
    except Exception as exc:
        logger.warning(
            "TTFMA delta calculation failed (first_signal_ts=%s, threshold_crossing_ts=%s): %s",
            first_signal_ts,
            threshold_crossing_event_ts,
            exc,
        )
        return first_signal_ts, first_meaningful_alert_ts, threshold_crossing_event_ts, None

    # A genuine 0.0s is valid when the first adversary action is itself the threshold crossing.
    # We do NOT force non-zero; we return the true delta.
    ttfma_seconds = round(dt_diff, 2)

    return first_signal_ts, first_meaningful_alert_ts, threshold_crossing_event_ts, ttfma_seconds


def generate_explanation(signals: list[Signal]) -> list[str]:
    """Build a short, chronological, human-readable narrative of the incident's attack progression."""
    from sentinelx.correlate.stages import classify_signal_stage

    sorted_signals = sorted(signals, key=lambda s: s.ts)
    narrative: list[str] = []
    seen_narratives: set[str] = set()

    for s in sorted_signals:
        stage = classify_signal_stage(s).replace("_", " ").title()
        timestamp_str = s.ts.strftime("%H:%M:%S UTC")
        rule_label = s.rule_id or s.detector.upper()

        line = f"[{timestamp_str}] [{stage}] {s.explanation} ({rule_label})"
        if line not in seen_narratives:
            seen_narratives.add(line)
            narrative.append(line)

    return narrative


def check_domain_touches(signals: list[Signal]) -> tuple[bool, bool]:
    """Determine whether decoy assets or OT process controllers were touched."""
    decoy_touched = False
    ot_touched = False

    decoy_keywords = {"cowrie", "opencanary", "decoy-plc", "10.10.2.20", "10.10.2.30", "10.10.3.60"}
    ot_keywords = {"plc-sim", "10.10.3.20", "modbus", "valve", "coil"}

    for s in signals:
        # Check rule ID and detector
        if s.detector == "deception" or (s.rule_id and "DECOY" in s.rule_id.upper()):
            decoy_touched = True
        if s.rule_id and "OT" in s.rule_id.upper():
            ot_touched = True

        # Check explanation
        expl_lower = s.explanation.lower()
        if any(dk in expl_lower for dk in decoy_keywords):
            decoy_touched = True
        if any(ok in expl_lower for ok in ot_keywords):
            ot_touched = True

        # Check entities
        for ent in s.entities:
            val_lower = ent.value.lower()
            if any(dk in val_lower for dk in decoy_keywords):
                decoy_touched = True
            if any(ok in val_lower for ok in ot_keywords):
                ot_touched = True

    return decoy_touched, ot_touched
