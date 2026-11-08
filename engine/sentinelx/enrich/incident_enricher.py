"""Enrichment service for correlated incidents (MITRE rollup, TTFMA, and narrative explanation)."""

from sentinelx.schemas.common import Technique, UtcDatetime
from sentinelx.schemas.signal import Signal

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
    first_signal_ts: UtcDatetime,
) -> tuple[UtcDatetime | None, float | None]:
    """Calculate Time To First Meaningful Alert (TTFMA).

    Definition:
    A meaningful alert is defined as the first detection signal with confidence >= 0.80
    or from a deterministic high-fidelity detector ('rule' or 'deception') that elevates
    the incident towards actionable SOC triage. TTFMA is the elapsed duration in seconds
    from the incident's earliest telemetry signal (first_signal_ts) to this alert.
    """
    sorted_signals = sorted(signals, key=lambda s: s.ts)
    for s in sorted_signals:
        is_high_fidelity = s.detector in MEANINGFUL_DETECTORS
        is_high_confidence = s.confidence >= MEANINGFUL_CONFIDENCE_THRESHOLD

        if is_high_fidelity or is_high_confidence:
            meaningful_ts: UtcDatetime = s.ts
            # Difference in seconds
            dt_diff = (meaningful_ts - first_signal_ts).total_seconds()
            ttfma_sec = max(0.0, round(dt_diff, 2))
            return meaningful_ts, ttfma_sec

    return None, None


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
