"""Isolation Forest unsupervised anomaly detector for entity behavior."""

import hashlib
import logging
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from sentinelx.detect.anomaly.trainer import FEATURE_NAMES, load_anomaly_bundle
from sentinelx.detect.utils import extract_event_entities
from sentinelx.enrich.mitre import MitreCatalog, get_mitre_catalog
from sentinelx.schemas.common import Technique
from sentinelx.schemas.event import Event
from sentinelx.schemas.signal import Signal

logger = logging.getLogger("anomaly_detector")


class AnomalyDetector:
    """Detects behavioral anomalies using an Isolation Forest trained on benign sliding-window features."""

    def __init__(
        self,
        bundle: dict[str, Any] | None = None,
        bundle_path: Path | str | None = None,
        mitre: MitreCatalog | None = None,
        window_sec: float | None = None,
    ):
        if bundle is not None:
            self.bundle = bundle
        elif bundle_path is not None:
            self.bundle = load_anomaly_bundle(bundle_path)
        else:
            default_path = (
                Path(__file__).resolve().parents[4] / "data" / "models" / "isolation_forest.joblib"
            )
            if default_path.is_file():
                self.bundle = load_anomaly_bundle(default_path)
            else:
                self.bundle = None

        self.mitre = mitre or get_mitre_catalog()
        self.window_sec = (
            window_sec
            if window_sec is not None
            else (self.bundle.get("window_sec", 300.0) if self.bundle else 300.0)
        )
        self._windows: dict[str, deque[Event]] = defaultdict(deque)

    def reset_state(self) -> None:
        """Reset sliding window state (used between replay runs)."""
        self._windows.clear()

    def evaluate_event(self, event: Event) -> list[Signal]:
        """Evaluate event against Isolation Forest and emit Signal if anomalous and explainable."""
        if self.bundle is None or "model" not in self.bundle:
            return []

        entity = event.user or event.host or event.src_ip
        if not entity:
            return []

        # Update sliding window for this entity
        q = self._windows[entity]
        q.append(event)
        while q and (event.ts - q[0].ts).total_seconds() > self.window_sec:
            q.popleft()

        count = len(q)
        hosts = set(ev.host for ev in q if ev.host)
        zones = set(ev.domain.value for ev in q if ev.domain)
        night_cnt = sum(1 for ev in q if ev.ts.hour in (22, 23, 0, 1, 2, 3, 4, 5))
        night_ratio = night_cnt / count if count > 0 else 0.0

        feat = [float(count), float(len(hosts)), float(len(zones)), float(night_ratio)]

        clf = self.bundle["model"]
        pred = clf.predict([feat])[0]
        if pred != -1:
            # Inlier, no anomaly
            return []

        # (b) Explainability check: compare against benign maximums / statistics
        max_feats = self.bundle.get("max_feats", [100.0, 10.0, 3.0, 1.0])
        reasons: list[str] = []

        if feat[0] > max_feats[0]:
            reasons.append(
                f"Rolling event count ({feat[0]:.0f}) exceeds benign baseline (max {max_feats[0]:.0f})"
            )
        if feat[1] > max_feats[1]:
            reasons.append(
                f"Multi-host spread ({feat[1]:.0f} hosts) exceeds benign baseline (max {max_feats[1]:.0f})"
            )
        if feat[2] > max_feats[2]:
            reasons.append(
                f"Cross-zone traversal across {feat[2]:.0f} distinct network zones (benign max {max_feats[2]:.0f})"
            )

        # Do not emit unexplained signals: must have at least one explicit deviation reason
        if not reasons:
            return []

        # Determine anomaly score
        score_val = float(abs(clf.score_samples([feat])[0]))
        normalized_score = min(round(score_val * 1.5, 3), 0.95)
        if normalized_score < 0.60:
            normalized_score = 0.75

        # Technique mapping
        technique = self.mitre.get("T1046") or self.mitre.get("T1078")
        techniques: list[Technique] = [technique] if technique else []

        # Deterministic signal ID
        id_material = f"ANOM-IF-001_{event.event_id}"
        sig_hash = hashlib.sha256(id_material.encode("utf-8")).hexdigest()[:16]
        signal_id = f"sig_{sig_hash}"

        explanation = f"Unsupervised windowed anomaly: {'; '.join(reasons)}"

        sig = Signal(
            signal_id=signal_id,
            ts=event.ts,
            detector="anomaly",
            rule_id="ANOM-IF-001",
            title=f"Unsupervised Behavioral Anomaly ({entity})",
            score=normalized_score,
            confidence=0.85,
            entities=extract_event_entities(event),
            evidence_event_ids=[event.event_id],
            techniques=techniques,
            explanation=explanation,
            metadata={
                "features": dict(zip(FEATURE_NAMES, feat)),
                "deviations": reasons,
                "window_sec": self.window_sec,
            },
        )
        return [sig]
