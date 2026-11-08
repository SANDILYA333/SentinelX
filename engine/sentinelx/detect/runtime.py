"""Detector pipeline running independent detection engines over the Event stream."""

import inspect
import logging
import sqlite3
from pathlib import Path
from typing import Any, Callable

import yaml

from sentinelx.detect.anomaly.detector import AnomalyDetector
from sentinelx.detect.baseline.detector import BaselineDetector
from sentinelx.detect.graph.detector import GraphDetector
from sentinelx.detect.rules.engine import RulesEngine, load_rules
from sentinelx.enrich.mitre import MitreCatalog, get_mitre_catalog
from sentinelx.normalize.assets import AssetInventory, get_assets
from sentinelx.schemas.common import WSMessage
from sentinelx.schemas.event import Event
from sentinelx.schemas.signal import Signal
from sentinelx.store.sqlite import init_db, insert_signals_batch

logger = logging.getLogger("detector_pipeline")


def load_detector_config(config_path: Path | str | None = None) -> dict[str, Any]:
    """Load detector toggles and parameters from content/detectors.yaml."""
    if config_path is None:
        repo_root = Path(__file__).resolve().parents[4]
        cfg_file = repo_root / "content" / "detectors.yaml"
    else:
        cfg_file = Path(config_path)

    if cfg_file.is_file():
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict) and "detectors" in data:
                    return data["detectors"]
        except Exception as exc:
            logger.warning(f"Failed to load detectors.yaml ({exc}); using defaults")

    return {
        "rule": {"enabled": True},
        "baseline": {"enabled": True, "threshold": 0.60},
        "anomaly": {"enabled": True, "window_sec": 300.0},
        "graph": {"enabled": True, "scan_window_seconds": 60.0, "scan_threshold": 5},
        "deception": {"enabled": True},
    }


class DetectorPipeline:
    """Subscribes to normalized Event stream, runs all active detectors independently,

    persists Signals with deterministic idempotency, and dispatches real-time signal callbacks.
    """

    def __init__(
        self,
        db: sqlite3.Connection | Path | str,
        config_path: Path | str | None = None,
        on_signal: Callable[[Signal], Any] | None = None,
        active_detectors: list[str] | None = None,
        assets: AssetInventory | None = None,
        mitre: MitreCatalog | None = None,
    ):
        if isinstance(db, sqlite3.Connection):
            self.db = db
        else:
            self.db = init_db(db)

        self.on_signal = on_signal
        self.config = load_detector_config(config_path)
        self.assets = assets or get_assets()
        self.mitre = mitre or get_mitre_catalog()

        # Detector configuration toggles (supports ablation studies)
        if active_detectors is not None:
            self.active_set = set(active_detectors)
        else:
            self.active_set = {
                name for name, cfg in self.config.items() if cfg.get("enabled", True)
            }

        # Initialize independent detection engines
        self.rules_engine = RulesEngine(
            rules=load_rules(),
            assets=self.assets,
            mitre=self.mitre,
        )

        baseline_cfg = self.config.get("baseline", {})
        self.baseline_detector = BaselineDetector(
            mitre=self.mitre,
            threshold=float(baseline_cfg.get("threshold", 0.60)),
        )

        anomaly_cfg = self.config.get("anomaly", {})
        self.anomaly_detector = AnomalyDetector(
            mitre=self.mitre,
            window_sec=float(anomaly_cfg.get("window_sec", 300.0)),
        )

        graph_cfg = self.config.get("graph", {})
        self.graph_detector = GraphDetector(
            assets=self.assets,
            mitre=self.mitre,
            scan_window_seconds=float(graph_cfg.get("scan_window_seconds", 60.0)),
            scan_threshold=int(graph_cfg.get("scan_threshold", 5)),
        )

        logger.info(
            f"DetectorPipeline initialized with active detectors: {sorted(self.active_set)}"
        )

    def reset_state(self) -> None:
        """Reset internal caches and sliding windows across all engines (e.g. between replays)."""
        self.rules_engine.reset_state()
        self.baseline_detector.reset_state()
        self.anomaly_detector.reset_state()
        self.graph_detector.reset_state()

    def process_event(self, event: Event) -> list[Signal]:
        """Evaluate a single Event across all active detectors independently.

        Per architectural discipline:
        - Detectors run independently over the same Event stream.
        - No detector ever reads or depends on another detector's output.
        """
        emitted_signals: list[Signal] = []

        # 1. Rules & Deception Engine
        if "rule" in self.active_set or "deception" in self.active_set:
            try:
                rule_sigs = self.rules_engine.evaluate_event(event)
                for s in rule_sigs:
                    if s.detector == "deception" and "deception" not in self.active_set:
                        continue
                    if s.detector == "rule" and "rule" not in self.active_set:
                        continue
                    emitted_signals.append(s)
            except Exception as exc:
                logger.error(f"RulesEngine error evaluating event {event.event_id}: {exc}")

        # 2. Baseline Behavioral Detector
        if "baseline" in self.active_set:
            try:
                base_sigs = self.baseline_detector.evaluate_event(event)
                emitted_signals.extend(base_sigs)
            except Exception as exc:
                logger.error(f"BaselineDetector error evaluating event {event.event_id}: {exc}")

        # 3. Anomaly Isolation Forest Detector
        if "anomaly" in self.active_set:
            try:
                anom_sigs = self.anomaly_detector.evaluate_event(event)
                emitted_signals.extend(anom_sigs)
            except Exception as exc:
                logger.error(f"AnomalyDetector error evaluating event {event.event_id}: {exc}")

        # 4. Interaction Graph Detector
        if "graph" in self.active_set:
            try:
                graph_sigs = self.graph_detector.evaluate_event(event)
                emitted_signals.extend(graph_sigs)
            except Exception as exc:
                logger.error(f"GraphDetector error evaluating event {event.event_id}: {exc}")

        # Persist signals to SQLite database (idempotent INSERT OR IGNORE via deterministic signal_id)
        if emitted_signals:
            insert_signals_batch(self.db, emitted_signals)

            # Invoke callback / broadcast
            if self.on_signal:
                for sig in emitted_signals:
                    try:
                        res = self.on_signal(sig)
                        if inspect.iscoroutine(res):
                            # In async contexts caller can await or schedule
                            pass
                    except Exception as exc:
                        logger.warning(f"on_signal callback error for {sig.signal_id}: {exc}")

        return emitted_signals

    def format_ws_message(self, signal: Signal) -> WSMessage:
        """Format a Signal into a typed WSMessage envelope for live streaming."""
        return WSMessage(
            type="signal",
            ts=signal.ts,
            payload=signal.model_dump(mode="json"),
        )
