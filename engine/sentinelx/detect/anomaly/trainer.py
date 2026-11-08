"""Isolation Forest anomaly model trainer using explainable windowed features."""

import asyncio
import json
import logging
import shutil
import tempfile
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from sentinelx.ingest.runtime import Ingestor
from sentinelx.schemas.event import Event

logger = logging.getLogger("anomaly_trainer")

FEATURE_NAMES = [
    "rolling_event_count",
    "distinct_hosts_touched",
    "distinct_zones_touched",
    "night_hour_activity_ratio",
]


async def load_capture_events(capture_dir: Path) -> list[Event]:
    """Ingest capture directory into a temporary SQLite database and return sorted Events."""
    temp_dir = Path(tempfile.mkdtemp(prefix="sx_anom_"))
    try:
        temp_db = temp_dir / "temp.db"
        ingestor = Ingestor(log_root=capture_dir, db=temp_db, mode="replay", speed="max")
        await ingestor.start()
        while ingestor._tasks and not all(t.done() for t in ingestor._tasks):
            await asyncio.sleep(0.02)
        await ingestor.stop()

        import sqlite3

        conn = sqlite3.connect(temp_db)
        rows = conn.execute("SELECT json FROM events ORDER BY ts ASC").fetchall()
        return [Event.model_validate_json(r[0]) for r in rows]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def extract_window_features(
    events: list[Event],
    window_sec: float = 300.0,
) -> list[tuple[str, Event, list[float]]]:
    """Extract rolling windowed features per entity for anomaly modeling."""
    entity_windows: dict[str, deque[Event]] = defaultdict(deque)
    records: list[tuple[str, Event, list[float]]] = []

    for e in events:
        entity = e.user or e.host or e.src_ip
        if not entity:
            continue
        q = entity_windows[entity]
        q.append(e)
        while q and (e.ts - q[0].ts).total_seconds() > window_sec:
            q.popleft()

        # 1. Rolling event count
        count = len(q)
        # 2. Distinct hosts touched
        hosts = set(ev.host for ev in q if ev.host)
        # 3. Distinct network zones touched
        zones = set(ev.domain.value for ev in q if ev.domain)
        # 4. Night hour activity ratio (22:00-06:00 UTC)
        night_cnt = sum(1 for ev in q if ev.ts.hour in (22, 23, 0, 1, 2, 3, 4, 5))
        ratio = night_cnt / count if count > 0 else 0.0

        feat = [float(count), float(len(hosts)), float(len(zones)), float(ratio)]
        records.append((entity, e, feat))

    return records


def train_anomaly_model(
    capture_dirs: list[Path | str],
    exclude_startup_sim_hours: float = 1.0,
    window_sec: float = 300.0,
    contamination: float = 0.01,
) -> dict[str, Any]:
    """Train Isolation Forest on benign captures and return model bundle."""
    all_feats: list[list[float]] = []

    for cap_path in capture_dirs:
        p = Path(cap_path)
        if not p.is_dir():
            continue

        events = asyncio.run(load_capture_events(p))
        if not events:
            continue

        t0 = events[0].ts
        sim_speed = 300.0
        manifest_file = p / "manifest.json"
        if manifest_file.exists():
            try:
                with open(manifest_file, "r", encoding="utf-8") as mf:
                    mdata = json.load(mf)
                    sim_speed = float(mdata.get("sim_speed", 300.0))
            except Exception:
                pass

        cutoff_sec = (3600.0 * exclude_startup_sim_hours) / sim_speed
        clean_events = [e for e in events if (e.ts - t0).total_seconds() >= cutoff_sec]

        records = extract_window_features(clean_events, window_sec=window_sec)
        all_feats.extend([r[2] for r in records])

    if not all_feats:
        raise ValueError("No feature vectors extracted from training captures")

    X_train = np.array(all_feats)
    max_feats = X_train.max(axis=0).tolist()
    mean_feats = X_train.mean(axis=0).tolist()
    std_feats = (X_train.std(axis=0) + 1e-4).tolist()

    clf = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
    )
    clf.fit(X_train)

    bundle = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "max_feats": max_feats,
        "mean_feats": mean_feats,
        "std_feats": std_feats,
        "window_sec": window_sec,
        "contamination": contamination,
        "trained_on_captures": [str(Path(c).name) for c in capture_dirs],
    }
    return bundle


def save_anomaly_bundle(bundle: dict[str, Any], file_path: Path | str) -> None:
    """Save trained Isolation Forest model bundle via joblib."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_anomaly_bundle(file_path: Path | str) -> dict[str, Any]:
    """Load Isolation Forest bundle via joblib."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Anomaly model bundle not found: {path}")
    return joblib.load(path)
