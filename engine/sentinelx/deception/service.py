"""Deception intelligence service for aggregation, querying, and asset inventory."""

import json
import logging
import sqlite3
from typing import Any

from sentinelx.deception.classifier import (
    classify_deception_event,
    generate_deception_interpretations,
)
from sentinelx.normalize.assets import get_assets
from sentinelx.schemas.deception import (
    DeceptionActivity,
    DeceptionAssetSummary,
    DeceptionOverview,
)
from sentinelx.schemas.event import Event

logger = logging.getLogger(__name__)


def _build_event_to_incident_map(db: sqlite3.Connection) -> dict[str, str]:
    """Map event_id to incident_id from incidents table."""
    mapping: dict[str, str] = {}
    cursor = db.cursor()
    rows = cursor.execute("SELECT incident_id, json FROM incidents").fetchall()
    for inc_id, j in rows:
        try:
            data = json.loads(j)
            for eid in data.get("event_ids", []):
                mapping[eid] = inc_id
        except Exception:
            continue
    return mapping


def list_deception_activities(
    db: sqlite3.Connection,
    incident_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[DeceptionActivity]:
    """Retrieve and classify deception activities from stored telemetry events."""
    event_incident_map = _build_event_to_incident_map(db)

    # Query events that match deception criteria
    query = """
        SELECT json FROM events
        WHERE domain = 'decoy'
           OR source_tool IN ('cowrie', 'opencanary')
           OR json_extract(json, '$.host') LIKE '%decoy%'
           OR json_extract(json, '$.host') IN ('backup-srv-02', 'db-prod-02', 'cowrie', 'opencanary', 'decoy-plc')
           OR json LIKE '%"decoy"%'
           OR json LIKE '%"lotl"%'
           OR json LIKE '%"lure_id%'
        ORDER BY ts DESC
    """
    cursor = db.cursor()
    rows = cursor.execute(query).fetchall()

    activities: list[DeceptionActivity] = []
    for r in rows:
        try:
            ev = Event.model_validate_json(r[0])
            mapped_inc_id = event_incident_map.get(ev.event_id)
            if incident_id and mapped_inc_id != incident_id:
                continue

            act = classify_deception_event(ev, incident_id=mapped_inc_id)
            if act:
                activities.append(act)
        except Exception as e:
            logger.debug("Failed to classify event as deception: %s", e)
            continue

    return activities[offset : offset + limit]


def get_deception_activity(db: sqlite3.Connection, activity_id: str) -> DeceptionActivity | None:
    """Retrieve an individual deception activity by its activity_id or event_id."""
    clean_id = activity_id.replace("decoy_act_", "")
    cursor = db.cursor()
    row = cursor.execute(
        "SELECT json FROM events WHERE event_id = ? OR event_id = ? OR event_id = ?",
        (activity_id, f"evt_{clean_id}", clean_id),
    ).fetchone()
    if not row:
        # Fallback search by scanning activities
        all_acts = list_deception_activities(db, limit=200)
        for a in all_acts:
            if a.activity_id == activity_id or a.event_id == activity_id:
                return a
        return None

    event_incident_map = _build_event_to_incident_map(db)
    ev = Event.model_validate_json(row[0])
    return classify_deception_event(ev, incident_id=event_incident_map.get(ev.event_id))


def get_deception_assets(db: sqlite3.Connection) -> list[DeceptionAssetSummary]:
    """Retrieve configured deception assets populated with live telemetry statistics."""
    assets = get_assets()
    activities = list_deception_activities(db, limit=500)

    # Group activities by decoy asset
    stats_by_asset: dict[str, dict[str, Any]] = {}
    for act in activities:
        key = act.decoy_asset.lower()
        if key not in stats_by_asset:
            stats_by_asset[key] = {
                "count": 0,
                "sources": set(),
                "last_seen": None,
                "incidents": set(),
            }
        stats_by_asset[key]["count"] += 1
        if act.src_ip:
            stats_by_asset[key]["sources"].add(act.src_ip)
        if act.incident_id:
            stats_by_asset[key]["incidents"].add(act.incident_id)
        if not stats_by_asset[key]["last_seen"] or act.ts > stats_by_asset[key]["last_seen"]:
            stats_by_asset[key]["last_seen"] = act.ts

    summaries: list[DeceptionAssetSummary] = []
    for host in assets.hosts:
        if not host.is_decoy:
            continue

        h_key = host.name.lower()
        stats = stats_by_asset.get(
            h_key,
            {
                "count": 0,
                "sources": set(),
                "last_seen": None,
                "incidents": set(),
            },
        )

        # Operational status: active if touched in telemetry, untouched otherwise
        status = "active" if stats["count"] > 0 else "untouched"

        summaries.append(
            DeceptionAssetSummary(
                name=host.name,
                hostname=host.hostname or host.name,
                role=host.role,
                zone=host.zone,
                ips=host.ips or {},
                total_interactions=stats["count"],
                unique_source_ips=sorted(list(stats["sources"])),
                last_seen=stats["last_seen"],
                associated_incident_ids=sorted(list(stats["incidents"])),
                status=status,
            )
        )

    return summaries


def get_deception_overview(db: sqlite3.Connection) -> DeceptionOverview:
    """Compute aggregated deception intelligence metrics and recent activity stream."""
    activities = list_deception_activities(db, limit=500)
    asset_summaries = get_deception_assets(db)

    unique_sources = sorted(list({a.src_ip for a in activities if a.src_ip}))
    incident_ids = {a.incident_id for a in activities if a.incident_id}

    # Top decoys by interaction count
    top_decoys = [
        {
            "name": asset.name,
            "hostname": asset.hostname,
            "role": asset.role,
            "zone": asset.zone,
            "interactions": asset.total_interactions,
            "status": asset.status,
        }
        for asset in sorted(asset_summaries, key=lambda a: a.total_interactions, reverse=True)
    ]

    # Category counts
    category_counts: dict[str, int] = {}
    for a in activities:
        category_counts[a.interaction_type] = category_counts.get(a.interaction_type, 0) + 1

    interpretations = generate_deception_interpretations(activities)

    return DeceptionOverview(
        total_interactions=len(activities),
        incident_count=len(incident_ids),
        unique_sources=unique_sources,
        top_decoys=top_decoys,
        category_counts=category_counts,
        recent_activities=activities[:25],
        deception_interpretations=interpretations,
    )
