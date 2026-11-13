"""Event Normalizer bridging LotL deception interactions into canonical SentinelX events."""

from datetime import UTC, datetime
from typing import Any

from sentinelx.schemas.common import Domain, Outcome, SourceTool, UtcDatetime
from sentinelx.schemas.deception import LotLInteraction, LotLLure
from sentinelx.schemas.event import Event


def normalize_lotl_event(
    interaction: LotLInteraction,
    lure: LotLLure,
    ingested_at: UtcDatetime | None = None,
) -> Event:
    """Construct a canonical Event from an attributed LotL interaction."""
    now = ingested_at or datetime.now(UTC)

    tags = [
        "decoy",
        "lotl",
        f"lure_id:{lure.lure_id}",
        f"lure_type:{lure.lure_type}",
        f"interaction_type:{interaction.interaction_type}",
    ]
    if lure.mitre_techniques:
        for t in lure.mitre_techniques:
            tags.append(f"technique:{t}")

    action = interaction.interaction_type
    category = "file" if "read" in action or "file" in action else "process"
    if "ssh" in action or "login" in action or "presented" in action:
        category = "authentication"

    raw_data: dict[str, Any] = {
        "lure_id": lure.lure_id,
        "lure_name": lure.name,
        "lure_type": lure.lure_type,
        "target_path": lure.path,
        "decoy_destination": lure.decoy_destination,
        "cmdline": interaction.cmdline,
        "evidence_source": interaction.evidence_source,
    }

    return Event(
        event_id=interaction.event_id,
        ts=interaction.ts,
        ingested_at=now,
        source_tool=SourceTool.generic,
        domain=Domain.decoy,
        category=category,
        action=action,
        outcome=interaction.outcome or Outcome.success,
        host=interaction.host,
        user=interaction.user,
        process=interaction.process,
        cmdline=interaction.cmdline,
        raw_ref=interaction.raw_ref or {"file": lure.path, "offset": 0},
        raw=raw_data,
        tags=tags,
    )

