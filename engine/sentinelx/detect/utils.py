"""Common utility functions for detection engines."""

from sentinelx.schemas.common import Entity, EntityType
from sentinelx.schemas.event import Event


def extract_event_entities(event: Event) -> list[Entity]:
    """Extract observable entities (user, host, IPs, process, device, session) from an Event."""
    entities: list[Entity] = []
    seen: set[tuple[str, str]] = set()

    def add(t: EntityType, v: str | None):
        if not v:
            return
        clean_v = str(v).strip()
        if not clean_v:
            return
        key = (t.value, clean_v)
        if key not in seen:
            seen.add(key)
            entities.append(Entity(type=t, value=clean_v))

    add(EntityType.user, event.user)
    add(EntityType.host, event.host)
    add(EntityType.ip, event.src_ip)
    add(EntityType.ip, event.dst_ip)
    add(EntityType.process, event.process)
    if event.ot and event.ot.device_id:
        add(EntityType.device, event.ot.device_id)
    if event.session_id:
        add(EntityType.session, event.session_id)

    return entities
