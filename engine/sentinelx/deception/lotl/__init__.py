"""Living-off-the-Land (LotL) Deception Engine package."""

from sentinelx.deception.lotl.health import LureHealthMonitor
from sentinelx.deception.lotl.manager import LureManager
from sentinelx.deception.lotl.monitor import InteractionMonitor
from sentinelx.deception.lotl.normalizer import normalize_lotl_event
from sentinelx.deception.lotl.registry import LureRegistry

__all__ = [
    "InteractionMonitor",
    "LureHealthMonitor",
    "LureManager",
    "LureRegistry",
    "normalize_lotl_event",
]

