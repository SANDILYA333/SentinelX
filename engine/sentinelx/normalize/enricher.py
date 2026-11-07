"""Normalization and enrichment engine resolving asset metadata, zones, and domains."""

from sentinelx.normalize.assets import AssetInventory, get_assets
from sentinelx.schemas.common import Domain, SourceTool
from sentinelx.schemas.event import Event


class EventEnricher:
    """Enriches normalized events with assets topology, cross-zone boundaries, and domain rules."""

    def __init__(self, assets: AssetInventory | None = None):
        self.assets = assets or get_assets()

    def enrich(self, event: Event) -> Event:
        """Apply asset enrichment, tag generation, and domain classification without mutating raw."""
        tags = list(event.tags)

        # 1. Resolve host and IP if one is missing
        host = event.host
        dst_ip = event.dst_ip
        src_ip = event.src_ip

        if not host:
            if dst_ip:
                h_asset = self.assets.get_host_by_ip(dst_ip)
                if h_asset:
                    host = h_asset.name
            elif src_ip:
                h_asset = self.assets.get_host_by_ip(src_ip)
                if h_asset:
                    host = h_asset.name

        if not dst_ip and host:
            h_asset = self.assets.get_host_by_name(host)
            if h_asset and h_asset.ips:
                # Use primary IP for the host's zone
                dst_ip = h_asset.ips.get(h_asset.zone) or next(iter(h_asset.ips.values()))

        # 2. Resolve Zones
        src_zone = self.assets.get_zone_for_ip(src_ip) if src_ip else None
        dst_zone = self.assets.get_zone_for_ip(dst_ip) if dst_ip else None

        if not dst_zone and host:
            h_asset = self.assets.get_host_by_name(host)
            if h_asset:
                dst_zone = h_asset.zone

        if src_zone and f"zone:{src_zone}" not in tags:
            tags.append(f"zone:{src_zone}")
        if dst_zone and f"zone:{dst_zone}" not in tags:
            tags.append(f"zone:{dst_zone}")

        src_host_asset = self.assets.get_host_by_ip(src_ip) if src_ip else None
        effective_src_zone = src_host_asset.zone if src_host_asset else src_zone

        if effective_src_zone and dst_zone and effective_src_zone != dst_zone:
            cross_tag = f"cross_zone:{effective_src_zone}->{dst_zone}"
            if cross_tag not in tags:
                tags.append(cross_tag)
        elif src_zone and dst_zone and src_zone != dst_zone:
            cross_tag = f"cross_zone:{src_zone}->{dst_zone}"
            if cross_tag not in tags:
                tags.append(cross_tag)

        # 3. Decoy Tagging
        is_dst_decoy = bool(
            (dst_ip and self.assets.is_decoy(dst_ip)) or (host and self.assets.is_decoy(host))
        )
        is_src_decoy = bool(src_ip and self.assets.is_decoy(src_ip))
        is_decoy_tool = event.source_tool in (SourceTool.cowrie, SourceTool.opencanary)

        if is_dst_decoy or is_src_decoy or is_decoy_tool or event.category == "decoy_interaction":
            if "decoy" not in tags:
                tags.append("decoy")

        # 4. Honey User Tagging
        if event.user and self.assets.is_honey_user(event.user):
            if "honey_user" not in tags:
                tags.append("honey_user")

        # 5. Domain Rule:
        # "decoy if source is decoy or dst is a decoy; else ot if dst zone is ot or category is ot_*; else it."
        if is_dst_decoy or is_src_decoy or is_decoy_tool or event.category == "decoy_interaction":
            domain = Domain.decoy
        elif (
            dst_zone == "ot"
            or src_zone == "ot"
            or event.category.startswith("ot_")
            or event.source_tool == SourceTool.modbus
        ):
            domain = Domain.ot
        else:
            domain = Domain.it

        # Return a copy with enriched fields (frozen schema compliant, raw untouched)
        return event.model_copy(
            update={
                "host": host,
                "dst_ip": dst_ip,
                "domain": domain,
                "tags": tags,
            }
        )
