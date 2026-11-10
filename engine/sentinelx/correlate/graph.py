"""Incident attack graph and chronological timeline builder with evidence-backed provenance."""

from typing import Any

from sentinelx.normalize.assets import get_assets
from sentinelx.schemas.common import Technique, UtcDatetime
from sentinelx.schemas.event import Event
from sentinelx.schemas.incident import (
    GraphEdge,
    GraphNode,
    IncidentGraph,
    NetworkZone,
    ProvenanceType,
    TimelineEvent,
)
from sentinelx.schemas.signal import Signal


def _resolve_entity_zone(
    entity_type: str, entity_val: str
) -> tuple[NetworkZone, list[NetworkZone], dict[str, Any]]:
    """Resolve authoritative primary network zone, multi-zone memberships, and asset metadata."""
    assets = get_assets()
    val_clean = entity_val.strip()
    val_lower = val_clean.lower()

    # 1. Direct host lookup by name
    host_asset = assets.get_host_by_name(val_clean)
    if host_asset:
        primary_zone: NetworkZone = host_asset.zone
        # Multi-interface hosts (e.g. eng-ws has IT, OT, MGMT; jump-host has IT, DMZ, MGMT)
        all_zones: list[NetworkZone] = (
            [z for z in host_asset.ips.keys() if z in ("it", "dmz", "ot", "mgmt")]
            if host_asset.ips
            else [primary_zone]
        )  # type: ignore[assignment]
        if primary_zone not in all_zones:
            all_zones.insert(0, primary_zone)

        return (
            primary_zone,
            all_zones,
            {
                "role": host_asset.role,
                "hostname": host_asset.hostname or host_asset.name,
                "is_decoy": host_asset.is_decoy,
                "process_critical": host_asset.process_critical,
                "criticality": host_asset.criticality,
                "ips": host_asset.ips,
                "allowed_ot_writers": host_asset.allowed_ot_writers,
                "status": "untrusted_actor" if host_asset.role == "attacker" else None,
            },
        )

    # 2. IP lookup
    if entity_type == "ip" or any(c.isdigit() for c in val_clean):
        host_by_ip = assets.get_host_by_ip(val_clean)
        if host_by_ip:
            zone_for_ip = assets.get_zone_for_ip(val_clean) or host_by_ip.zone
            all_zones = (
                [z for z in host_by_ip.ips.keys() if z in ("it", "dmz", "ot", "mgmt")]
                if host_by_ip.ips
                else [zone_for_ip]
            )  # type: ignore[assignment]
            return (
                zone_for_ip,  # type: ignore[return-value]
                all_zones,
                {
                    "role": host_by_ip.role,
                    "hostname": host_by_ip.hostname or host_by_ip.name,
                    "is_decoy": host_by_ip.is_decoy,
                    "process_critical": host_by_ip.process_critical,
                    "criticality": host_by_ip.criticality,
                    "ips": host_by_ip.ips,
                    "status": "untrusted_actor" if host_by_ip.role == "attacker" else None,
                },
            )

        # Subnet-based fallback for standard SentinelX subnets
        subnet_zone = assets.get_zone_for_ip(val_clean)
        if subnet_zone in ("it", "dmz", "ot", "mgmt"):
            return subnet_zone, [subnet_zone], {"role": "internal_host"}  # type: ignore[return-value]

        # External IP check (non-lab IP address)
        return "external", ["external"], {"role": "external_source", "status": "untrusted_actor"}

    # 3. Known keywords in label
    if "cowrie" in val_lower or "opencanary" in val_lower or "decoy" in val_lower:
        return "dmz", ["dmz"], {"is_decoy": True, "role": "decoy"}
    if "plc" in val_lower or "modbus" in val_lower:
        return "ot", ["ot"], {"process_critical": True, "role": "programmable_logic_controller"}
    if "attacker" in val_lower or val_clean == "10.10.1.5":
        return "it", ["it"], {"role": "attacker", "status": "untrusted_actor"}
    if "jump" in val_lower or "file" in val_lower or "db" in val_lower or "eng" in val_lower:
        return "it", ["it"], {}

    return "unknown", ["unknown"], {}


def build_incident_graph(
    signals: list[Signal],
    events: list[Event] | None = None,
) -> IncidentGraph:
    """Build an IncidentGraph incrementally from correlated signals and evidence events."""
    nodes: dict[str, GraphNode] = {}
    edges_map: dict[tuple[str, str, str], GraphEdge] = {}

    sorted_signals = sorted(signals, key=lambda s: s.ts)

    # 1. Register entity nodes from signals
    for sig in sorted_signals:
        for ent in sig.entities:
            nid = f"{ent.type.value}:{ent.value.lower()}"
            zone, all_zones, meta = _resolve_entity_zone(ent.type.value, ent.value)
            is_decoy = bool(meta.get("is_decoy", False))
            is_critical = bool(meta.get("process_critical", False))
            is_attacker = meta.get("role") == "attacker" or meta.get("status") == "untrusted_actor"
            risk_level = (
                "critical" if is_critical else ("high" if (is_decoy or is_attacker) else "medium")
            )

            if nid not in nodes:
                nodes[nid] = GraphNode(
                    id=nid,
                    entity_id=ent.value,
                    type=ent.type.value,
                    label=ent.value,
                    hostname=meta.get("hostname"),
                    ip_address=ent.value if ent.type.value == "ip" else None,
                    network_zone=zone,
                    network_zones=all_zones,
                    first_seen=sig.ts,
                    last_seen=sig.ts,
                    first_observed_event_id=sig.evidence_event_ids[0]
                    if sig.evidence_event_ids
                    else None,
                    last_observed_event_id=sig.evidence_event_ids[-1]
                    if sig.evidence_event_ids
                    else None,
                    status="untrusted_actor"
                    if is_attacker
                    else ("decoy" if is_decoy else ("targeted" if is_critical else "active")),
                    risk_level=risk_level,
                    evidence_count=len(sig.evidence_event_ids),
                    metadata=meta,
                )
            else:
                existing = nodes[nid]
                nodes[nid] = existing.model_copy(
                    update={
                        "last_seen": max(existing.last_seen or sig.ts, sig.ts),
                        "evidence_count": existing.evidence_count + len(sig.evidence_event_ids),
                    }
                )

        # 2. Derive relationship edges based on detector, rule, or entity topology
        rule_id = (sig.rule_id or "").upper()
        evidence_ids = list(sig.evidence_event_ids)
        ts: UtcDatetime = sig.ts
        confidence = float(sig.confidence)

        # Detect hosts, users, devices in signal
        entity_nodes = [
            nodes[f"{ent.type.value}:{ent.value.lower()}"]
            for ent in sig.entities
            if f"{ent.type.value}:{ent.value.lower()}" in nodes
        ]
        hosts = [n for n in entity_nodes if n.type == "host"]
        users = [n for n in entity_nodes if n.type == "user"]
        ips = [n for n in entity_nodes if n.type == "ip"]

        if rule_id == "RULE-AUTH-001":
            # Direct SSH Authentication attempt or session
            src = ips[0].id if ips else (users[0].id if users else None)
            dst = hosts[0].id if hosts else None
            if src and dst and src != dst:
                _add_edge(
                    edges_map=edges_map,
                    src=src,
                    dst=dst,
                    label="unexpected_ssh_login",
                    rel_type="ssh_authentication",
                    ts=ts,
                    event_ids=evidence_ids,
                    confidence=confidence,
                    provenance="observed",
                )

        elif rule_id in ("RULE-NET-001", "GRAPH-PATH-001", "GRAPH-EDGE-001"):
            # Lateral movement pivot inferred across hosts
            src = hosts[0].id if len(hosts) >= 1 else None
            dst = hosts[1].id if len(hosts) >= 2 else None
            if not src and ips:
                src = ips[0].id
            if src and dst and src != dst:
                _add_edge(
                    edges_map=edges_map,
                    src=src,
                    dst=dst,
                    label="lateral_pivot",
                    rel_type="lateral_pivot",
                    ts=ts,
                    event_ids=evidence_ids,
                    confidence=confidence,
                    provenance="inferred",  # Inferred lateral attack movement!
                )

        elif rule_id == "RULE-OT-001" or any(t.technique_id == "T0855" for t in sig.techniques):
            # Direct Modbus OT write command
            src = hosts[0].id if hosts else None
            dst = None
            for d in entity_nodes:
                if "plc" in d.label.lower():
                    dst = d.id
                elif "eng" in d.label.lower() and not src:
                    src = d.id
            if not dst:
                dst = (
                    "device:plc-sim"
                    if "device:plc-sim" in nodes
                    else ("host:plc-sim" if "host:plc-sim" in nodes else None)
                )
            if src and dst and src != dst:
                _add_edge(
                    edges_map=edges_map,
                    src=src,
                    dst=dst,
                    label="modbus_write_command",
                    rel_type="modbus_write_command",
                    ts=ts,
                    event_ids=evidence_ids,
                    confidence=confidence,
                    provenance="observed",
                )

        elif (
            sig.detector == "deception"
            or rule_id == "RULE-DECOY-001"
            or any(t.technique_id == "T0846" for t in sig.techniques)
        ):
            # Direct Decoy interaction
            src = hosts[0].id if hosts else (ips[0].id if ips else None)
            dst_label = "cowrie"
            if "opencanary" in sig.explanation.lower():
                dst_label = "opencanary"
            elif "decoy-plc" in sig.explanation.lower() or "10.10.3.60" in sig.explanation:
                dst_label = "decoy-plc"
            dst = f"host:{dst_label}"
            if dst not in nodes:
                zone, all_z, meta = _resolve_entity_zone("host", dst_label)
                nodes[dst] = GraphNode(
                    id=dst,
                    entity_id=dst_label,
                    type="host",
                    label=dst_label,
                    network_zone=zone,
                    network_zones=all_z,
                    first_seen=ts,
                    last_seen=ts,
                    status="decoy",
                    risk_level="high",
                    evidence_count=len(evidence_ids),
                    metadata=meta,
                )
            if src and dst and src != dst:
                _add_edge(
                    edges_map=edges_map,
                    src=src,
                    dst=dst,
                    label="decoy_interaction",
                    rel_type="decoy_interaction",
                    ts=ts,
                    event_ids=evidence_ids,
                    confidence=confidence,
                    provenance="observed",
                )

        elif users and hosts and users[0].id != hosts[0].id:
            _add_edge(
                edges_map=edges_map,
                src=users[0].id,
                dst=hosts[0].id,
                label="authenticated_session",
                rel_type="authentication",
                ts=ts,
                event_ids=evidence_ids,
                confidence=confidence,
                provenance="observed",
            )

    # 3. Associate raw evidence events if provided
    for ev in events or []:
        for nid, node in list(nodes.items()):
            label_lower = node.label.lower()
            ev_host = (ev.host or "").lower()
            ev_src_ip = ev.src_ip or ""
            ev_dst_ip = ev.dst_ip or ""
            ev_user = (ev.user or "").lower()

            matches = (
                node.id == f"ip:{ev_src_ip}"
                or node.id == f"ip:{ev_dst_ip}"
                or node.id == f"host:{ev_host}"
                or node.id == f"user:{ev_user}"
                or label_lower in (ev_host, ev_src_ip, ev_dst_ip, ev_user)
            )
            if matches:
                nodes[nid] = node.model_copy(
                    update={
                        "first_seen": min(node.first_seen or ev.ts, ev.ts),
                        "last_seen": max(node.last_seen or ev.ts, ev.ts),
                        "evidence_count": node.evidence_count + 1,
                    }
                )

    return IncidentGraph(
        nodes=list(nodes.values()),
        edges=list(edges_map.values()),
    )


def _add_edge(
    edges_map: dict[tuple[str, str, str], GraphEdge],
    src: str,
    dst: str,
    label: str,
    rel_type: str,
    ts: UtcDatetime,
    event_ids: list[str],
    confidence: float = 1.0,
    provenance: ProvenanceType = "observed",
) -> None:
    if not src or not dst or src == dst:
        return

    key = (src, dst, label)
    deterministic_id = f"edge:{src}->{dst}:{rel_type}"

    if key in edges_map:
        existing = edges_map[key]
        merged_ids = list(dict.fromkeys(existing.event_ids + event_ids))
        earliest_ts = min(existing.first_observed_at or existing.ts, ts)
        latest_ts = max(existing.last_observed_at or existing.ts, ts)
        edges_map[key] = existing.model_copy(
            update={
                "ts": latest_ts,
                "first_observed_at": earliest_ts,
                "last_observed_at": latest_ts,
                "event_ids": merged_ids,
                "confidence": max(existing.confidence, confidence),
            }
        )
    else:
        edges_map[key] = GraphEdge(
            id=deterministic_id,
            source=src,
            target=dst,
            label=label,
            relationship_type=rel_type,
            ts=ts,
            first_observed_at=ts,
            last_observed_at=ts,
            event_ids=list(dict.fromkeys(event_ids)),
            confidence=confidence,
            provenance=provenance,
            observation_status=provenance,
        )


def build_incident_timeline(
    incident_id: str,
    events: list[Event],
    signals: list[Signal],
) -> list[TimelineEvent]:
    """Reconstruct a deterministic, chronologically sorted attack timeline with human descriptions."""
    # Build lookup for signals by evidence event ID
    event_to_signals: dict[str, list[Signal]] = {}
    for sig in signals:
        for eid in sig.evidence_event_ids:
            event_to_signals.setdefault(eid, []).append(sig)

    # Sort events deterministically by timestamp, then event_id
    sorted_events = sorted(events, key=lambda e: (e.ts, e.event_id))

    timeline: list[TimelineEvent] = []

    for ev in sorted_events:
        related_sigs = event_to_signals.get(ev.event_id, [])
        technique: Technique | None = None
        for s in related_sigs:
            if s.techniques:
                technique = s.techniques[0]
                break

        title, description, src_node, dst_node, severity = _format_timeline_entry(ev, related_sigs)

        tle = TimelineEvent(
            id=f"tle_{ev.event_id}",
            event_id=ev.event_id,
            signal_id=related_sigs[0].signal_id if related_sigs else None,
            incident_id=incident_id,
            timestamp=ev.ts,
            event_type=ev.action or ev.category,
            category=ev.category,
            title=title,
            description=description,
            source_node_id=src_node,
            target_node_id=dst_node,
            severity=severity,
            evidence_reference=f"{ev.source_tool.value if hasattr(ev.source_tool, 'value') else ev.source_tool} ({ev.domain.value if hasattr(ev.domain, 'value') else ev.domain})",
            provenance="observed",
            mitre_technique=technique,
            metadata={
                "outcome": str(ev.outcome.value if hasattr(ev.outcome, "value") else ev.outcome),
                "protocol": ev.protocol,
                "src_ip": ev.src_ip,
                "dst_ip": ev.dst_ip,
                "src_port": ev.src_port,
                "dst_port": ev.dst_port,
                "host": ev.host,
                "user": ev.user,
                "ot": ev.ot.model_dump() if ev.ot else None,
            },
        )
        timeline.append(tle)

    return timeline


def _format_timeline_entry(
    ev: Event,
    signals: list[Signal],
) -> tuple[str, str, str | None, str | None, Any]:
    """Format human-readable title, narrative description, node IDs, and severity."""
    action = (ev.action or "").lower()
    cat = (ev.category or "").lower()
    domain = ev.domain.value if hasattr(ev.domain, "value") else str(ev.domain)
    outcome_str = (ev.outcome.value if hasattr(ev.outcome, "value") else str(ev.outcome)).lower()

    src_node = f"ip:{ev.src_ip}" if ev.src_ip else None
    dst_node = f"host:{ev.host}" if ev.host else (f"ip:{ev.dst_ip}" if ev.dst_ip else None)

    # Determine severity
    if any(s.score >= 0.8 for s in signals) or domain == "ot" or (ev.ot and ev.ot.is_write):
        severity = "critical"
    elif any(s.score >= 0.6 for s in signals) or domain == "decoy":
        severity = "high"
    elif any(s.score >= 0.3 for s in signals):
        severity = "medium"
    else:
        severity = "low"

    is_success = outcome_str in ("success", "allow", "permitted", "ok")

    # Category-specific descriptions
    if domain == "ot" or cat == "ot_command" or ev.ot:
        is_write = ev.ot.is_write if ev.ot else False
        reg = ev.ot.register if ev.ot else "N/A"
        val = ev.ot.value if ev.ot else "N/A"
        fc = ev.ot.function_code if ev.ot else "N/A"

        if is_write:
            if is_success:
                title = f"Unauthorized Modbus OT Write to Register {reg}"
                desc = (
                    f"Modbus write command delivered to PLC '{ev.host or ev.dst_ip}' "
                    f"(FC={fc}, Reg={reg}, Value={val}) by '{ev.src_ip or 'unknown'}'. "
                    f"Recorded outcome: {outcome_str} (telemetry confirms command delivery to PLC controller)."
                )
            else:
                title = f"Modbus OT Write Attempt Blocked/Failed (Reg {reg})"
                desc = (
                    f"Modbus write attempt to PLC '{ev.host or ev.dst_ip}' "
                    f"(FC={fc}, Reg={reg}, Value={val}) by '{ev.src_ip or 'unknown'}'. "
                    f"Recorded outcome: {outcome_str} (command blocked or rejected by controller)."
                )
        else:
            title = f"Modbus OT Telemetry Query (FC={fc})"
            desc = (
                f"Modbus read query issued to PLC '{ev.host or ev.dst_ip}' "
                f"(Reg={reg}) by '{ev.src_ip or 'unknown'}'."
            )
        dst_node = dst_node or "host:plc-sim"
        return title, desc, src_node, dst_node, severity

    if domain == "decoy" or cat == "decoy_interaction":
        decoy_name = ev.host or "deception decoy"
        title = f"Attacker Interaction on Decoy Asset ({decoy_name})"
        desc = (
            f"Adversary activity detected on honeypot decoy '{decoy_name}' "
            f"from source '{ev.src_ip or 'unknown'}'. Action: {ev.action}. "
            f"Recorded outcome: {outcome_str}."
        )
        return title, desc, src_node, dst_node, severity

    if cat == "authentication" or "login" in action or "auth" in action:
        user = ev.user or "unspecified user"
        host = ev.host or ev.dst_ip or "jump host"
        if is_success:
            title = f"Authentication Observed on {host}"
            desc = (
                f"Session authentication recorded for account '{user}' on '{host}' "
                f"originating from '{ev.src_ip or 'internal'}'. Protocol: {ev.protocol or 'SSH'}."
            )
        else:
            title = f"Failed Authentication Attempt on {host}"
            desc = (
                f"Failed authentication attempt for account '{user}' on '{host}' "
                f"from '{ev.src_ip or 'internal'}'. Outcome: {outcome_str}."
            )
        return title, desc, src_node, dst_node, severity

    if cat == "network" or "conn" in action:
        port_info = f":{ev.dst_port}" if ev.dst_port else ""
        proto = ev.protocol or "TCP"
        target_name = (
            f"{ev.host} ({ev.dst_ip})"
            if ev.host and ev.dst_ip
            else (ev.host or ev.dst_ip or "internal host")
        )
        title = f"Network Connection Observed: {ev.src_ip} -> {target_name}{port_info}"
        desc = (
            f"Network traffic observed between source '{ev.src_ip}' and destination "
            f"'{target_name}' over {proto}{port_info}."
        )
        return title, desc, src_node, dst_node, severity

    if cat == "process" or ev.cmdline:
        cmd_preview = (
            ev.cmdline[:80] + "..."
            if ev.cmdline and len(ev.cmdline) > 80
            else (ev.cmdline or ev.process or "command")
        )
        if is_success:
            title = f"Command Execution on {ev.host or 'Host'}"
            desc = (
                f"Process '{ev.process or 'shell'}' executed on '{ev.host}': `{cmd_preview}`. "
                f"Outcome: {outcome_str}."
            )
        else:
            title = f"Command Submission Attempt on {ev.host or 'Host'}"
            desc = (
                f"Command submission recorded for process '{ev.process or 'shell'}' on '{ev.host}': `{cmd_preview}`. "
                f"Outcome: {outcome_str}."
            )
        return title, desc, src_node, dst_node, severity

    # Fallback generic presentation
    title = f"Telemetry Event: {ev.action.replace('_', ' ').capitalize()}"
    desc = (
        f"Recorded {ev.source_tool} log entry in {domain} domain on host '{ev.host or ev.src_ip or 'internal'}'. "
        f"Action: {ev.action}. Outcome: {outcome_str}."
    )
    return title, desc, src_node, dst_node, severity
