"""Incident attack graph builder constructing entity nodes and relationship edges."""

from sentinelx.schemas.common import UtcDatetime
from sentinelx.schemas.incident import GraphEdge, GraphNode, IncidentGraph
from sentinelx.schemas.signal import Signal


def build_incident_graph(signals: list[Signal]) -> IncidentGraph:
    """Build an IncidentGraph incrementally from a set of correlated signals."""
    nodes: dict[str, GraphNode] = {}
    edges_map: dict[tuple[str, str, str], GraphEdge] = {}

    for sig in sorted(signals, key=lambda s: s.ts):
        # 1. Register entity nodes
        entity_nodes: list[GraphNode] = []
        for ent in sig.entities:
            nid = f"{ent.type.value}:{ent.value.lower()}"
            if nid not in nodes:
                nodes[nid] = GraphNode(
                    id=nid,
                    type=ent.type.value,
                    label=ent.value,
                )
            entity_nodes.append(nodes[nid])

        # 2. Derive relationship edges based on detector, rule, or entity topology
        rule_id = (sig.rule_id or "").upper()
        evidence_ids = list(sig.evidence_event_ids)
        ts: UtcDatetime = sig.ts

        # Detect hosts, users, devices in signal
        hosts = [n for n in entity_nodes if n.type == "host"]
        users = [n for n in entity_nodes if n.type == "user"]
        ips = [n for n in entity_nodes if n.type == "ip"]

        if rule_id == "RULE-AUTH-001":
            # Attacker IP / User -> Jump Host
            src = ips[0].id if ips else (users[0].id if users else "unknown")
            dst = hosts[0].id if hosts else "host:jump-host"
            label = "unexpected_ssh_login"
            _add_edge(edges_map, src, dst, label, ts, evidence_ids)

        elif rule_id in ("RULE-NET-001", "GRAPH-PATH-001", "GRAPH-EDGE-001"):
            # Lateral movement pivot: jump-host -> eng-ws
            if len(hosts) >= 2:
                _add_edge(edges_map, hosts[0].id, hosts[1].id, "lateral_pivot", ts, evidence_ids)
            else:
                _add_edge(
                    edges_map,
                    "host:jump-host",
                    hosts[0].id if hosts else "host:eng-ws",
                    "lateral_pivot",
                    ts,
                    evidence_ids,
                )

        elif rule_id == "RULE-OT-001" or any(t.technique_id == "T0855" for t in sig.techniques):
            # OT write: eng-ws -> plc-sim
            src = hosts[0].id if hosts else "host:eng-ws"
            dst = "host:plc-sim"
            for h in hosts:
                if "plc" in h.label.lower():
                    dst = h.id
                elif "eng" in h.label.lower():
                    src = h.id
            _add_edge(edges_map, src, dst, "modbus_write_command", ts, evidence_ids)

        elif (
            sig.detector == "deception"
            or rule_id == "RULE-DECOY-001"
            or any(t.technique_id == "T0846" for t in sig.techniques)
        ):
            # Decoy interaction
            src = hosts[0].id if hosts else (users[0].id if users else "host:jump-host")
            dst_label = "cowrie"
            if "opencanary" in sig.explanation.lower():
                dst_label = "opencanary"
            elif "decoy-plc" in sig.explanation.lower() or "10.10.3.60" in sig.explanation:
                dst_label = "decoy-plc"
            dst = f"host:{dst_label}"
            if dst not in nodes:
                nodes[dst] = GraphNode(id=dst, type="host", label=dst_label)
            _add_edge(edges_map, src, dst, "decoy_interaction", ts, evidence_ids)

        elif users and hosts:
            _add_edge(
                edges_map, users[0].id, hosts[0].id, "authenticated_session", ts, evidence_ids
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
    ts: UtcDatetime,
    event_ids: list[str],
) -> None:
    key = (src, dst, label)
    if key in edges_map:
        existing = edges_map[key]
        merged_ids = list(dict.fromkeys(existing.event_ids + event_ids))
        edges_map[key] = GraphEdge(
            source=src,
            target=dst,
            label=label,
            ts=ts,
            event_ids=merged_ids,
        )
    else:
        edges_map[key] = GraphEdge(
            source=src,
            target=dst,
            label=label,
            ts=ts,
            event_ids=list(dict.fromkeys(event_ids)),
        )
