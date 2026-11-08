"""Incremental NetworkX graph detector tracking interactions, cross-zone paths, and scans."""

import hashlib
import logging
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

import networkx as nx

from sentinelx.detect.graph.model import GraphModel
from sentinelx.detect.graph.trainer import is_valid_unicast
from sentinelx.detect.utils import extract_event_entities
from sentinelx.enrich.mitre import MitreCatalog, get_mitre_catalog
from sentinelx.normalize.assets import AssetInventory, get_assets
from sentinelx.schemas.common import SourceTool
from sentinelx.schemas.event import Event
from sentinelx.schemas.signal import Signal

logger = logging.getLogger("graph_detector")


class GraphDetector:
    """Builds and updates an incremental NetworkX DiGraph of entity interactions.

    Emits Signals for:
    (a) Genuinely new interaction edges not in the known benign set.
    (b) Multi-hop cross-zone paths traversing multiple zone boundaries.
    (c) High out-degree discovery bursts in short time windows.
    """

    def __init__(
        self,
        model: GraphModel | None = None,
        model_path: Path | str | None = None,
        assets: AssetInventory | None = None,
        mitre: MitreCatalog | None = None,
        scan_window_seconds: float = 60.0,
        scan_threshold: int = 5,
    ):
        if model is not None:
            self.model = model
        elif model_path is not None:
            self.model = GraphModel.load(model_path)
        else:
            default_path = (
                Path(__file__).resolve().parents[4] / "data" / "models" / "known_edges.json"
            )
            if default_path.is_file():
                self.model = GraphModel.load(default_path)
            else:
                self.model = GraphModel()

        self.assets = assets or get_assets()
        self.mitre = mitre or get_mitre_catalog()
        self.scan_window_seconds = scan_window_seconds
        self.scan_threshold = scan_threshold

        # Incremental live graph
        self.graph = nx.DiGraph()
        # Out-degree tracking: entity -> deque of (timestamp, target)
        self._out_degree_history: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
        # Recent hops tracking for multi-hop path detection: target -> list of (source, timestamp)
        self._recent_hops: dict[str, list[tuple[str, datetime]]] = defaultdict(list)
        # Set of edges alerted as new
        self._alerted_edges: set[tuple[str, str]] = set()

    def reset_state(self) -> None:
        """Reset live graph and sliding window state between runs."""
        self.graph.clear()
        self._out_degree_history.clear()
        self._recent_hops.clear()
        self._alerted_edges.clear()

    def _resolve_zone(self, entity_str: str) -> str:
        """Resolve network zone for entity string (host:... or ip:...)."""
        if entity_str.startswith("host:"):
            name = entity_str[5:]
            h = self.assets.get_host_by_name(name)
            if h:
                return h.zone
        elif entity_str.startswith("ip:"):
            ip = entity_str[3:]
            zone = self.assets.get_zone_for_ip(ip)
            if zone:
                return zone
            h = self.assets.get_host_by_ip(ip)
            if h:
                return h.zone
        return "unknown"

    def evaluate_event(self, event: Event) -> list[Signal]:
        """Process incoming Event incrementally and detect graph anomalies."""
        signals: list[Signal] = []

        u = event.user
        h = event.host
        src = event.src_ip
        dst = event.dst_ip

        # Candidate interaction edges
        edges: list[tuple[str, str, str]] = []  # (u, v, kind)
        if u and h:
            edges.append((f"user:{u}", f"host:{h}", "auth"))
        if is_valid_unicast(src) and is_valid_unicast(dst):
            edges.append((f"ip:{src}", f"ip:{dst}", "net"))
        if event.ot and event.ot.device_id and h:
            edges.append((f"host:{h}", f"device:{event.ot.device_id}", "modbus"))

        for src_node, dst_node, kind in edges:
            edge_key = (src_node, dst_node)

            # (a) Genuinely NEW edge detection
            is_new = not self.model.is_known(src_node, dst_node)
            if is_new and not self.graph.has_edge(src_node, dst_node):
                if edge_key not in self._alerted_edges:
                    self._alerted_edges.add(edge_key)

                    if event.source_tool == SourceTool.evtx:
                        tid = "T1021" if kind in ("auth", "net") else "T0882"
                    else:
                        tid = "T1021.004" if kind in ("auth", "net") else "T0882"
                    tech = self.mitre.get(tid) or self.mitre.get("T1046")
                    techniques = [tech] if tech else []

                    id_mat = f"GRAPH-EDGE-001_{event.event_id}_{src_node}_{dst_node}"
                    sig_id = f"sig_{hashlib.sha256(id_mat.encode('utf-8')).hexdigest()[:16]}"

                    sig = Signal(
                        signal_id=sig_id,
                        ts=event.ts,
                        detector="graph",
                        rule_id="GRAPH-EDGE-001",
                        title=f"Unobserved Interaction Edge ({src_node} -> {dst_node})",
                        score=0.75,
                        confidence=0.80,
                        entities=extract_event_entities(event),
                        evidence_event_ids=[event.event_id],
                        techniques=techniques,
                        explanation=(
                            f"Graph topology: unprecedented interaction edge detected: "
                            f"{src_node} -> {dst_node} (kind={kind})"
                        ),
                        metadata={
                            "source_node": src_node,
                            "dest_node": dst_node,
                            "kind": kind,
                        },
                    )
                    signals.append(sig)

            # (b) Multi-hop cross-zone path detection
            if kind == "net":
                # Check if src_node was a target in an inbound hop recently
                src_zone = self._resolve_zone(src_node)
                dst_zone = self._resolve_zone(dst_node)

                # Record current hop
                self._recent_hops[dst_node].append((src_node, event.ts))
                # Purge older than 300s
                self._recent_hops[dst_node] = [
                    (s, t)
                    for (s, t) in self._recent_hops[dst_node]
                    if (event.ts - t).total_seconds() <= 300.0
                ]

                # Check prior hops into src_node
                prior_hops = self._recent_hops.get(src_node, [])
                for origin_node, hop_ts in prior_hops:
                    if origin_node == dst_node:
                        continue
                    origin_zone = self._resolve_zone(origin_node)
                    # Check if crosses more than one zone boundary
                    zones_set = {origin_zone, src_zone, dst_zone} - {"unknown"}
                    if len(zones_set) >= 2 and origin_zone != dst_zone:
                        path_str = f"{origin_node} ({origin_zone}) -> {src_node} ({src_zone}) -> {dst_node} ({dst_zone})"
                        path_key = (f"path_{origin_node}_{dst_node}",)
                        if path_key not in self._alerted_edges:
                            self._alerted_edges.add(path_key)  # type: ignore[arg-type]

                            tid = "T1021" if event.source_tool == SourceTool.evtx else "T1021.004"
                            tech = self.mitre.get(tid) or self.mitre.get("T1046")
                            techniques = [tech] if tech else []

                            id_mat = f"GRAPH-PATH-001_{event.event_id}_{path_str}"
                            sig_id = (
                                f"sig_{hashlib.sha256(id_mat.encode('utf-8')).hexdigest()[:16]}"
                            )

                            sig = Signal(
                                signal_id=sig_id,
                                ts=event.ts,
                                detector="graph",
                                rule_id="GRAPH-PATH-001",
                                title=f"Multi-Hop Cross-Zone Traversal ({origin_zone} -> {dst_zone})",
                                score=0.85,
                                confidence=0.85,
                                entities=extract_event_entities(event),
                                evidence_event_ids=[event.event_id],
                                techniques=techniques,
                                explanation=(
                                    f"Multi-hop cross-zone traversal detected across perimeters: {path_str}"
                                ),
                                metadata={
                                    "origin": origin_node,
                                    "pivot": src_node,
                                    "target": dst_node,
                                    "zones": list(zones_set),
                                },
                            )
                            signals.append(sig)
                            break

            # (c) High out-degree discovery proxy
            if kind == "net":
                q = self._out_degree_history[src_node]
                q.append((event.ts, dst_node))
                while q and (event.ts - q[0][0]).total_seconds() > self.scan_window_seconds:
                    q.popleft()

                distinct_targets = set(target for _, target in q)
                if len(distinct_targets) >= self.scan_threshold:
                    scan_key = (f"scan_{src_node}", len(distinct_targets))
                    if scan_key not in self._alerted_edges:
                        self._alerted_edges.add(scan_key)  # type: ignore[arg-type]

                        tech = self.mitre.get("T1046")
                        techniques = [tech] if tech else []

                        id_mat = (
                            f"GRAPH-SCAN-001_{event.event_id}_{src_node}_{len(distinct_targets)}"
                        )
                        sig_id = f"sig_{hashlib.sha256(id_mat.encode('utf-8')).hexdigest()[:16]}"

                        sig = Signal(
                            signal_id=sig_id,
                            ts=event.ts,
                            detector="graph",
                            rule_id="GRAPH-SCAN-001",
                            title=f"High Out-Degree Discovery Burst ({src_node})",
                            score=0.80,
                            confidence=0.85,
                            entities=extract_event_entities(event),
                            evidence_event_ids=[event.event_id],
                            techniques=techniques,
                            explanation=(
                                f"High out-degree discovery burst: entity '{src_node}' "
                                f"contacted {len(distinct_targets)} distinct targets in {self.scan_window_seconds}s"
                            ),
                            metadata={
                                "scanner": src_node,
                                "target_count": len(distinct_targets),
                                "targets": sorted(distinct_targets)[:10],
                            },
                        )
                        signals.append(sig)

            # Update live graph
            self.graph.add_node(src_node)
            self.graph.add_node(dst_node)
            self.graph.add_edge(src_node, dst_node, timestamp=event.ts, kind=kind)

        return signals
