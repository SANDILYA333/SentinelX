"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  Background,
  Controls,
  Edge,
  MarkerType,
  MiniMap,
  Node,
  ReactFlow,
  useEdgesState,
  useNodesState,
  useReactFlow,
  ReactFlowProvider,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import type { Event, GraphEdge, GraphNode, GuardDecision, ResponseRecommendation, TimelineEvent } from "@contracts/index";
import { fetchGuardRecommendations, fetchIncidentById, type IncidentWithEvidence } from "@/lib/api";
import { useEvidenceDrawer } from "@/components/evidence-drawer";
import { EntityNode, type EntityNodeData } from "@/components/graph-nodes";
import { AttackTimeline } from "@/components/attack-timeline";
import { EvidenceInspector, type InspectorSelection } from "@/components/evidence-inspector";
import { ResponseGuardPanel } from "@/components/response-guard-panel";
import { useEventStream } from "@/hooks/useEventStream";
import { useEventStore } from "@/lib/store";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  GitGraph,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";

const nodeTypes = {
  entityNode: EntityNode,
};

// Zone horizontal anchor coordinates (Left to Right progression)
const ZONE_X_COORDS: Record<string, number> = {
  external: 60,
  it: 360,
  dmz: 880,
  ot: 1360,
  mgmt: 360,
  unknown: 620,
};

function getZonedLayout(nodes: Node[], edges: Edge[]): { nodes: Node[]; edges: Edge[] } {
  const zoneBuckets: Record<string, Node[]> = {
    external: [],
    it: [],
    dmz: [],
    ot: [],
    mgmt: [],
    unknown: [],
  };

  nodes.forEach((n) => {
    const data = n.data as EntityNodeData;
    // Use authoritative network_zone from canonical graph model.
    // Attacker role is distinct from network zone (e.g. 10.10.1.5 has role: attacker, zone: it).
    let zone = (data?.network_zone || "unknown").toLowerCase();
    if (zone === "unknown") {
      if (data?.name?.includes("wazuh")) zone = "mgmt";
      else if (data?.is_decoy || data?.name?.includes("decoy") || data?.name?.includes("cowrie") || data?.name?.includes("opencanary")) zone = "dmz";
      else if (data?.process_critical || data?.name?.includes("plc") || data?.type === "device") zone = "ot";
    }

    if (zoneBuckets[zone]) {
      zoneBuckets[zone].push(n);
    } else {
      zoneBuckets.unknown.push(n);
    }
  });

  const layoutedNodes: Node[] = [];

  // Position nodes within each zone with 2-column grid when crowded to avoid excessive vertical scrolling
  Object.entries(zoneBuckets).forEach(([zoneKey, zoneNodes]) => {
    const baseX = ZONE_X_COORDS[zoneKey] ?? 400;
    const startY = zoneKey === "mgmt" ? 420 : 60;
    const cols = zoneNodes.length > 5 ? 2 : 1;
    const spacingX = 230;
    const spacingY = 95;

    zoneNodes.forEach((node, index) => {
      const col = index % cols;
      const row = Math.floor(index / cols);
      layoutedNodes.push({
        ...node,
        position: {
          x: baseX + col * spacingX,
          y: startY + row * spacingY,
        },
      });
    });
  });

  return { nodes: layoutedNodes, edges };
}

function getDagreLayout(nodes: Node[], edges: Edge[], direction = "LR") {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({ rankdir: direction, nodesep: 60, ranksep: 100 });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 200, height: 80 });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPos = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPos ? nodeWithPos.x - 100 : 0,
        y: nodeWithPos ? nodeWithPos.y - 40 : 0,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

function findEventsForNode(node: Node, incident: IncidentWithEvidence): Event[] {
  const data = (node.data || {}) as EntityNodeData;
  const rawId = String(node.id || data.id || "");
  const nodeType = String(data.type || (rawId.includes(":") ? rawId.split(":")[0] : "")).toLowerCase();
  const nodeName = String(data.name || (rawId.includes(":") ? rawId.split(":")[1] : rawId)).toLowerCase();

  const isDecoy = Boolean(
    data.is_decoy ||
    nodeName.includes("cowrie") ||
    nodeName.includes("opencanary") ||
    nodeName.includes("decoy")
  );

  const isPlc = Boolean(
    data.process_critical ||
    nodeType === "device" ||
    nodeName.includes("plc") ||
    nodeName.includes("modbus")
  );

  // 1. Evidence event IDs cited by signals touching this entity
  const signalEvidenceIds = new Set<string>();
  for (const sig of incident.signals || []) {
    const touchesEntity = sig.entities?.some((ent) => {
      const entVal = ent.value.toLowerCase();
      const entType = ent.type.toLowerCase();
      return (
        entVal === nodeName ||
        (entType === nodeType && entVal === nodeName) ||
        `${entType}:${entVal}` === rawId.toLowerCase()
      );
    });
    if (touchesEntity && sig.evidence_event_ids) {
      sig.evidence_event_ids.forEach((id) => signalEvidenceIds.add(id));
    }
  }

  // 2. Filter evidence events
  const matched = (incident.evidence_events || []).filter((ev) => {
    if (signalEvidenceIds.has(ev.event_id)) return true;
    if (ev.src_ip === nodeName || ev.dst_ip === nodeName) return true;
    if (ev.host?.toLowerCase() === nodeName) return true;
    if (isPlc && (ev.domain === "ot" || Boolean(ev.ot) || ev.dst_ip === "10.10.3.20")) return true;
    if (isDecoy && (ev.domain === "decoy" || ["10.10.2.20", "10.10.2.30", "10.10.3.60"].includes(ev.dst_ip || ""))) return true;
    if (nodeType === "user" && ev.user?.toLowerCase() === nodeName) return true;
    return false;
  });

  return matched.sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
}

function findEventsForEdge(edge: Edge, incident: IncidentWithEvidence): Event[] {
  const edgeData = (edge.data || {}) as {
    evidence_ids?: string[];
  };
  const citedIds = new Set(edgeData.evidence_ids || []);
  const matched = (incident.evidence_events || []).filter((ev) => citedIds.has(ev.event_id));
  return matched.sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
}

function AttackGraphContent() {
  useEventStream();
  const searchParams = useSearchParams();
  const incidentParam = searchParams.get("incident_id");
  const { openEvidence } = useEvidenceDrawer();
  const reactFlow = useReactFlow();

  const { incidents } = useEventStore();
  const [selectedId, setSelectedId] = useState<string | null>(incidentParam);
  const [incidentDetail, setIncidentDetail] = useState<IncidentWithEvidence | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  // Playback state
  const [playbackIndex, setPlaybackIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);
  const playbackTimerRef = useRef<NodeJS.Timeout | null>(null);

  // Response Safety Guard Recommendations State
  const [recommendations, setRecommendations] = useState<ResponseRecommendation[]>([]);
  const [showGuardPanel, setShowGuardPanel] = useState<boolean>(false);

  // Unified Inspector Selection State
  const [inspectorSelection, setInspectorSelection] = useState<InspectorSelection | null>(null);

  // React Flow elements state
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  // Sync initial incident param
  useEffect(() => {
    if (incidentParam && !selectedId) {
      setSelectedId(incidentParam);
    } else if (!selectedId && incidents.length > 0) {
      setSelectedId(incidents[0].incident_id);
    }
  }, [incidentParam, incidents, selectedId]);

  // Load incident details and guard recommendations
  useEffect(() => {
    if (!selectedId) return;
    let active = true;
    setLoading(true);
    setInspectorSelection(null);
    setIsPlaying(false);

    fetchIncidentById(selectedId)
      .then((res) => {
        if (active) {
          setIncidentDetail(res);
          const timelineLength = res.timeline?.length || res.evidence_events?.length || 0;
          setPlaybackIndex(Math.max(0, timelineLength - 1));
        }
      })
      .catch((err) => {
        console.error("Failed to fetch incident graph:", err);
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    fetchGuardRecommendations(selectedId)
      .then((recs) => {
        if (active) setRecommendations(recs);
      })
      .catch((err) => {
        console.debug("Guard recommendations unavailable:", err);
      });

    return () => {
      active = false;
      if (playbackTimerRef.current) clearInterval(playbackTimerRef.current);
    };
  }, [selectedId]);

  // Ordered timeline events
  const timelineEvents: TimelineEvent[] = useMemo(() => {
    if (!incidentDetail) return [];
    if (incidentDetail.timeline && incidentDetail.timeline.length > 0) {
      return [...incidentDetail.timeline].sort(
        (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );
    }
    // Fallback if timeline array was empty: construct from evidence_events
    return (incidentDetail.evidence_events || [])
      .map((ev) => ({
        id: `tle_${ev.event_id}`,
        event_id: ev.event_id,
        incident_id: incidentDetail.incident_id,
        timestamp: ev.ts,
        event_type: ev.action,
        category: ev.category,
        title: `${ev.source_tool.toUpperCase()} ${ev.category}: ${ev.action}`,
        description: `Observed action on host ${ev.host || ev.dst_ip || "internal"}`,
        source_node_id: ev.src_ip ? `ip:${ev.src_ip}` : undefined,
        target_node_id: ev.host ? `host:${ev.host}` : undefined,
        severity: "medium" as const,
        evidence_reference: `${ev.source_tool} (${ev.domain})`,
        provenance: "observed" as const,
      }))
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }, [incidentDetail]);

  // Raw base nodes and edges from incidentDetail.graph
  const rawGraphElements = useMemo(() => {
    if (!incidentDetail?.graph) return { rawNodes: [], rawEdges: [] };

    const rawNodes: GraphNode[] = incidentDetail.graph.nodes || [];
    const rawEdges: GraphEdge[] = incidentDetail.graph.edges || [];

    const rfNodes: Node[] = rawNodes.map((n) => {
      const isDecoy =
        n.metadata?.is_decoy ||
        n.label.includes("decoy") ||
        n.label.includes("cowrie") ||
        n.label.includes("opencanary");
      const isCritical =
        n.metadata?.process_critical ||
        n.label.includes("plc") ||
        n.label.includes("eng-ws");
      const isAttacker =
        n.status === "untrusted_actor" ||
        n.label.includes("attacker") ||
        n.label === "10.10.1.5";

      return {
        id: n.id,
        type: "entityNode",
        position: { x: 0, y: 0 },
        data: {
          id: n.id,
          type: n.type,
          name: n.label || n.id,
          label: n.label,
          hostname: n.hostname,
          ip_address: n.ip_address,
          network_zone: n.network_zone || "unknown",
          network_zones: n.network_zones && n.network_zones.length > 0 ? n.network_zones : (n.network_zone ? [n.network_zone] : ["unknown"]),
          is_decoy: isDecoy,
          process_critical: isCritical,
          status: isAttacker ? "untrusted_actor" : n.status,
          risk_level: n.risk_level,
          evidence_count: n.evidence_count,
          first_seen: n.first_seen,
          last_seen: n.last_seen,
        } as EntityNodeData,
      };
    });

    const rfEdges: Edge[] = rawEdges.map((e, idx) => {
      const isOt = e.label.includes("modbus") || e.label.includes("ot");
      const isPivot = e.label.includes("pivot") || e.label.includes("net");
      const isAuth = e.label.includes("ssh") || e.label.includes("auth");
      const isDecoy = e.label.includes("decoy");

      const strokeColor = isOt ? "#f43f5e" : isPivot ? "#f59e0b" : isDecoy ? "#c084fc" : isAuth ? "#38bdf8" : "#94a3b8";

      return {
        id: e.id || `e_${e.source}_${e.target}_${idx}`,
        source: e.source,
        target: e.target,
        label: e.label.replace(/_/g, " "),
        animated: isOt || isPivot,
        style: {
          stroke: strokeColor,
          strokeWidth: isOt ? 3 : 2,
          strokeDasharray: isAuth ? "5,5" : undefined,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: strokeColor,
          width: 16,
          height: 16,
        },
        data: {
          id: e.id,
          label: e.label,
          relationship_type: e.relationship_type || e.label,
          source: e.source,
          target: e.target,
          evidence_ids: e.event_ids,
          provenance: e.provenance || "observed",
          confidence: e.confidence ?? 1.0,
          first_observed_at: e.first_observed_at || e.ts,
          last_observed_at: e.last_observed_at || e.ts,
        },
      };
    });

    return { rawNodes: rfNodes, rawEdges: rfEdges };
  }, [incidentDetail]);

  // Deterministic Graph State Derivation:
  // GraphState(T) = Reconstruct(all events up to playbackIndex)
  useEffect(() => {
    if (rawGraphElements.rawNodes.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    const currentEvent =
      playbackIndex >= 0 && playbackIndex < timelineEvents.length
        ? timelineEvents[playbackIndex]
        : null;

    const currentTimestamp = currentEvent ? new Date(currentEvent.timestamp).getTime() : Infinity;

    // Set of event IDs that have occurred up to playbackIndex
    const occurredEventIds = new Set<string>();
    for (let i = 0; i <= playbackIndex && i < timelineEvents.length; i++) {
      occurredEventIds.add(timelineEvents[i].event_id);
    }

    // Determine nodes active/visible at current time
    const updatedNodes = rawGraphElements.rawNodes.map((node) => {
      const data = node.data as EntityNodeData;
      const firstSeenTime = data.first_seen ? new Date(data.first_seen).getTime() : 0;

      // Check if any associated event has occurred
      const nodeEvents = incidentDetail ? findEventsForNode(node, incidentDetail) : [];
      const hasObservedActivity = nodeEvents.some((ev) => occurredEventIds.has(ev.event_id));
      const hasReachedFirstSeen = firstSeenTime <= currentTimestamp;

      const isVisible = hasObservedActivity || hasReachedFirstSeen || playbackIndex >= timelineEvents.length - 1;

      // Check if node is active in the currently highlighted event
      const isActiveInPlayback = Boolean(
        currentEvent &&
        (currentEvent.source_node_id === node.id ||
         currentEvent.target_node_id === node.id ||
         (currentEvent.metadata?.src_ip && data.name === currentEvent.metadata.src_ip) ||
         (currentEvent.metadata?.host && data.name.toLowerCase() === String(currentEvent.metadata.host).toLowerCase()))
      );

      const isSelected = Boolean(
        inspectorSelection?.kind === "node" && inspectorSelection.node.id === node.id
      );

      return {
        ...node,
        data: {
          ...data,
          is_active_playback: isActiveInPlayback,
          is_selected: isSelected,
          is_dimmed: !isVisible,
        },
      };
    });

    // Determine edges active/visible at current time
    const updatedEdges = rawGraphElements.rawEdges.map((edge) => {
      const edgeData = edge.data as {
        evidence_ids?: string[];
        first_observed_at?: string;
      };
      const edgeEvidenceIds = edgeData?.evidence_ids || [];
      const edgeFirstSeen = edgeData?.first_observed_at ? new Date(edgeData.first_observed_at).getTime() : 0;

      // An edge appears only when its supporting event has occurred
      const isObserved =
        edgeEvidenceIds.some((id) => occurredEventIds.has(id)) ||
        edgeFirstSeen <= currentTimestamp ||
        playbackIndex >= timelineEvents.length - 1;

      const isActiveInPlayback = Boolean(
        currentEvent &&
        edgeEvidenceIds.includes(currentEvent.event_id)
      );

      const isSelected = Boolean(
        inspectorSelection?.kind === "edge" && inspectorSelection.edge.id === edge.id
      );

      return {
        ...edge,
        hidden: !isObserved,
        animated: isObserved && (edge.animated || isActiveInPlayback),
        style: {
          ...edge.style,
          strokeWidth: isActiveInPlayback || isSelected ? 4 : isObserved ? 2 : 1,
          opacity: isObserved ? 1 : 0.15,
        },
      };
    });

    // Apply zoned layout
    const layouted = getZonedLayout(updatedNodes, updatedEdges);
    setNodes(layouted.nodes);
    setEdges(layouted.edges);
  }, [rawGraphElements, playbackIndex, timelineEvents, inspectorSelection, incidentDetail, setNodes, setEdges]);

  // Playback timer progression
  useEffect(() => {
    if (!isPlaying) {
      if (playbackTimerRef.current) clearInterval(playbackTimerRef.current);
      return;
    }

    const intervalMs = Math.max(100, Math.round(1000 / playbackSpeed));
    playbackTimerRef.current = setInterval(() => {
      setPlaybackIndex((prev) => {
        if (prev >= timelineEvents.length - 1) {
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, intervalMs);

    return () => {
      if (playbackTimerRef.current) clearInterval(playbackTimerRef.current);
    };
  }, [isPlaying, playbackSpeed, timelineEvents.length]);

  // Playback controls handlers
  const handlePlayPause = useCallback(() => {
    setIsPlaying((prev) => {
      if (!prev && playbackIndex >= timelineEvents.length - 1) {
        setPlaybackIndex(0); // restart if at the end
      }
      return !prev;
    });
  }, [playbackIndex, timelineEvents.length]);

  const handleStepForward = useCallback(() => {
    setIsPlaying(false);
    setPlaybackIndex((prev) => Math.min(timelineEvents.length - 1, prev + 1));
  }, [timelineEvents.length]);

  const handleStepBackward = useCallback(() => {
    setIsPlaying(false);
    setPlaybackIndex((prev) => Math.max(0, prev - 1));
  }, []);

  const handleRestart = useCallback(() => {
    setIsPlaying(false);
    setPlaybackIndex(0);
  }, []);

  const handleSelectTimelineIndex = useCallback((index: number) => {
    setIsPlaying(false);
    setPlaybackIndex(index);

    if (timelineEvents[index]) {
      const selectedEvent = timelineEvents[index];
      const raw = incidentDetail?.evidence_events?.find((e) => e.event_id === selectedEvent.event_id);
      setInspectorSelection({
        kind: "event",
        event: selectedEvent,
        rawEvent: raw,
      });
    }
  }, [timelineEvents, incidentDetail]);

  const handleDecisionUpdated = useCallback((updated: GuardDecision) => {
    setRecommendations((prev) =>
      prev.map((rec) =>
        rec.decision.decision_id === updated.decision_id
          ? { ...rec, decision: updated }
          : rec
      )
    );
  }, []);

  const handleAutoLayout = useCallback(() => {
    const layouted = getDagreLayout(nodes, edges);
    setNodes([...layouted.nodes]);
    setEdges([...layouted.edges]);
    reactFlow.fitView({ duration: 400 });
  }, [nodes, edges, setNodes, setEdges, reactFlow]);

  const handleZonedLayout = useCallback(() => {
    const layouted = getZonedLayout(nodes, edges);
    setNodes([...layouted.nodes]);
    setEdges([...layouted.edges]);
    reactFlow.fitView({ duration: 400 });
  }, [nodes, edges, setNodes, setEdges, reactFlow]);

  // Node Click Selection
  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (!incidentDetail) return;
      const data = node.data as EntityNodeData;
      const relevantEvents = findEventsForNode(node, incidentDetail);

      const canonicalNode: GraphNode = {
        id: node.id,
        entity_id: data.id,
        type: data.type,
        label: data.name,
        hostname: data.hostname,
        ip_address: data.ip_address,
        network_zone: data.network_zone || "unknown",
        network_zones: (data.network_zones && data.network_zones.length > 0 ? data.network_zones : [data.network_zone || "unknown"]) as ("it" | "dmz" | "ot" | "mgmt" | "external" | "unknown")[],
        first_seen: data.first_seen,
        last_seen: data.last_seen,
        status: data.status || "active",
        risk_level: data.risk_level || "low",
        evidence_count: relevantEvents.length,
        metadata: data as Record<string, unknown>,
      };

      setInspectorSelection({
        kind: "node",
        node: canonicalNode,
        events: relevantEvents,
      });
    },
    [incidentDetail]
  );

  // Edge Click Selection
  const onEdgeClick = useCallback(
    (_: React.MouseEvent, edge: Edge) => {
      if (!incidentDetail) return;
      const relevantEvents = findEventsForEdge(edge, incidentDetail);
      const edgeData = edge.data as {
        label?: string;
        relationship_type?: string;
        source?: string;
        target?: string;
        evidence_ids?: string[];
        provenance?: "observed" | "inferred" | "configured";
        confidence?: number;
      };

      const canonicalEdge: GraphEdge = {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edgeData.label || edge.label?.toString() || "relationship",
        relationship_type: edgeData.relationship_type || edgeData.label || "connection",
        ts: relevantEvents[0]?.ts || new Date().toISOString(),
        event_ids: edgeData.evidence_ids || [],
        confidence: edgeData.confidence ?? 1.0,
        provenance: edgeData.provenance || "observed",
        observation_status: edgeData.provenance || "observed",
      };

      setInspectorSelection({
        kind: "edge",
        edge: canonicalEdge,
        events: relevantEvents,
      });
    },
    [incidentDetail]
  );

  // Select event from Inspector to synchronize timeline
  const handleSelectEventFromInspector = useCallback(
    (eventId: string) => {
      const idx = timelineEvents.findIndex((t) => t.event_id === eventId);
      if (idx !== -1) {
        handleSelectTimelineIndex(idx);
      } else {
        openEvidence(eventId, "event");
      }
    },
    [timelineEvents, handleSelectTimelineIndex, openEvidence]
  );

  return (
    <div className="flex-1 flex flex-col h-[calc(100vh-4rem)] p-4 sm:p-6 space-y-3.5 max-w-[1600px] mx-auto w-full">
      {/* Top Header & Incident Summary Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800/80 shrink-0 font-mono">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
              <GitGraph className="w-5 h-5 text-blue-400" />
              Attack Investigation &amp; Chronological Replay
            </h1>
            <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-800 bg-emerald-950/40">
              PHASE B
            </Badge>
          </div>
          <p className="text-xs text-slate-400">
            Topology-mapped attacker traversal with evidence-backed provenance and synchronized chronological playback.
          </p>
        </div>

        {/* Incident Selector & Layout Actions */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400">Incident:</span>
            <select
              value={selectedId || ""}
              onChange={(e) => setSelectedId(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-xs text-slate-200 rounded-lg px-3 py-1.5 focus:outline-hidden focus:border-blue-500 font-mono shadow-xs"
            >
              {incidents.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  {inc.incident_id} ({inc.severity.toUpperCase()} - {(inc.score * 100).toFixed(0)}%)
                </option>
              ))}
            </select>
          </div>

          {incidentDetail && (
            <Badge
              variant="outline"
              className={cn(
                "text-xs px-2 py-0.5 font-bold uppercase",
                incidentDetail.severity === "critical"
                  ? "bg-rose-950/60 text-rose-300 border-rose-800"
                  : incidentDetail.severity === "high"
                  ? "bg-amber-950/60 text-amber-300 border-amber-800"
                  : "bg-blue-950/60 text-blue-300 border-blue-800"
              )}
            >
              {incidentDetail.severity} ({(incidentDetail.score * 100).toFixed(0)}%)
            </Badge>
          )}

          <Button
            variant="outline"
            size="sm"
            onClick={handleZonedLayout}
            className="text-xs font-mono border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-300 h-8"
          >
            <Sparkles className="w-3.5 h-3.5 mr-1 text-purple-400" /> Zoned Layout
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleAutoLayout}
            className="text-xs font-mono border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-300 h-8"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1 text-blue-400" /> Auto Dagre
          </Button>

          {recommendations.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowGuardPanel(true)}
              className="text-xs font-mono border-emerald-800/80 bg-emerald-950/40 hover:bg-emerald-900/40 text-emerald-300 h-8 font-bold"
            >
              <ShieldCheck className="w-3.5 h-3.5 mr-1 text-emerald-400" /> Response Guard ({recommendations.length})
            </Button>
          )}
        </div>
      </div>

      {/* Main Graph Canvas Area */}
      <div className="relative flex-1 rounded-2xl border border-slate-800 bg-[#080d1a] overflow-hidden shadow-2xl min-h-[380px]">
        {loading && (
          <div className="absolute inset-0 z-40 flex flex-col items-center justify-center bg-slate-950/80 text-slate-400 space-y-3">
            <div className="w-8 h-8 border-2 border-slate-700 border-t-blue-500 rounded-full animate-spin" />
            <p className="text-xs font-mono">Reconstructing attack graph and chronological evidence...</p>
          </div>
        )}

        {/* Network Zone Background Column Guides */}
        <div className="absolute inset-0 grid grid-cols-4 pointer-events-none opacity-20 z-0">
          <div className="border-r border-slate-700/60 p-3">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-red-400/80">
              EXTERNAL / ATTACKER
            </span>
          </div>
          <div className="border-r border-slate-700/60 p-3">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-blue-400/80">
              IT ZONE (10.10.1.0/24)
            </span>
          </div>
          <div className="border-r border-slate-700/60 p-3">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-purple-400/80">
              DMZ / DECOY (10.10.2.0/24)
            </span>
          </div>
          <div className="p-3">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-rose-400/80">
              OT ZONE / ICS (10.10.3.0/24)
            </span>
          </div>
        </div>

        {nodes.length > 0 ? (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            onEdgeClick={onEdgeClick}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.2}
            maxZoom={1.8}
            className="bg-transparent z-10"
          >
            <Background color="#1e293b" gap={24} size={1} />
            <Controls className="bg-slate-900 border-slate-800 text-slate-300 fill-slate-300" />
            <MiniMap
              nodeColor={(n) => {
                const data = n.data as EntityNodeData;
                if (data?.is_decoy) return "#a855f7";
                if (data?.process_critical) return "#f43f5e";
                if (data?.status === "untrusted_actor") return "#ef4444";
                return "#38bdf8";
              }}
              maskColor="rgba(8, 13, 26, 0.75)"
              className="bg-slate-950 border border-slate-800 rounded-lg shadow-lg"
            />
          </ReactFlow>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 p-8 space-y-3 z-10 relative">
            <GitGraph className="w-10 h-10 opacity-30 text-slate-400" />
            <h4 className="text-sm font-semibold text-slate-300">
              No Recorded Attacker Activity Available
            </h4>
            <p className="text-xs text-slate-500 max-w-sm text-center">
              Select an incident with recorded telemetry to reconstruct attacker movement across IT hosts, honeypots, and PLC devices.
            </p>
          </div>
        )}

        {/* Legend Overlay in Bottom Left */}
        <div className="absolute bottom-4 left-4 z-20 p-3 rounded-xl bg-slate-950/85 border border-slate-800 backdrop-blur-md text-[11px] font-mono space-y-2 shadow-xl select-none">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-1 gap-4">
            <span className="font-semibold text-slate-400">Attack Graph Legend</span>
            <span className="text-[9px] text-emerald-400 font-bold bg-emerald-950/60 px-1 py-0.2 rounded border border-emerald-800">
              OBSERVED TELEMETRY
            </span>
          </div>

          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-slate-300">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
              <span>External Actor</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
              <span>IT Host / User</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-500" />
              <span>Decoy Canary (DMZ)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
              <span>Process PLC (OT)</span>
            </div>
          </div>

          <div className="pt-1.5 border-t border-slate-800/80 flex items-center gap-3 text-slate-400 text-[10px]">
            <span className="flex items-center gap-1">
              <span className="w-3.5 h-0.5 bg-sky-400 inline-block border-b border-dashed border-sky-400" /> SSH Auth
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3.5 h-0.5 bg-amber-400 inline-block" /> Lateral Pivot
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3.5 h-0.5 bg-rose-500 inline-block" /> OT Modbus
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3.5 h-0.5 bg-purple-400 inline-block" /> Decoy Pivot
            </span>
          </div>
        </div>

        {/* Evidence Inspector Docked in Top Right */}
        {inspectorSelection && (
          <div className="absolute top-4 right-4 z-30 max-h-[calc(100%-2rem)]">
            <EvidenceInspector
              selection={inspectorSelection}
              onClose={() => setInspectorSelection(null)}
              onSelectEvent={handleSelectEventFromInspector}
              onOpenRawDrawer={openEvidence}
            />
          </div>
        )}
      </div>

      {/* Chronological Attack Timeline & Playback Controller */}
      <AttackTimeline
        events={timelineEvents}
        currentIndex={playbackIndex}
        isPlaying={isPlaying}
        playbackSpeed={playbackSpeed}
        onPlayPause={handlePlayPause}
        onStepForward={handleStepForward}
        onStepBackward={handleStepBackward}
        onRestart={handleRestart}
        onSelectIndex={handleSelectTimelineIndex}
        onSpeedChange={setPlaybackSpeed}
      />

      {/* Incident Response Safety Guard Modal */}
      {showGuardPanel && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150 font-mono text-xs">
          <div className="relative w-full max-w-4xl rounded-2xl border border-slate-800 bg-[#0b1120] p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <h2 className="text-base font-bold text-slate-100">
                  Incident Containment Response Recommendations ({recommendations.length})
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setShowGuardPanel(false)}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <ResponseGuardPanel
              recommendations={recommendations}
              onDecisionUpdated={handleDecisionUpdated}
            />
          </div>
        </div>
      )}
    </div>
  );
}

export default function AttackGraphPage() {
  return (
    <ReactFlowProvider>
      <Suspense fallback={<div className="p-8 text-slate-400 font-mono text-xs">Loading attack graph canvas...</div>}>
        <AttackGraphContent />
      </Suspense>
    </ReactFlowProvider>
  );
}
