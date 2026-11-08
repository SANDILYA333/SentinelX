"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
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
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import type { GraphEdge, GraphNode } from "@contracts/index";
import { fetchIncidentById, type IncidentWithEvidence } from "@/lib/api";
import { useEvidenceDrawer } from "@/components/evidence-drawer";
import { EntityNode } from "@/components/graph-nodes";
import { useEventStream } from "@/hooks/useEventStream";
import { useEventStore } from "@/lib/store";
import { Button } from "@/components/ui/button";
import {
  GitGraph,
  RefreshCw,
} from "lucide-react";

const nodeTypes = {
  entityNode: EntityNode,
};

function getLayoutedElements(nodes: Node[], edges: Edge[], direction = "LR") {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({ rankdir: direction, nodesep: 50, ranksep: 90 });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 190, height: 75 });
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
        x: nodeWithPos ? nodeWithPos.x - 95 : 0,
        y: nodeWithPos ? nodeWithPos.y - 37 : 0,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

function AttackGraphContent() {
  useEventStream();
  const searchParams = useSearchParams();
  const incidentParam = searchParams.get("incident_id");
  const { openEvidence } = useEvidenceDrawer();

  const { incidents } = useEventStore();
  const [selectedId, setSelectedId] = useState<string | null>(incidentParam);
  const [incidentDetail, setIncidentDetail] = useState<IncidentWithEvidence | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  // Sync initial param
  useEffect(() => {
    if (incidentParam && !selectedId) {
      setSelectedId(incidentParam);
    } else if (!selectedId && incidents.length > 0) {
      setSelectedId(incidents[0].incident_id);
    }
  }, [incidentParam, incidents, selectedId]);

  // Load incident details with graph
  useEffect(() => {
    if (!selectedId) return;
    let active = true;
    setLoading(true);

    fetchIncidentById(selectedId)
      .then((res) => {
        if (active) {
          setIncidentDetail(res);
        }
      })
      .catch((err) => {
        console.error("Failed to fetch incident graph:", err);
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [selectedId]);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  // Construct React Flow elements from incident.graph
  useEffect(() => {
    if (!incidentDetail?.graph) {
      setNodes([]);
      setEdges([]);
      return;
    }

    const rawNodes: GraphNode[] = incidentDetail.graph.nodes || [];
    const rawEdges: GraphEdge[] = incidentDetail.graph.edges || [];

    const rfNodes: Node[] = rawNodes.map((n) => {
      const isDecoy = n.label.includes("decoy") || n.label.includes("cowrie") || n.label.includes("opencanary");
      const isCritical = n.label.includes("plc") || n.label.includes("eng-ws");
      return {
        id: n.id,
        type: "entityNode",
        position: { x: 0, y: 0 },
        data: {
          id: n.id,
          type: n.type,
          name: n.label || n.id,
          is_decoy: isDecoy,
          process_critical: isCritical,
        },
      };
    });

    const rfEdges: Edge[] = rawEdges.map((e, idx) => {
      const isOt = e.label.includes("modbus") || e.label.includes("ot");
      const isPivot = e.label.includes("pivot") || e.label.includes("net");
      const isAuth = e.label.includes("ssh") || e.label.includes("auth");

      const strokeColor = isOt ? "#f43f5e" : isPivot ? "#f59e0b" : isAuth ? "#38bdf8" : "#94a3b8";

      return {
        id: `e_${e.source}_${e.target}_${idx}`,
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
          label: e.label,
          source: e.source,
          target: e.target,
          evidence_ids: e.event_ids,
        },
      };
    });

    // Auto-layout via Dagre
    const layouted = getLayoutedElements(rfNodes, rfEdges);
    setNodes(layouted.nodes);
    setEdges(layouted.edges);
  }, [incidentDetail, setNodes, setEdges]);

  const handleAutoLayout = useCallback(() => {
    const layouted = getLayoutedElements(nodes, edges);
    setNodes([...layouted.nodes]);
    setEdges([...layouted.edges]);
  }, [nodes, edges, setNodes, setEdges]);

  const onNodeClick = useCallback(
    (_: React.MouseEvent, _node: Node) => {
      // Find events in incident mentioning this node
      if (incidentDetail?.event_ids && incidentDetail.event_ids.length > 0) {
        openEvidence(incidentDetail.event_ids[0], "event");
      }
    },
    [incidentDetail, openEvidence]
  );

  const onEdgeClick = useCallback(
    (_: React.MouseEvent, edge: Edge) => {
      const edgeData = edge.data as {
        label: string;
        source: string;
        target: string;
        evidence_ids?: string[];
      };
      if (edgeData?.evidence_ids && edgeData.evidence_ids.length > 0) {
        openEvidence(edgeData.evidence_ids[0], "event");
      } else if (incidentDetail?.event_ids && incidentDetail.event_ids.length > 0) {
        openEvidence(incidentDetail.event_ids[0], "event");
      }
    },
    [incidentDetail, openEvidence]
  );

  return (
    <div className="flex-1 flex flex-col h-[calc(100vh-4rem)] p-6 space-y-4 max-w-7xl mx-auto w-full">
      {/* Top Controls Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80 shrink-0">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <GitGraph className="w-5 h-5 text-blue-400" />
            Attack Graph &amp; Lateral Traversal
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Topology-mapped lateral movement, honeypot pivots, and PLC actuator commands.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Incident Selector Dropdown */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Incident:</span>
            <select
              value={selectedId || ""}
              onChange={(e) => setSelectedId(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-xs text-slate-200 rounded-md px-3 py-1.5 focus:outline-hidden focus:border-blue-500 font-mono"
            >
              {incidents.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  {inc.incident_id} ({inc.severity.toUpperCase()} - {(inc.score * 100).toFixed(0)}%)
                </option>
              ))}
            </select>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={handleAutoLayout}
            className="text-xs font-mono border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-300"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1 text-blue-400" /> Auto Layout
          </Button>
        </div>
      </div>

      {/* Main Canvas Area */}
      <div className="relative flex-1 rounded-2xl border border-slate-800 bg-[#080d1a] overflow-hidden shadow-2xl">
        {loading && (
          <div className="absolute inset-0 z-20 flex flex-col items-center justify-center bg-slate-950/70 text-slate-400 space-y-3">
            <div className="w-8 h-8 border-2 border-slate-700 border-t-blue-500 rounded-full animate-spin" />
            <p className="text-xs font-mono">Reconstructing attack graph topology...</p>
          </div>
        )}

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
            className="bg-[#080d1a]"
          >
            <Background color="#1e293b" gap={20} size={1} />
            <Controls className="bg-slate-900 border-slate-800 text-slate-300 fill-slate-300" />
            <MiniMap
              nodeColor={(n) => {
                const data = n.data as { is_decoy?: boolean; process_critical?: boolean };
                if (data?.is_decoy) return "#a855f7";
                if (data?.process_critical) return "#f43f5e";
                return "#38bdf8";
              }}
              maskColor="rgba(8, 13, 26, 0.7)"
              className="bg-slate-950 border border-slate-800 rounded-lg"
            />
          </ReactFlow>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 p-8 space-y-3">
            <GitGraph className="w-10 h-10 opacity-30 text-slate-400" />
            <h4 className="text-sm font-semibold text-slate-300">
              No Attack Graph Available
            </h4>
            <p className="text-xs text-slate-500 max-w-sm text-center">
              Select an incident with multi-entity hops to visualize the attack path traversal across IT hosts, decoys, and PLC devices.
            </p>
          </div>
        )}

        {/* Legend Overlay in Bottom Left */}
        <div className="absolute bottom-4 left-4 z-10 p-3 rounded-xl bg-slate-950/80 border border-slate-800 backdrop-blur-xs text-[11px] font-mono space-y-2 shadow-lg">
          <span className="font-semibold text-slate-400 block border-b border-slate-800/60 pb-1">
            Graph Topology Legend
          </span>

          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-slate-300">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
              <span>IT Host / User</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-500" />
              <span>Decoy Canary</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
              <span>Process PLC (OT)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
              <span>External Actor</span>
            </div>
          </div>

          <div className="pt-1 border-t border-slate-800/60 flex items-center gap-3 text-slate-400 text-[10px]">
            <span className="flex items-center gap-1">
              <span className="w-3 h-0.5 bg-sky-400 inline-block border-b border-dashed border-sky-400" /> SSH Auth
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-0.5 bg-amber-400 inline-block" /> Lateral Pivot
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-0.5 bg-rose-500 inline-block" /> OT Modbus
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function AttackGraphPage() {
  return (
    <Suspense fallback={<div className="p-8 text-slate-400 font-mono text-xs">Loading attack graph canvas...</div>}>
      <AttackGraphContent />
    </Suspense>
  );
}
