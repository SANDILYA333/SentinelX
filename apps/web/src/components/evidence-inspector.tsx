"use client";

import React, { useState } from "react";
import type { Event, GraphEdge, GraphNode, TimelineEvent } from "@contracts/index";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Check,
  Cpu,
  ExternalLink,
  GitCommit,
  Globe,
  Server,
  User,
  X,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

export type InspectorSelection =
  | { kind: "event"; event: TimelineEvent; rawEvent?: Event }
  | { kind: "node"; node: GraphNode; events: Event[] }
  | { kind: "edge"; edge: GraphEdge; events: Event[] };

interface EvidenceInspectorProps {
  selection: InspectorSelection | null;
  onClose: () => void;
  onSelectEvent: (eventId: string) => void;
  onOpenRawDrawer: (id: string, type?: "event" | "signal") => void;
}

export function EvidenceInspector({
  selection,
  onClose,
  onSelectEvent,
  onOpenRawDrawer,
}: EvidenceInspectorProps) {
  const [showRawJson, setShowRawJson] = useState(false);
  const [copied, setCopied] = useState(false);

  if (!selection) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const otMeta = (selection.kind === "event" && selection.event.metadata?.ot)
    ? (selection.event.metadata.ot as {
        register?: unknown;
        value?: unknown;
        is_write?: boolean;
        unit_id?: unknown;
      })
    : null;

  return (
    <aside className="w-96 max-h-full bg-slate-950/95 border border-slate-800 rounded-2xl shadow-2xl flex flex-col backdrop-blur-md animate-in fade-in slide-in-from-right-4 duration-200 z-30 overflow-hidden font-mono text-xs">
      {/* Top Header */}
      <div className="p-3.5 border-b border-slate-800 bg-slate-900/60 flex items-start justify-between gap-2 shrink-0">
        <div className="space-y-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge
              variant="outline"
              className={cn(
                "text-[10px] uppercase font-bold px-1.5 py-0",
                selection.kind === "event"
                  ? "bg-blue-950/60 text-blue-300 border-blue-800"
                  : selection.kind === "node"
                  ? "bg-purple-950/60 text-purple-300 border-purple-800"
                  : "bg-amber-950/60 text-amber-300 border-amber-800"
              )}
            >
              {selection.kind === "event"
                ? "TIMELINE EVENT"
                : selection.kind === "node"
                ? "GRAPH ENTITY"
                : "ATTACK PATH EDGE"}
            </Badge>

            <span className="text-[11px] text-slate-400 truncate">
              {selection.kind === "event"
                ? selection.event.event_id
                : selection.kind === "node"
                ? selection.node.id
                : `${selection.edge.source} -> ${selection.edge.target}`}
            </span>
          </div>

          <h3 className="text-sm font-semibold text-slate-100 truncate flex items-center gap-1.5">
            {selection.kind === "event" ? (
              <Zap className="w-4 h-4 text-blue-400 shrink-0" />
            ) : selection.kind === "node" ? (
              String(selection.node.type) === "device" || selection.node.label.includes("plc") ? (
                <Cpu className="w-4 h-4 text-rose-400 shrink-0" />
              ) : String(selection.node.type) === "user" ? (
                <User className="w-4 h-4 text-amber-400 shrink-0" />
              ) : String(selection.node.type) === "ip" ? (
                <Globe className="w-4 h-4 text-sky-400 shrink-0" />
              ) : (
                <Server className="w-4 h-4 text-blue-400 shrink-0" />
              )
            ) : (
              <GitCommit className="w-4 h-4 text-amber-400 shrink-0" />
            )}
            <span className="truncate">
              {selection.kind === "event"
                ? selection.event.title
                : selection.kind === "node"
                ? selection.node.label
                : selection.edge.label.replace(/_/g, " ")}
            </span>
          </h3>
        </div>

        <Button
          variant="ghost"
          size="icon"
          onClick={onClose}
          className="h-7 w-7 text-slate-400 hover:text-slate-100 hover:bg-slate-800 shrink-0"
        >
          <X className="w-4 h-4" />
        </Button>
      </div>

      {/* Content Scroll Area */}
      <ScrollArea className="flex-1 p-3.5 space-y-3.5 overflow-y-auto">
        {/* VIEW 1: SELECTED TIMELINE EVENT */}
        {selection.kind === "event" && (
          <div className="space-y-3">
            {/* Metadata Badges */}
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400 flex items-center gap-1">
                  <Clock className="w-3 h-3 text-blue-400" /> Timestamp:
                </span>
                <span className="text-slate-200 font-semibold">
                  {new Date(selection.event.timestamp).toLocaleString()}
                </span>
              </div>

              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Provenance:</span>
                <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-800 bg-emerald-950/40">
                  {String(selection.event.provenance || "observed").toUpperCase()}
                </Badge>
              </div>

              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Log Source:</span>
                <span className="text-slate-200">{selection.event.evidence_reference}</span>
              </div>

              {selection.event.mitre_technique && (
                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
                  <span className="text-slate-400">MITRE ATT&amp;CK:</span>
                  <span className="text-rose-400 font-bold">
                    {selection.event.mitre_technique.technique_id} - {selection.event.mitre_technique.name}
                  </span>
                </div>
              )}
            </div>

            {/* Narrative Description */}
            <div className="p-3 rounded-xl bg-slate-900/40 border border-slate-800 space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">
                Event Reconstruction
              </span>
              <p className="text-xs text-slate-200 leading-relaxed">
                {String(selection.event.description || "")}
              </p>
            </div>

            {/* OT Registers if present */}
            {otMeta && (
              <div className="p-3 rounded-xl bg-rose-950/30 border border-rose-900/50 space-y-1">
                <span className="text-[10px] text-rose-400 uppercase font-semibold flex items-center gap-1">
                  <Cpu className="w-3 h-3" /> Modbus Register Telemetry
                </span>
                <div className="grid grid-cols-2 gap-2 text-[11px] text-rose-200 pt-1">
                  <div>
                    <span className="text-rose-400">Register:</span>{" "}
                    {String(otMeta.register ?? "N/A")}
                  </div>
                  <div>
                    <span className="text-rose-400">Value:</span>{" "}
                    {String(otMeta.value ?? "N/A")}
                  </div>
                  <div>
                    <span className="text-rose-400">Operation:</span>{" "}
                    {otMeta.is_write ? "Write (State Change)" : "Read"}
                  </div>
                  <div>
                    <span className="text-rose-400">Unit ID:</span>{" "}
                    {String(otMeta.unit_id ?? "N/A")}
                  </div>
                </div>
              </div>
            )}

            {/* Expandable Raw Telemetry */}
            <div className="border border-slate-800 rounded-xl overflow-hidden">
              <button
                onClick={() => setShowRawJson(!showRawJson)}
                className="w-full flex items-center justify-between p-2.5 bg-slate-900/60 hover:bg-slate-900 text-[11px] text-slate-300 transition-colors"
              >
                <span>Raw Normalized Telemetry</span>
                {showRawJson ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              </button>

              {showRawJson && (
                <div className="p-3 bg-slate-950 relative">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleCopy(JSON.stringify(selection.rawEvent || selection.event, null, 2))}
                    className="absolute top-2 right-2 h-6 px-1.5 text-[10px] text-slate-400 hover:text-slate-100"
                  >
                    {copied ? <Check className="w-3 h-3 mr-1 text-emerald-400" /> : <Copy className="w-3 h-3 mr-1" />}
                    {copied ? "Copied" : "Copy"}
                  </Button>
                  <pre className="text-[10px] text-slate-300 font-mono overflow-x-auto max-h-48">
                    {JSON.stringify(selection.rawEvent || selection.event, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={() => onOpenRawDrawer(selection.event.event_id, "event")}
              className="w-full text-xs font-mono border-slate-700 bg-slate-900 hover:bg-slate-800 text-blue-400"
            >
              <ExternalLink className="w-3.5 h-3.5 mr-1.5" /> Inspect in Full Drawer
            </Button>
          </div>
        )}

        {/* VIEW 2: SELECTED GRAPH NODE */}
        {selection.kind === "node" && (
          <div className="space-y-3">
            {/* Node Properties */}
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Network Zone:</span>
                <div className="flex items-center gap-1">
                  {(selection.node.network_zones && selection.node.network_zones.length > 0
                    ? selection.node.network_zones
                    : [selection.node.network_zone || "unknown"]
                  ).map((z) => (
                    <Badge key={z} variant="outline" className="text-[10px] font-bold text-blue-400 border-blue-800 bg-blue-950/40 uppercase">
                      {z}
                    </Badge>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Entity Type:</span>
                <span className="text-slate-200 capitalize">{String(selection.node.type)}</span>
              </div>

              {selection.node.hostname && (
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-400">Hostname:</span>
                  <span className="text-slate-200">{selection.node.hostname}</span>
                </div>
              )}

              {selection.node.ip_address && (
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-400">IP Address:</span>
                  <span className="text-slate-200">{selection.node.ip_address}</span>
                </div>
              )}

              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Risk Level:</span>
                <span className={cn(
                  "font-bold uppercase text-[10px]",
                  selection.node.risk_level === "critical"
                    ? "text-rose-400"
                    : selection.node.risk_level === "high"
                    ? "text-amber-400"
                    : "text-slate-300"
                )}>
                  {selection.node.risk_level || "low"}
                </span>
              </div>

              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Total Associated Events:</span>
                <span className="text-slate-200 font-bold">{selection.events.length}</span>
              </div>
            </div>

            {/* List of associated events */}
            <div className="space-y-1.5">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">
                Associated Telemetry Events ({selection.events.length})
              </span>

              {selection.events.length === 0 ? (
                <div className="p-3 rounded-lg bg-slate-900/40 text-center text-slate-500 text-[11px]">
                  No discrete telemetry events found for this entity.
                </div>
              ) : (
                <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                  {selection.events.map((ev) => (
                    <button
                      key={ev.event_id}
                      onClick={() => onSelectEvent(ev.event_id)}
                      className="w-full text-left p-2 rounded-lg bg-slate-900/70 border border-slate-800 hover:border-blue-500 hover:bg-slate-900 transition-colors flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <div className="text-xs text-slate-200 font-medium truncate">
                          {ev.action}
                        </div>
                        <div className="text-[10px] text-slate-400 truncate">
                          {ev.source_tool} ({ev.domain}) - {ev.category}
                        </div>
                      </div>
                      <span className="text-[10px] text-slate-400 shrink-0 tabular-nums">
                        {new Date(ev.ts).toLocaleTimeString()}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* VIEW 3: SELECTED GRAPH EDGE */}
        {selection.kind === "edge" && (
          <div className="space-y-3">
            {/* Edge Properties */}
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Provenance:</span>
                <Badge
                  variant="outline"
                  className={cn(
                    "text-[10px] font-bold px-1.5 py-0.5",
                    selection.edge.provenance === "observed"
                      ? "text-emerald-400 border-emerald-800 bg-emerald-950/40"
                      : selection.edge.provenance === "inferred"
                      ? "text-amber-400 border-amber-800 bg-amber-950/40"
                      : "text-blue-400 border-blue-800 bg-blue-950/40"
                  )}
                >
                  {selection.edge.provenance === "observed"
                    ? "OBSERVED TELEMETRY"
                    : selection.edge.provenance === "inferred"
                    ? "INFERRED ATTACK PATH"
                    : "CONFIGURED TOPOLOGY"}
                </Badge>
              </div>

              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Relationship:</span>
                <span className="text-slate-200 font-semibold">
                  {(selection.edge.relationship_type || selection.edge.label).replace(/_/g, " ")}
                </span>
              </div>

              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Source:</span>
                <span className="text-slate-200 truncate">{selection.edge.source}</span>
              </div>

              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Target:</span>
                <span className="text-slate-200 truncate">{selection.edge.target}</span>
              </div>

              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Supporting Events:</span>
                <span className="text-slate-200 font-bold">{selection.events.length}</span>
              </div>
            </div>

            {/* Supporting Events List */}
            <div className="space-y-1.5">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">
                Supporting Evidence Events ({selection.events.length})
              </span>

              {selection.events.length === 0 ? (
                <div className="p-3 rounded-lg bg-slate-900/40 text-center text-slate-500 text-[11px]">
                  No supporting events cited for this edge.
                </div>
              ) : (
                <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                  {selection.events.map((ev) => (
                    <button
                      key={ev.event_id}
                      onClick={() => onSelectEvent(ev.event_id)}
                      className="w-full text-left p-2 rounded-lg bg-slate-900/70 border border-slate-800 hover:border-amber-500 hover:bg-slate-900 transition-colors flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <div className="text-xs text-slate-200 font-medium truncate">
                          {ev.action}
                        </div>
                        <div className="text-[10px] text-slate-400 truncate">
                          {ev.source_tool} ({ev.domain})
                        </div>
                      </div>
                      <span className="text-[10px] text-slate-400 shrink-0 tabular-nums">
                        {new Date(ev.ts).toLocaleTimeString()}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </ScrollArea>
    </aside>
  );
}
