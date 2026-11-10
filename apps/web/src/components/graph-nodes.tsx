"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { Cpu, Globe, Server, ShieldAlert, User, Zap } from "lucide-react";
import { cn } from "@/lib/utils";

export interface EntityNodeData {
  id: string;
  type: string; // "user" | "host" | "ip" | "device"
  name: string;
  label?: string;
  hostname?: string;
  ip_address?: string;
  network_zone?: "it" | "dmz" | "ot" | "mgmt" | "external" | "unknown";
  network_zones?: string[];
  is_decoy?: boolean;
  process_critical?: boolean;
  status?: string;
  risk_level?: string;
  evidence_count?: number;
  is_active_playback?: boolean;
  is_selected?: boolean;
  is_dimmed?: boolean;
  first_seen?: string;
  last_seen?: string;
  evidence_event_ids?: string[];
  [key: string]: unknown;
}

export function EntityNode({ data }: { data: EntityNodeData }) {
  const isDecoy = Boolean(
    data.is_decoy ||
    data.name.includes("decoy") ||
    data.name.includes("cowrie") ||
    data.name.includes("opencanary")
  );
  const isCritical = Boolean(
    data.process_critical ||
    data.name.includes("plc") ||
    data.name.includes("eng-ws")
  );
  const isAttacker = Boolean(
    data.status === "untrusted_actor" ||
    data.name.includes("attacker") ||
    data.name === "10.10.1.5"
  );

  let Icon = Server;
  if (data.type === "user") Icon = User;
  if (data.type === "device" || data.name.includes("plc")) Icon = Cpu;
  if (data.type === "ip") Icon = Globe;

  const zones = (data.network_zones && data.network_zones.length > 0)
    ? data.network_zones
    : [data.network_zone || "unknown"];

  const getZoneStyle = (z: string) => {
    const zu = z.toUpperCase();
    if (zu === "IT") return "text-blue-400 border-blue-800 bg-blue-950/60";
    if (zu === "DMZ") return "text-purple-400 border-purple-800 bg-purple-950/60";
    if (zu === "OT") return "text-rose-400 border-rose-800 bg-rose-950/60";
    if (zu === "MGMT") return "text-emerald-400 border-emerald-800 bg-emerald-950/60";
    if (zu === "EXTERNAL") return "text-red-400 border-red-800 bg-red-950/60";
    return "text-slate-400 border-slate-800 bg-slate-900/60";
  };

  return (
    <div
      className={cn(
        "relative px-3.5 py-2.5 rounded-xl border font-mono text-xs shadow-md transition-all select-none min-w-[190px]",
        data.is_dimmed && "opacity-25 grayscale pointer-events-none",
        data.is_active_playback && "ring-2 ring-blue-400 ring-offset-2 ring-offset-slate-950 shadow-[0_0_25px_rgba(56,189,248,0.7)] animate-pulse",
        data.is_selected && "ring-2 ring-amber-400 ring-offset-1 ring-offset-slate-950 shadow-[0_0_15px_rgba(251,191,36,0.5)]",
        isDecoy
          ? "bg-purple-950/80 border-purple-600/80 text-purple-200 shadow-[0_0_15px_rgba(168,85,247,0.3)]"
          : isCritical
          ? "bg-rose-950/80 border-rose-600/80 text-rose-200 shadow-[0_0_15px_rgba(244,63,94,0.3)]"
          : isAttacker
          ? "bg-red-950/80 border-red-600/80 text-red-200 shadow-[0_0_15px_rgba(239,68,68,0.3)]"
          : "bg-slate-900/90 border-slate-700 text-slate-100 hover:border-slate-500"
      )}
    >
      <Handle type="target" position={Position.Left} className="w-2 h-2 bg-slate-400 border border-slate-800" />

      {/* Header bar: Icon + Label + Zone Badges (supports multi-zone) */}
      <div className="flex items-center justify-between gap-1.5 mb-1">
        <div className="flex items-center gap-1.5 truncate min-w-0">
          <Icon
            className={cn(
              "w-3.5 h-3.5 shrink-0",
              isDecoy
                ? "text-purple-400"
                : isCritical
                ? "text-rose-400"
                : isAttacker
                ? "text-red-400"
                : "text-blue-400"
            )}
          />
          <span className="font-bold text-xs truncate text-slate-100">{data.name}</span>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          {zones.map((z) => (
            <span key={z} className={cn("text-[8px] font-bold px-1 py-0.2 rounded border uppercase", getZoneStyle(z))}>
              {z.toUpperCase()}
            </span>
          ))}
        </div>
      </div>

      {/* Subtitle / Details: Type + Evidence Count */}
      <div className="flex items-center justify-between text-[10px] text-slate-400 border-t border-slate-800/60 pt-1 mt-1">
        <span className="uppercase text-[9px] text-slate-400 font-medium">
          {data.type}
        </span>

        {typeof data.evidence_count === "number" && data.evidence_count > 0 && (
          <span className="flex items-center gap-0.5 text-[9px] text-slate-300 bg-slate-950/60 px-1 py-0.2 rounded border border-slate-800">
            <Zap className="w-2.5 h-2.5 text-blue-400" />
            {data.evidence_count} ev
          </span>
        )}
      </div>

      {/* Role / Criticality Badges */}
      {(isDecoy || isCritical || isAttacker) && (
        <div className="mt-1 pt-1 border-t border-slate-800/60 flex items-center justify-between gap-1 text-[9px]">
          {isDecoy && (
            <span className="text-purple-300 font-semibold flex items-center gap-1">
              <ShieldAlert className="w-2.5 h-2.5" /> DECOY CANARY
            </span>
          )}
          {isCritical && (
            <span className="text-rose-300 font-semibold flex items-center gap-1">
              <Cpu className="w-2.5 h-2.5" /> PROCESS CRITICAL
            </span>
          )}
          {isAttacker && (
            <span className="text-red-300 font-semibold flex items-center gap-1">
              UNTRUSTED ACTOR
            </span>
          )}
        </div>
      )}

      <Handle type="source" position={Position.Right} className="w-2 h-2 bg-slate-400 border border-slate-800" />
    </div>
  );
}
