"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { Cpu, Globe, Server, ShieldAlert, User } from "lucide-react";
import { cn } from "@/lib/utils";

export interface EntityNodeData {
  id: string;
  type: string; // "user" | "host" | "ip" | "device"
  name: string;
  is_decoy?: boolean;
  process_critical?: boolean;
  evidence_event_ids?: string[];
  [key: string]: unknown;
}

export function EntityNode({ data }: { data: EntityNodeData }) {
  const isDecoy = data.is_decoy || data.name.includes("decoy") || data.name.includes("cowrie") || data.name.includes("opencanary");
  const isCritical = data.process_critical || data.name.includes("plc") || data.name.includes("eng-ws");
  const isAttacker = data.name.includes("attacker") || data.name === "10.10.1.5";

  let Icon = Server;
  if (data.type === "user") Icon = User;
  if (data.type === "device" || data.name.includes("plc")) Icon = Cpu;
  if (data.type === "ip") Icon = Globe;

  return (
    <div
      className={cn(
        "px-3.5 py-2.5 rounded-xl border font-mono text-xs shadow-md transition-all select-none min-w-[170px]",
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

      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 truncate">
          <Icon className={cn(
            "w-3.5 h-3.5 shrink-0",
            isDecoy ? "text-purple-400" : isCritical ? "text-rose-400" : isAttacker ? "text-red-400" : "text-blue-400"
          )} />
          <span className="font-bold text-xs truncate">{data.name}</span>
        </div>

        <span className="text-[9px] uppercase px-1 py-0.2 rounded bg-slate-950/60 text-slate-400 border border-slate-800">
          {data.type}
        </span>
      </div>

      {(isDecoy || isCritical || isAttacker) && (
        <div className="mt-1.5 pt-1 border-t border-slate-800/60 flex items-center gap-1 text-[10px]">
          {isDecoy && (
            <span className="text-purple-300 font-semibold flex items-center gap-1">
              <ShieldAlert className="w-2.5 h-2.5" /> DECOY
            </span>
          )}
          {isCritical && (
            <span className="text-rose-300 font-semibold flex items-center gap-1">
              <Cpu className="w-2.5 h-2.5" /> PROCESS CRITICAL
            </span>
          )}
          {isAttacker && (
            <span className="text-red-300 font-semibold">
              UNTRUSTED ACTOR
            </span>
          )}
        </div>
      )}

      <Handle type="source" position={Position.Right} className="w-2 h-2 bg-slate-400 border border-slate-800" />
    </div>
  );
}

