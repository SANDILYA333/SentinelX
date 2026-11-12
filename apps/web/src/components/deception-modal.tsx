"use client";

import Link from "next/link";
import type { DeceptionActivity } from "@contracts/index";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  CheckCircle2,
  ExternalLink,
  FileCode,
  Globe,
  Server,
  Shield,
  ShieldAlert,
  Terminal,
  X,
  XCircle,
} from "lucide-react";
interface DeceptionModalProps {
  activity: DeceptionActivity | null;
  onClose: () => void;
}

export function DeceptionModal({ activity, onClose }: DeceptionModalProps) {
  if (!activity) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150 font-mono text-xs">
      <div className="relative w-full max-w-2xl rounded-2xl border border-slate-800 bg-[#0b1120] p-6 shadow-2xl space-y-5 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-slate-800/80">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-[10px] bg-purple-950/60 border-purple-700 text-purple-300 font-bold uppercase">
                DECEPTION INTELLIGENCE
              </Badge>
              {activity.mitre_technique && (
                <Badge variant="outline" className="text-[10px] bg-slate-900 border-slate-700 text-slate-300">
                  MITRE {activity.mitre_technique}
                </Badge>
              )}
              <span className="text-slate-500 text-[10px]">ID: {activity.activity_id}</span>
            </div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-purple-400" />
              {activity.title}
            </h2>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Target Decoy & Source Overview Grid */}
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1">
                <Server className="w-3.5 h-3.5 text-purple-400" /> Target Decoy Asset
              </span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-950/60 border border-blue-800 text-blue-300 font-mono">
                CONFIGURED TOPOLOGY
              </span>
            </div>
            <div className="text-slate-200 font-bold text-sm">{activity.decoy_hostname}</div>
            <div className="text-[11px] text-slate-400 flex items-center gap-2">
              <span>Role: <strong className="text-purple-300">{activity.decoy_type}</strong></span>
              <span>&bull;</span>
              <span>Zone: <strong className="uppercase text-slate-300">{activity.network_zone}</strong></span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1">
                <Globe className="w-3.5 h-3.5 text-red-400" /> Attacker Origin
              </span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300 font-mono">
                OBSERVED IP + INFERRED ROLE
              </span>
            </div>
            <div className="text-red-400 font-bold text-sm">{activity.src_ip || "Unknown IP"}</div>
            <div className="text-[11px] text-slate-400 flex items-center gap-2">
              <span>Status: <strong className="text-red-300 uppercase">{activity.attacker_role || "Untrusted"}</strong></span>
              {Boolean(activity.metadata?.user) && (
                <>
                  <span>&bull;</span>
                  <span>User: <strong className="text-amber-300">{String(activity.metadata?.user)}</strong></span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Description & Intelligence Narrative */}
        <div className="p-3.5 rounded-xl bg-purple-950/20 border border-purple-800/40 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold text-purple-400 flex items-center gap-1">
              <Shield className="w-3.5 h-3.5" /> Intelligence Narrative
            </span>
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-950/80 border border-purple-700 text-purple-300 font-mono">
              INFERRED ATTACKER INTENT
            </span>
          </div>
          <p className="text-slate-200 text-xs leading-relaxed">
            {activity.description}
          </p>
          <div className="text-[10px] text-slate-400 pt-1 border-t border-purple-900/40 flex items-center justify-between">
            <span>Provenance: <strong className="text-emerald-400 uppercase">{activity.provenance || "OBSERVED"} TELEMETRY</strong></span>
            <span>Recorded: <strong>{new Date(activity.ts).toLocaleString()}</strong></span>
          </div>
        </div>

        {/* Structured Interaction Metadata */}
        <div className="space-y-2">
          <span className="text-[11px] font-bold text-slate-400">Interaction Telemetry Details:</span>
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-[11px]">
            {Boolean(activity.metadata?.cmdline) && (
              <div>
                <span className="text-slate-500 block mb-0.5">Executed Command Line:</span>
                <div className="p-2 rounded bg-slate-900 border border-slate-800 text-emerald-400 flex items-center gap-2 font-mono">
                  <Terminal className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                  <code>{String(activity.metadata?.cmdline)}</code>
                </div>
              </div>
            )}

            <div className="grid grid-cols-3 gap-2 pt-1 text-[10px]">
              <div>
                <span className="text-slate-500 block">Sensor Tool:</span>
                <span className="text-slate-200 font-bold uppercase">{activity.sensor_tool}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Interaction Type:</span>
                <span className="text-slate-200 font-bold">{activity.interaction_type}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Recorded Outcome:</span>
                <span className="text-slate-200 font-bold uppercase flex items-center gap-1">
                  {activity.outcome === "success" ? (
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <XCircle className="w-3 h-3 text-red-400" />
                  )}
                  {activity.outcome}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Raw Evidence Reference */}
        {activity.raw_evidence_ref && (
          <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 text-[10px] text-slate-400 flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 text-blue-400" />
              Source Log: <strong className="text-slate-300">{String(activity.raw_evidence_ref.file || "sensor log")}</strong> (offset: {String(activity.raw_evidence_ref.offset || 0)})
            </span>
            <span className="text-slate-500">Event ID: {activity.event_id}</span>
          </div>
        )}

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-100"
          >
            Close
          </Button>

          <div className="flex items-center gap-2">
            {activity.incident_id && (
              <>
                <Link href={`/incidents?id=${activity.incident_id}`}>
                  <Button
                    size="sm"
                    variant="outline"
                    className="gap-1.5 border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 font-medium"
                  >
                    View Incident Details
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Button>
                </Link>
                <Link href={`/graph?incident_id=${activity.incident_id}`}>
                  <Button
                    size="sm"
                    className="gap-1.5 bg-purple-600 hover:bg-purple-500 text-white font-bold"
                  >
                    Inspect in Attack Graph
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Button>
                </Link>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
