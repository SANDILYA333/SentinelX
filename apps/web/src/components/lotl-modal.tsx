"use client";

import React from "react";
import type { LotLInteraction, LotLLure } from "@contracts/index";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { StatusBadge } from "@/components/ui/status-badge";
import { SeverityBadge } from "@/components/ui/severity-badge";
import {
  FileText,
  Key,
  Shield,
  Server,
  Terminal,
  Clock,
  Activity,
  AlertTriangle,
  FolderLock,
  X,
  Lock,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface LotLModalProps {
  lure: LotLLure | null;
  interactions?: LotLInteraction[];
  onClose: () => void;
  onToggleEnabled?: (lureId: string, enabled: boolean) => void;
}

export function LotLModal({
  lure,
  interactions = [],
  onClose,
  onToggleEnabled,
}: LotLModalProps) {
  if (!lure) return null;

  const relevantInteractions = interactions.filter((i) => i.lure_id === lure.lure_id);

  const getLureIcon = (type: string) => {
    switch (type) {
      case "shell_history":
      case "powershell_history":
        return <Terminal className="w-5 h-5 text-amber-400" />;
      case "ssh_key":
      case "ssh_config":
        return <Key className="w-5 h-5 text-rose-400" />;
      case "canary_env":
        return <AlertTriangle className="w-5 h-5 text-amber-400" />;
      case "decoy_share":
        return <FolderLock className="w-5 h-5 text-sky-400" />;
      case "scheduled_task":
        return <Clock className="w-5 h-5 text-indigo-400" />;
      default:
        return <FileText className="w-5 h-5 text-cyan-400" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-slate-950 border border-slate-800 rounded-lg shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-md bg-slate-800 border border-slate-700">
              {getLureIcon(lure.lure_type)}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-slate-400 font-semibold tracking-wider">
                  {lure.lure_id}
                </span>
                <StatusBadge status={lure.status} />
                <SeverityBadge severity={lure.severity} />
              </div>
              <h2 className="text-lg font-semibold text-slate-100">{lure.name}</h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-100 rounded-md hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <ScrollArea className="flex-1 p-6 space-y-6">
          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-slate-900/60 border-slate-800">
              <CardContent className="p-4 space-y-3">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  DEPLOYMENT TOPOLOGY
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Target Host:</span>
                    <span className="font-mono font-medium text-slate-200 flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-cyan-400" />
                      {lure.host}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Platform:</span>
                    <span className="capitalize text-slate-200">{lure.platform}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Target Path:</span>
                    <span className="font-mono text-xs text-amber-300 break-all max-w-[260px] text-right">
                      {lure.path}
                    </span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-400">Decoy Destination:</span>
                    <span className="font-mono text-xs text-rose-300">
                      {lure.decoy_destination || "Local Endpoint Trap"}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-900/60 border-slate-800">
              <CardContent className="p-4 space-y-3">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  TELEMETRY ATTRIBUTION & INTEGRITY
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Total Interactions:</span>
                    <span className="font-mono font-bold text-slate-100 flex items-center gap-1">
                      <Activity className="w-3.5 h-3.5 text-emerald-400" />
                      {lure.total_interactions}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Last Touch:</span>
                    <span className="font-mono text-xs text-slate-300">
                      {lure.last_interaction ? new Date(lure.last_interaction).toLocaleString() : "Never observed"}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">SHA-256 Digest:</span>
                    <span className="font-mono text-xs text-slate-400 truncate max-w-[200px]" title={lure.sha256_hash || ""}>
                      {lure.sha256_hash ? `${lure.sha256_hash.substring(0, 16)}...` : "N/A"}
                    </span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-400">Administrative Status:</span>
                    <span className={cn("text-xs font-semibold uppercase", lure.enabled ? "text-emerald-400" : "text-slate-500")}>
                      {lure.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Description & Intelligence Narrative */}
          <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800 space-y-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              LURE PURPOSE & ADVERSARY TRAP
            </span>
            <p className="text-sm text-slate-300 leading-relaxed">{lure.description}</p>
          </div>

          {/* MITRE ATT&CK Mapping */}
          <div className="space-y-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              MAPPED MITRE ATT&CK TECHNIQUES
            </span>
            <div className="flex flex-wrap gap-2">
              {lure.mitre_techniques.map((tid) => (
                <Badge
                  key={tid}
                  variant="outline"
                  className="bg-slate-900 text-sky-300 border-sky-800/60 font-mono text-xs py-1 px-2.5 flex items-center gap-1.5"
                >
                  <Shield className="w-3.5 h-3.5 text-sky-400" />
                  {tid}
                </Badge>
              ))}
            </div>
          </div>

          {/* Secret Redaction Advisory */}
          <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-800/40 flex items-start gap-3">
            <Lock className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div className="text-xs text-emerald-200 leading-relaxed">
              <span className="font-semibold text-emerald-300">Credential Safety Policy Active:</span> All synthetic private key bodies, tokens, and database passwords planted by the Living-off-the-Land deception engine are cryptographically unique bait artifacts. Real production secrets are never deployed. Plaintext canary values are strictly redacted in API outputs.
            </div>
          </div>

          {/* Interaction History for this Lure */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                RECENT ATTRIBUTED INTERACTIONS ({relevantInteractions.length})
              </span>
            </div>

            {relevantInteractions.length === 0 ? (
              <div className="p-6 text-center rounded-lg border border-dashed border-slate-800 text-slate-500 text-sm">
                No attacker interactions observed for this lure yet. Sensor is actively monitoring.
              </div>
            ) : (
              <div className="space-y-2">
                {relevantInteractions.map((act) => (
                  <div
                    key={act.interaction_id}
                    className="p-3 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-700 transition-colors space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-slate-400">{new Date(act.ts).toLocaleTimeString()}</span>
                        <Badge variant="outline" className="font-mono text-[10px] bg-slate-950 text-slate-300">
                          {act.interaction_type}
                        </Badge>
                        {act.mitre_technique && (
                          <Badge variant="outline" className="font-mono text-[10px] text-sky-400 border-sky-800/40">
                            {act.mitre_technique}
                          </Badge>
                        )}
                      </div>
                      <span className="font-mono text-xs text-slate-400">
                        Sensor: {act.evidence_source}
                      </span>
                    </div>
                    {act.cmdline && (
                      <div className="p-2 rounded bg-slate-950 border border-slate-800/80 font-mono text-xs text-amber-300 overflow-x-auto">
                        $ {act.cmdline}
                      </div>
                    )}
                    <div className="flex items-center justify-between text-xs text-slate-400 pt-0.5">
                      <span>User: <strong className="text-slate-300 font-mono">{act.user || "N/A"}</strong></span>
                      <span>Target: <span className="font-mono text-slate-300">{act.target}</span></span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </ScrollArea>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-slate-800 bg-slate-900/50">
          <div className="text-xs text-slate-500 font-mono">
            ID: {lure.lure_id}
          </div>
          <div className="flex items-center gap-3">
            {onToggleEnabled && lure.status !== "unsupported" && (
              <Button
                variant={lure.enabled ? "destructive" : "default"}
                size="sm"
                onClick={() => onToggleEnabled(lure.lure_id, !lure.enabled)}
              >
                {lure.enabled ? "Disable Lure" : "Enable Lure"}
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

