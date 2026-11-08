"use client";

import { useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Clock,
  Layers,
  Radio,
  Shield,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import type { GuardDecision } from "@contracts/index";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useEventStream } from "@/hooks/useEventStream";
import { evaluateGuardAction, fetchIncidentById, type IncidentWithEvidence } from "@/lib/api";
import { useEventStore } from "@/lib/store";
import { cn } from "@/lib/utils";

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "bg-red-950/60", text: "text-red-400", border: "border-red-800/60" },
  high: { bg: "bg-orange-950/60", text: "text-orange-400", border: "border-orange-800/60" },
  medium: { bg: "bg-amber-950/60", text: "text-amber-400", border: "border-amber-800/60" },
  low: { bg: "bg-slate-900/60", text: "text-slate-400", border: "border-slate-800" },
};

const STAGE_LABELS: Record<string, string> = {
  initial_access: "Initial Access",
  discovery: "Discovery",
  credential_access: "Cred Access",
  lateral_movement: "Lateral Move",
  ot_impact: "OT Impact",
};

export default function IncidentsPage() {
  useEventStream();
  const { incidents, guardDecisions, status } = useEventStore();

  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetail, setIncidentDetail] = useState<IncidentWithEvidence | null>(null);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);

  // Guard action tester state
  const [guardAction, setGuardAction] = useState<string>("isolate_host");
  const [guardTarget, setGuardTarget] = useState<string>("plc-sim");
  const [testingGuard, setTestingGuard] = useState<boolean>(false);
  const [latestGuardDecision, setLatestGuardDecision] = useState<GuardDecision | null>(null);

  // Select incident and fetch detailed evidence
  const handleSelectIncident = async (id: string) => {
    if (selectedIncidentId === id) {
      setSelectedIncidentId(null);
      setIncidentDetail(null);
      return;
    }
    setSelectedIncidentId(id);
    setLoadingDetail(true);
    try {
      const detail = await fetchIncidentById(id);
      setIncidentDetail(detail);
    } catch (err) {
      console.error("Failed to load incident detail:", err);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleTestGuard = async () => {
    setTestingGuard(true);
    try {
      const dec = await evaluateGuardAction(
        guardAction,
        guardTarget,
        selectedIncidentId || undefined,
      );
      setLatestGuardDecision(dec);
    } catch (err) {
      console.error("Failed to evaluate guard action:", err);
    } finally {
      setTestingGuard(false);
    }
  };

  const activeIncidents = useMemo(() => {
    return incidents.filter((inc) => inc.score >= 0.50);
  }, [incidents]);

  return (
    <div className="p-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-6 h-6 text-red-400" />
            Security Incidents & Response Guard
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Correlated multi-engine attack chains, kill-chain progression scoring, and safety-verified automated containment.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge
            variant="outline"
            className="bg-emerald-950/40 text-emerald-400 border-emerald-800/60 font-mono text-xs px-2.5 py-1"
          >
            Budget: 0.50 Thresh (0.000 FP/24h)
          </Badge>
          <div className="flex items-center gap-2 font-mono text-xs px-3 py-1.5 rounded-md border border-slate-800 bg-slate-900/60">
            <Radio
              className={cn(
                "w-3 h-3 animate-pulse",
                status === "open" ? "text-emerald-400" : "text-amber-400",
              )}
            />
            <span className="text-slate-300">Live WS: {status}</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Incident Cards & Guard Action Tester */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Incidents List (2 cols) */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-200 flex items-center gap-2">
              <Layers className="w-5 h-5 text-slate-400" />
              Active Correlated Incidents ({activeIncidents.length})
            </h2>
            <span className="text-xs text-slate-500 font-mono">
              Total Recorded: {incidents.length}
            </span>
          </div>

          {activeIncidents.length === 0 ? (
            <Card className="border-slate-800 bg-slate-900/40 p-8 text-center">
              <p className="text-slate-400 text-sm">
                No active incidents above the 0.50 budget threshold. Ingest telemetry or run a replay scenario to observe incident correlation.
              </p>
            </Card>
          ) : (
            activeIncidents.map((inc) => {
              const sev = SEVERITY_COLORS[inc.severity] || SEVERITY_COLORS.low;
              const isSelected = selectedIncidentId === inc.incident_id;

              return (
                <Card
                  key={inc.incident_id}
                  onClick={() => handleSelectIncident(inc.incident_id)}
                  className={cn(
                    "cursor-pointer border transition-all duration-200 bg-slate-900/50 hover:bg-slate-900/80",
                    isSelected ? "border-red-500/80 ring-1 ring-red-500/50" : "border-slate-800",
                  )}
                >
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <CardTitle className="text-base font-mono text-slate-100">
                            {inc.incident_id}
                          </CardTitle>
                          <Badge
                            className={cn(
                              "font-mono text-xs uppercase px-2 py-0.5 border",
                              sev.bg,
                              sev.text,
                              sev.border,
                            )}
                          >
                            {inc.severity} ({inc.score.toFixed(2)})
                          </Badge>
                          {inc.decoy_touched && (
                            <Badge className="bg-rose-950/60 text-rose-300 border-rose-800/60 text-xs">
                              Decoy Touched
                            </Badge>
                          )}
                          {inc.ot_touched && (
                            <Badge className="bg-red-950/60 text-red-300 border-red-800/60 text-xs">
                              OT Impacted
                            </Badge>
                          )}
                        </div>
                        <CardDescription className="text-xs text-slate-400 mt-1 flex items-center gap-4">
                          <span>
                            Started: {new Date(inc.first_signal_ts).toLocaleTimeString()}
                          </span>
                          <span>
                            TTFMA: {inc.ttfma_seconds !== null && inc.ttfma_seconds !== undefined ? `${inc.ttfma_seconds.toFixed(1)}s` : "0.0s"}
                          </span>
                          <span>Signals: {inc.signal_ids.length}</span>
                          <span>Events: {inc.event_ids.length}</span>
                        </CardDescription>
                      </div>
                      <ChevronRight
                        className={cn(
                          "w-5 h-5 text-slate-500 transition-transform",
                          isSelected && "rotate-90 text-red-400",
                        )}
                      />
                    </div>
                  </CardHeader>

                  <CardContent className="space-y-3 pt-0">
                    {/* Kill Chain Stage Progress Bar */}
                    <div className="space-y-1">
                      <div className="text-xs text-slate-400 flex justify-between">
                        <span>Kill Chain Progression:</span>
                        <span className="font-mono text-slate-300">
                          {inc.kill_chain_stages.length} stages
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {inc.kill_chain_stages.map((stg) => (
                          <span
                            key={stg}
                            className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700"
                          >
                            {STAGE_LABELS[stg] || stg}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Forensic Narrative Sample */}
                    {inc.explanation.length > 0 && (
                      <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/60 text-xs text-slate-300 font-mono space-y-1">
                        <div className="text-slate-500 font-semibold mb-1">
                          Forensic Milestones:
                        </div>
                        {inc.explanation.slice(0, 3).map((line, idx) => (
                          <div key={idx} className="truncate">
                            • {line}
                          </div>
                        ))}
                        {inc.explanation.length > 3 && (
                          <div className="text-slate-500 text-[11px] italic">
                            + {inc.explanation.length - 3} additional evidence items...
                          </div>
                        )}
                      </div>
                    )}

                    {/* MITRE Technique Chips */}
                    {inc.techniques.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap pt-1">
                        {inc.techniques.slice(0, 6).map((t) => (
                          <span
                            key={t.technique_id}
                            className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-950/40 text-purple-300 border border-purple-800/40"
                          >
                            {t.technique_id}: {t.name}
                          </span>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              );
            })
          )}

          {/* Drilldown Evidence Panel */}
          {selectedIncidentId && (
            <Card className="border-slate-800 bg-slate-900/60 p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  Forensic Drilldown: {selectedIncidentId}
                </h3>
                {loadingDetail && (
                  <span className="text-xs text-slate-400 animate-pulse">Loading evidence...</span>
                )}
              </div>

              {incidentDetail && (
                <div className="space-y-4 text-xs">
                  {/* Narrative Section */}
                  <div>
                    <h4 className="font-semibold text-slate-300 mb-2">Chronological Attack Narrative</h4>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto pr-2 font-mono text-slate-400">
                      {incidentDetail.explanation.map((line, idx) => (
                        <div key={idx} className="p-1.5 rounded bg-slate-950 border border-slate-800/80">
                          {line}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Attached Signals */}
                  <div>
                    <h4 className="font-semibold text-slate-300 mb-2">
                      Constituent Signals ({incidentDetail.signals.length})
                    </h4>
                    <div className="space-y-1.5 max-h-40 overflow-y-auto pr-2 font-mono text-[11px]">
                      {incidentDetail.signals.map((sig) => (
                        <div
                          key={sig.signal_id}
                          className="flex items-center justify-between p-1.5 rounded bg-slate-950/80 border border-slate-800"
                        >
                          <span className="text-slate-200 font-semibold">{sig.rule_id || sig.detector.toUpperCase()}: {sig.title}</span>
                          <span className="text-slate-400">conf: {sig.confidence.toFixed(2)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </Card>
          )}
        </div>

        {/* Right Column: Response Safety Guard Tester */}
        <div className="space-y-6">
          <Card className="border-slate-800 bg-slate-900/50">
            <CardHeader>
              <CardTitle className="text-base text-slate-200 flex items-center gap-2">
                <Shield className="w-5 h-5 text-indigo-400" />
                Response Safety Guard Tester
              </CardTitle>
              <CardDescription className="text-xs text-slate-400">
                Evaluate proposed automated containment actions against asset criticality and live PLC physics states.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-xs font-semibold text-slate-300">Containment Action</label>
                <select
                  value={guardAction}
                  onChange={(e) => setGuardAction(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="isolate_host">isolate_host (Sever Host Network)</option>
                  <option value="block_ip">block_ip (Boundary Firewall Drop)</option>
                  <option value="disable_account">disable_account (Revoke Credential)</option>
                  <option value="block_modbus_write">block_modbus_write (Modbus FC05/06 Filter)</option>
                  <option value="kill_process">kill_process (Terminate Process Tree)</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-xs font-semibold text-slate-300">Target Asset / Identity</label>
                <input
                  type="text"
                  value={guardTarget}
                  onChange={(e) => setGuardTarget(e.target.value)}
                  placeholder="e.g. plc-sim, 10.10.1.5, jump-host, svc_backup"
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
                />
                <div className="flex gap-1.5 flex-wrap text-[10px]">
                  <span className="text-slate-500">Presets:</span>
                  <button
                    onClick={() => { setGuardAction("isolate_host"); setGuardTarget("plc-sim"); }}
                    className="text-slate-400 hover:text-indigo-400 underline font-mono"
                  >
                    plc-sim (OT)
                  </button>
                  <button
                    onClick={() => { setGuardAction("block_ip"); setGuardTarget("10.10.1.5"); }}
                    className="text-slate-400 hover:text-indigo-400 underline font-mono"
                  >
                    10.10.1.5 (Attacker)
                  </button>
                  <button
                    onClick={() => { setGuardAction("disable_account"); setGuardTarget("svc_backup"); }}
                    className="text-slate-400 hover:text-indigo-400 underline font-mono"
                  >
                    svc_backup
                  </button>
                </div>
              </div>

              <Button
                onClick={handleTestGuard}
                disabled={testingGuard}
                className="w-full bg-indigo-600 hover:bg-indigo-500 text-white text-xs py-2"
              >
                {testingGuard ? "Evaluating Policies..." : "Evaluate Guard Decision"}
              </Button>

              {/* Guard Decision Result Card */}
              {latestGuardDecision && (
                <div
                  className={cn(
                    "p-4 rounded border space-y-2",
                    latestGuardDecision.decision === "allow" && "bg-emerald-950/40 border-emerald-800 text-emerald-300",
                    latestGuardDecision.decision === "deny" && "bg-red-950/40 border-red-800 text-red-300",
                    latestGuardDecision.decision === "needs_human" && "bg-amber-950/40 border-amber-800 text-amber-300",
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm uppercase flex items-center gap-1.5">
                      {latestGuardDecision.decision === "allow" && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                      {latestGuardDecision.decision === "deny" && <XCircle className="w-4 h-4 text-red-400" />}
                      {latestGuardDecision.decision === "needs_human" && <AlertTriangle className="w-4 h-4 text-amber-400" />}
                      Decision: {latestGuardDecision.decision}
                    </span>
                    <Badge variant="outline" className="text-[10px] font-mono">
                      {latestGuardDecision.rule_ids[0] || "GUARD-DEFAULT"}
                    </Badge>
                  </div>

                  <div className="text-[11px] font-mono opacity-90">
                    Target Criticality: {latestGuardDecision.asset_criticality || "low"}
                  </div>

                  <div className="space-y-1 text-xs pt-1 border-t border-slate-800/60">
                    {latestGuardDecision.reasons.map((r, i) => (
                      <p key={i} className="text-slate-300 leading-relaxed">• {r}</p>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Recent Guard Decision History */}
          <Card className="border-slate-800 bg-slate-900/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                <Clock className="w-4 h-4 text-slate-400" />
                Recent Safety Guard Evaluations ({guardDecisions.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {guardDecisions.length === 0 ? (
                <p className="text-xs text-slate-500">No evaluations logged yet.</p>
              ) : (
                <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                  {guardDecisions.map((dec) => (
                    <div
                      key={dec.decision_id}
                      className="p-2 rounded bg-slate-950 border border-slate-800 text-xs flex items-center justify-between"
                    >
                      <div className="font-mono text-[11px]">
                        <span className="text-slate-300 font-semibold">{dec.action}</span>
                        <span className="text-slate-500"> ({dec.target})</span>
                      </div>
                      <Badge
                        className={cn(
                          "text-[10px] uppercase font-mono px-1.5 py-0.5",
                          dec.decision === "allow" && "bg-emerald-950 text-emerald-400 border-emerald-800",
                          dec.decision === "deny" && "bg-red-950 text-red-400 border-red-800",
                          dec.decision === "needs_human" && "bg-amber-950 text-amber-400 border-amber-800",
                        )}
                      >
                        {dec.decision}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
