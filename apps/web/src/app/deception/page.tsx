"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { Action, GuardDecision } from "@contracts/index";
import { evaluateGuardAction, fetchAssets } from "@/lib/api";
import { useEventStream } from "@/hooks/useEventStream";
import { useEventStore } from "@/lib/store";
import { getGuardStyle } from "@/lib/theme";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Send,
  Shield,
  ShieldAlert,
  XCircle,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

const GUARD_ACTIONS: { value: Action; label: string; desc: string }[] = [
  { value: "isolate_host", label: "Isolate Host", desc: "Sever network interfaces" },
  { value: "block_ip", label: "Block IP", desc: "Drop traffic at firewall boundary" },
  { value: "block_modbus_write", label: "Block Modbus Write", desc: "Filter OT actuator write commands" },
  { value: "disable_account", label: "Disable Account", desc: "Revoke compromised user authentication" },
  { value: "kill_process", label: "Kill Process", desc: "Terminate suspicious process execution" },
];

export default function DeceptionGuardPage() {
  useEventStream();
  const { signals, incidents, guardDecisions } = useEventStore();

  const { data: assets } = useQuery({
    queryKey: ["assets"],
    queryFn: fetchAssets,
  });

  // Guard action tester state
  const [selectedAction, setSelectedAction] = useState<Action>("isolate_host");
  const [selectedTarget, setSelectedTarget] = useState<string>("plc-sim");
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("");
  const [testing, setTesting] = useState<boolean>(false);
  const [latestDecision, setLatestDecision] = useState<GuardDecision | null>(null);

  // Decoy assets list from assets inventory
  const decoyAssets = useMemo(() => {
    if (!assets) return [];
    return assets.filter((a) => a.is_decoy);
  }, [assets]);

  // Compute interaction counts on decoys from signals
  const decoyActivity = useMemo(() => {
    const activityMap: Record<string, { count: number; honeytokens: number; lastTouched: string | null }> = {
      cowrie: { count: 0, honeytokens: 0, lastTouched: null },
      opencanary: { count: 0, honeytokens: 0, lastTouched: null },
      "decoy-plc": { count: 0, honeytokens: 0, lastTouched: null },
    };

    for (const sig of signals) {
      for (const ent of sig.entities) {
        const val = ent.value.toLowerCase();
        for (const decoyKey of Object.keys(activityMap)) {
          if (val === decoyKey || val.includes(decoyKey) || (decoyKey === "cowrie" && val === "backup-srv-02") || (decoyKey === "opencanary" && val === "db-prod-02")) {
            activityMap[decoyKey].count++;
            if (!activityMap[decoyKey].lastTouched || sig.ts > activityMap[decoyKey].lastTouched!) {
              activityMap[decoyKey].lastTouched = sig.ts;
            }
          }
        }
      }
      if (sig.detector === "deception" || sig.rule_id === "RULE-DECOY-001" || sig.metadata?.confirmed_honeytoken) {
        // Also check entities
        for (const decoyKey of Object.keys(activityMap)) {
          if (sig.entities.some((e) => e.value.toLowerCase().includes(decoyKey) || (decoyKey === "cowrie" && e.value.includes("backup-srv-02")))) {
            activityMap[decoyKey].honeytokens++;
          }
        }
      }
    }

    return activityMap;
  }, [signals]);

  const handleTestGuard = async () => {
    setTesting(true);
    try {
      const dec = await evaluateGuardAction(
        selectedAction,
        selectedTarget,
        selectedIncidentId || undefined
      );
      setLatestDecision(dec);
    } catch (err) {
      console.error("Guard test error:", err);
    } finally {
      setTesting(false);
    }
  };

  const handlePresetDemo = (action: Action, target: string) => {
    setSelectedAction(action);
    setSelectedTarget(target);
    if (incidents.length > 0) {
      setSelectedIncidentId(incidents[0].incident_id);
    }
  };

  // Distinct targets for dropdown
  const availableTargets = useMemo(() => {
    if (!assets) return ["plc-sim", "eng-ws", "jump-host", "10.10.1.5", "file-srv", "svc_backup"];
    const names = assets.map((a) => a.name);
    // Add known users and IP
    return Array.from(new Set([...names, "10.10.1.5", "svc_backup", "svc_dbadmin"])).sort();
  }, [assets]);

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto w-full">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <ShieldAlert className="w-6 h-6 text-purple-400" />
            Deception Assets &amp; Response Safety Guard
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Canary bait telemetry monitoring and automated response containment policy enforcement.
          </p>
        </div>

        <Badge variant="outline" className="bg-purple-950/60 text-purple-300 border-purple-800/60 font-mono text-xs">
          Policy Engine: Active
        </Badge>
      </div>

      {/* SECTION 1: DECEPTION CANARY ASSETS */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-slate-200 flex items-center gap-2">
            <Shield className="w-4 h-4 text-purple-400" />
            Active Deception Canaries ({decoyAssets.length})
          </h2>
          <span className="text-xs text-slate-500 font-mono">Real-time interaction telemetry</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {decoyAssets.map((decoy) => {
            const stats = decoyActivity[decoy.name] || { count: 0, honeytokens: 0, lastTouched: null };
            const isTouched = stats.count > 0;
            const primaryIp = decoy.ips ? (Object.values(decoy.ips)[0] as string) || "N/A" : "N/A";

            return (
              <Card
                key={decoy.name}
                className={cn(
                  "border transition-all shadow-md relative overflow-hidden",
                  isTouched
                    ? "bg-purple-950/40 border-purple-600/80 shadow-[0_0_20px_rgba(168,85,247,0.2)]"
                    : "bg-slate-900/50 border-slate-800 hover:border-slate-700"
                )}
              >
                {isTouched && (
                  <div className="absolute top-0 right-0 left-0 h-1 bg-gradient-to-r from-purple-500 to-rose-500 animate-pulse" />
                )}

                <CardHeader className="p-4 pb-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CardTitle className="text-sm font-bold text-slate-100 font-mono">
                        {decoy.name}
                      </CardTitle>
                      {decoy.hostname && (
                        <span className="text-[10px] font-mono text-slate-400 px-1.5 py-0.5 rounded bg-slate-800">
                          as &apos;{decoy.hostname}&apos;
                        </span>
                      )}
                    </div>

                    <Badge
                      variant="outline"
                      className={cn(
                        "text-[10px] uppercase font-mono py-0",
                        isTouched
                          ? "bg-purple-950/80 text-purple-300 border-purple-600 animate-pulse"
                          : "bg-slate-800/80 text-slate-400 border-slate-700"
                      )}
                    >
                      {isTouched ? "Touched" : "Untouched"}
                    </Badge>
                  </div>

                  <CardDescription className="text-xs text-slate-400 font-mono">
                    {decoy.role.replace(/_/g, " ")} &bull; {primaryIp} ({decoy.zone})
                  </CardDescription>
                </CardHeader>

                <CardContent className="p-4 pt-2 space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    <div className="p-2 rounded bg-slate-950/60 border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 block">Touch Signals</span>
                      <span className={cn(
                        "text-base font-bold",
                        stats.count > 0 ? "text-purple-300" : "text-slate-400"
                      )}>
                        {stats.count}
                      </span>
                    </div>

                    <div className="p-2 rounded bg-slate-950/60 border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 block">Honeytoken Alarms</span>
                      <span className={cn(
                        "text-base font-bold",
                        stats.honeytokens > 0 ? "text-rose-400" : "text-slate-400"
                      )}>
                        {stats.honeytokens}
                      </span>
                    </div>
                  </div>

                  <div className="text-[11px] font-mono text-slate-500 flex justify-between pt-1 border-t border-slate-800/60">
                    <span>Last Interaction:</span>
                    <span className="text-slate-300 font-medium">
                      {stats.lastTouched ? new Date(stats.lastTouched).toLocaleTimeString() : "None"}
                    </span>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* SECTION 2: RESPONSE SAFETY GUARD & TESTER */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Guard Action Tester (The Demo Moment) */}
        <div className="lg:col-span-5 space-y-4">
          <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
            <CardHeader className="pb-3 border-b border-slate-800/80">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <Zap className="w-4 h-4 text-amber-400" />
                  Response Guard Containment Tester
                </CardTitle>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                  Pre-Execution Interlock
                </span>
              </div>
              <CardDescription className="text-xs text-slate-400">
                Safely test automated containment decisions against OT physics interlocks and critical asset policies.
              </CardDescription>
            </CardHeader>

            <CardContent className="pt-4 space-y-4 font-mono text-xs">
              {/* Quick Preset Buttons for Live Demo */}
              <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1.5">
                <span className="text-[10px] uppercase tracking-wider text-slate-400 font-bold block">
                  Demo Fast Presets:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => handlePresetDemo("isolate_host", "plc-sim")}
                    className="px-2 py-1 rounded bg-red-950/40 border border-red-800/60 text-red-300 hover:bg-red-900/40 text-[10px] transition"
                  >
                    1. Isolate PLC (OT Critical)
                  </button>
                  <button
                    type="button"
                    onClick={() => handlePresetDemo("block_ip", "10.10.1.5")}
                    className="px-2 py-1 rounded bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 hover:bg-emerald-900/40 text-[10px] transition"
                  >
                    2. Block Attacker IP (IT Boundary)
                  </button>
                  <button
                    type="button"
                    onClick={() => handlePresetDemo("isolate_host", "jump-host")}
                    className="px-2 py-1 rounded bg-amber-950/40 border border-amber-800/60 text-amber-300 hover:bg-amber-900/40 text-[10px] transition"
                  >
                    3. Isolate Jump Host (Needs Human)
                  </button>
                </div>
              </div>

              {/* Form Inputs */}
              <div className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400">Containment Action:</label>
                  <select
                    value={selectedAction}
                    onChange={(e) => setSelectedAction(e.target.value as Action)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-hidden focus:border-blue-500"
                  >
                    {GUARD_ACTIONS.map((a) => (
                      <option key={a.value} value={a.value}>
                        {a.label} ({a.desc})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400">Target Asset / Host / IP:</label>
                  <select
                    value={selectedTarget}
                    onChange={(e) => setSelectedTarget(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-hidden focus:border-blue-500"
                  >
                    {availableTargets.map((t) => (
                      <option key={t} value={t}>
                        {t}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400">Contextual Incident (Optional):</label>
                  <select
                    value={selectedIncidentId}
                    onChange={(e) => setSelectedIncidentId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-hidden focus:border-blue-500"
                  >
                    <option value="">None (Independent Policy Check)</option>
                    {incidents.map((i) => (
                      <option key={i.incident_id} value={i.incident_id}>
                        {i.incident_id} ({i.severity.toUpperCase()} - {(i.score * 100).toFixed(0)}%)
                      </option>
                    ))}
                  </select>
                </div>

                <Button
                  onClick={handleTestGuard}
                  disabled={testing}
                  className="w-full gap-2 bg-blue-600 hover:bg-blue-500 text-white font-mono text-xs font-semibold py-2.5 rounded-lg"
                >
                  <Send className="w-3.5 h-3.5" />
                  {testing ? "Evaluating Policy Matrix..." : "Evaluate Safety Guard Policy"}
                </Button>
              </div>

              {/* Evaluation Outcome Display */}
              {latestDecision && (
                <div
                  className={cn(
                    "p-4 rounded-xl border space-y-3 animate-in fade-in duration-200",
                    latestDecision.decision === "deny"
                      ? "bg-red-950/40 border-red-700/80 shadow-[0_0_15px_rgba(239,68,68,0.25)]"
                      : latestDecision.decision === "allow"
                        ? "bg-emerald-950/40 border-emerald-700/80 shadow-[0_0_15px_rgba(16,185,129,0.25)]"
                        : "bg-amber-950/40 border-amber-700/80 shadow-[0_0_15px_rgba(245,158,11,0.25)]"
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-sm tracking-wider uppercase flex items-center gap-2">
                      {latestDecision.decision === "deny" && <XCircle className="w-4 h-4 text-red-400" />}
                      {latestDecision.decision === "allow" && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                      {latestDecision.decision === "needs_human" && <AlertTriangle className="w-4 h-4 text-amber-400" />}
                      <span className={cn(
                        latestDecision.decision === "deny" ? "text-red-400" : latestDecision.decision === "allow" ? "text-emerald-400" : "text-amber-400"
                      )}>
                        DECISION: {latestDecision.decision.toUpperCase()}
                      </span>
                    </span>

                    <span className="text-[10px] text-slate-400 px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                      Rule: {latestDecision.rule_ids[0]}
                    </span>
                  </div>

                  <div className="space-y-1 text-slate-300 text-[11px] leading-relaxed">
                    {latestDecision.reasons.map((r, idx) => (
                      <p key={idx} className={cn(r.toLowerCase().includes("safer alternative") ? "text-emerald-300 font-semibold pt-1 border-t border-slate-800/80" : "")}>
                        &bull; {r}
                      </p>
                    ))}
                  </div>

                  <div className="flex items-center justify-between pt-1 border-t border-slate-800/60 text-[10px] text-slate-400">
                    <span>Criticality: <strong className="text-slate-200">{latestDecision.asset_criticality}</strong></span>
                    <span>Action: <strong className="text-slate-200">{latestDecision.action}</strong></span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Live Feed of Guard Decisions */}
        <div className="lg:col-span-7 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-400" />
              Guard Decision Audit History ({guardDecisions.length})
            </h2>
            <span className="text-xs text-slate-500 font-mono">Streamed via WebSocket</span>
          </div>

          <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
            <CardContent className="p-0">
              <ScrollArea className="h-[520px]">
                <div className="divide-y divide-slate-800/60 font-mono text-xs">
                  {guardDecisions.length === 0 ? (
                    <div className="p-16 text-center text-slate-500 space-y-2">
                      <Shield className="w-8 h-8 mx-auto opacity-40 text-slate-400" />
                      <p>No containment actions evaluated yet.</p>
                      <p className="text-[11px] text-slate-600">
                        Use the tester on the left to evaluate automated response containment actions.
                      </p>
                    </div>
                  ) : (
                    guardDecisions.map((dec) => {
                      const guardStyle = getGuardStyle(dec.decision);
                      return (
                        <div
                          key={dec.decision_id}
                          className="p-4 hover:bg-slate-900/80 transition-colors space-y-2"
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className={cn("text-[10px] uppercase font-bold py-0.5", guardStyle.badge)}>
                                {dec.decision}
                              </Badge>
                              <span className="text-xs font-bold text-slate-200">
                                {dec.action} &rarr; <span className="text-blue-400">{dec.target}</span>
                              </span>
                            </div>

                            <div className="flex items-center gap-2 text-slate-400 text-[11px]">
                              <Badge variant="outline" className="text-[10px] bg-slate-950 text-slate-400 border-slate-800">
                                {dec.rule_ids[0] || "GUARD-DEFAULT"}
                              </Badge>
                              <span>{new Date(dec.ts).toLocaleTimeString()}</span>
                            </div>
                          </div>

                          <p className="text-[11px] text-slate-400 leading-relaxed">
                            {dec.reasons[0]}
                          </p>

                          {dec.reasons.length > 2 && dec.reasons[2].toLowerCase().includes("safer alternative") && (
                            <div className="p-2 rounded bg-emerald-950/20 border border-emerald-800/40 text-emerald-300 text-[11px]">
                              {dec.reasons[2]}
                            </div>
                          )}

                          <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-800/40">
                            <span>Criticality: {dec.asset_criticality}</span>
                            <span>Requested by: {dec.requested_by}</span>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
