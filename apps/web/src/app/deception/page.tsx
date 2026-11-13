"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { Action, DeceptionActivity, GuardDecision, LotLLure } from "@contracts/index";
import {
  disableLotLLure,
  deployLotLLures,
  enableLotLLure,
  evaluateGuardAction,
  fetchAssets,
  fetchDeceptionActivities,
  fetchDeceptionAssets,
  fetchDeceptionOverview,
  fetchLotLAnalytics,
  fetchLotLHealth,
  fetchLotLInteractions,
  fetchLotLLures,
  verifyLotLLures,
} from "@/lib/api";
import { useEventStream } from "@/hooks/useEventStream";
import { useEventStore } from "@/lib/store";
import { getGuardStyle } from "@/lib/theme";
import { DeceptionFeed } from "@/components/deception-feed";
import { DeceptionModal } from "@/components/deception-modal";
import { LotLInventory } from "@/components/lotl-inventory";
import { LotLFeed } from "@/components/lotl-feed";
import { LotLAnalyticsView } from "@/components/lotl-analytics";
import { LotLModal } from "@/components/lotl-modal";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  HeartPulse,
  Info,
  Layers,
  Send,
  Server,
  Shield,
  ShieldAlert,
  Terminal,
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

function DeceptionGuardContent() {
  useEventStream();
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();
  const tabParam = searchParams.get("tab");
  const { incidents, guardDecisions } = useEventStore();

  const [activeTab, setActiveTab] = useState<"deception" | "lotl" | "guard">(
    tabParam === "guard" ? "guard" : tabParam === "lotl" ? "lotl" : "deception"
  );
  const [lotlSubTab, setLotlSubTab] = useState<"inventory" | "feed" | "analytics">("inventory");
  const [selectedDeceptionActivity, setSelectedDeceptionActivity] = useState<DeceptionActivity | null>(null);
  const [selectedLotLLure, setSelectedLotLLure] = useState<LotLLure | null>(null);
  const [isDeployingLotL, setIsDeployingLotL] = useState<boolean>(false);

  useEffect(() => {
    if (tabParam === "guard") {
      setActiveTab("guard");
    } else if (tabParam === "lotl") {
      setActiveTab("lotl");
    } else if (tabParam === "deception") {
      setActiveTab("deception");
    }
  }, [tabParam]);

  // Deception backend queries
  const { data: overview } = useQuery({
    queryKey: ["deception-overview"],
    queryFn: fetchDeceptionOverview,
    refetchInterval: 5000,
  });

  const { data: activities = [] } = useQuery({
    queryKey: ["deception-activities"],
    queryFn: () => fetchDeceptionActivities(),
    refetchInterval: 5000,
  });

  const { data: deceptionAssets = [] } = useQuery({
    queryKey: ["deception-assets"],
    queryFn: fetchDeceptionAssets,
    refetchInterval: 5000,
  });

  const { data: assets } = useQuery({
    queryKey: ["assets"],
    queryFn: fetchAssets,
  });

  // LotL Deception Queries
  const { data: lotlLures = [] } = useQuery({
    queryKey: ["lotl-lures"],
    queryFn: () => fetchLotLLures(),
    refetchInterval: 5000,
  });

  const { data: lotlInteractions = [] } = useQuery({
    queryKey: ["lotl-interactions"],
    queryFn: () => fetchLotLInteractions({ limit: 100 }),
    refetchInterval: 5000,
  });

  const { data: lotlHealth = null } = useQuery({
    queryKey: ["lotl-health"],
    queryFn: fetchLotLHealth,
    refetchInterval: 10000,
  });

  const { data: lotlAnalytics = null } = useQuery({
    queryKey: ["lotl-analytics"],
    queryFn: fetchLotLAnalytics,
    refetchInterval: 5000,
  });

  const handleToggleLotLEnabled = async (lureId: string, enabled: boolean) => {
    try {
      if (enabled) {
        await enableLotLLure(lureId);
      } else {
        await disableLotLLure(lureId);
      }
      queryClient.invalidateQueries({ queryKey: ["lotl-lures"] });
      queryClient.invalidateQueries({ queryKey: ["lotl-analytics"] });
    } catch (err) {
      console.error("Failed to toggle LotL lure enabled status:", err);
    }
  };

  const handleDeployAllLotL = async () => {
    setIsDeployingLotL(true);
    try {
      await deployLotLLures();
      queryClient.invalidateQueries({ queryKey: ["lotl-lures"] });
      queryClient.invalidateQueries({ queryKey: ["lotl-health"] });
      queryClient.invalidateQueries({ queryKey: ["lotl-analytics"] });
    } catch (err) {
      console.error("Failed to deploy LotL lures:", err);
    } finally {
      setIsDeployingLotL(false);
    }
  };

  const handleVerifyAllLotL = async () => {
    try {
      await verifyLotLLures();
      queryClient.invalidateQueries({ queryKey: ["lotl-lures"] });
      queryClient.invalidateQueries({ queryKey: ["lotl-health"] });
    } catch (err) {
      console.error("Failed to verify LotL lures:", err);
    }
  };

  // Guard action tester state
  const [selectedAction, setSelectedAction] = useState<Action>("isolate_host");
  const [selectedTarget, setSelectedTarget] = useState<string>("plc-sim");
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("");
  const [testing, setTesting] = useState<boolean>(false);
  const [latestDecision, setLatestDecision] = useState<GuardDecision | null>(null);

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

  const availableTargets = useMemo(() => {
    if (!assets) return ["plc-sim", "eng-ws", "jump-host", "10.10.1.5", "file-srv", "svc_backup"];
    const names = assets.map((a) => a.name);
    return Array.from(new Set([...names, "10.10.1.5", "svc_backup", "svc_dbadmin"])).sort();
  }, [assets]);

  return (
    <div className="p-8 space-y-7 max-w-7xl mx-auto w-full font-mono text-xs">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <ShieldAlert className="w-6 h-6 text-purple-400" />
            Deception Intelligence &amp; Response Safety Guard
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time adversary deception telemetry classification and pre-execution safety interlocks.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
          <button
            type="button"
            onClick={() => setActiveTab("deception")}
            className={cn(
              "px-3.5 py-1.5 rounded-lg transition font-bold text-xs flex items-center gap-1.5",
              activeTab === "deception"
                ? "bg-purple-600 text-white shadow-md shadow-purple-900/30"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            <Shield className="w-3.5 h-3.5" /> Deception Canaries
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("lotl")}
            className={cn(
              "px-3.5 py-1.5 rounded-lg transition font-bold text-xs flex items-center gap-1.5",
              activeTab === "lotl"
                ? "bg-purple-600 text-white shadow-md shadow-purple-900/30"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            <Terminal className="w-3.5 h-3.5" /> LotL Deception Engine
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("guard")}
            className={cn(
              "px-3.5 py-1.5 rounded-lg transition font-bold text-xs flex items-center gap-1.5",
              activeTab === "guard"
                ? "bg-blue-600 text-white shadow-md shadow-blue-900/30"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            <Zap className="w-3.5 h-3.5" /> Safety Guard Interlock
          </button>
        </div>
      </div>

      {/* OVERVIEW METRICS KPI BAR */}
      {activeTab === "lotl" ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Active Managed Lures
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-purple-300">
                {lotlAnalytics?.total_active_lures ?? lotlLures.filter((l) => l.enabled).length}
              </span>
              <span className="text-[10px] text-emerald-400">
                / {lotlLures.length} total
              </span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Lures Discovered
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-rose-400">
                {lotlAnalytics?.total_discovered_lures ?? 0}
              </span>
              <span className="text-[10px] text-slate-500">artifacts probed</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Total LotL Interactions
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-cyan-400">
                {lotlAnalytics?.total_interactions ?? lotlInteractions.length}
              </span>
              <span className="text-[10px] text-slate-500">audit &amp; FIM events</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Canary Invocations
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-amber-400">
                {lotlAnalytics?.canary_presentations ?? 0}
              </span>
              <span className="text-[10px] text-slate-500">credential accesses</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Total Deception Interactions
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-purple-300">
                {overview?.total_interactions ?? activities.length}
              </span>
              <span className="text-[10px] text-slate-500">classified events</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Incidents Involving Canaries
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-rose-400">
                {overview?.incident_count ?? 1}
              </span>
              <span className="text-[10px] text-slate-500">correlated attacks</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Unique Attacker Sources
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-amber-400">
                {overview?.unique_sources?.length ?? 2}
              </span>
              <span className="text-[10px] text-slate-500">source IPs trapped</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Active Decoy Infrastructure
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-emerald-400">
                {deceptionAssets.filter((a) => (a.status as string) === "active").length} / {deceptionAssets.length || 3}
              </span>
              <span className="text-[10px] text-slate-500">decoys engaged</span>
            </div>
          </div>
        </div>
      )}

      {/* TAB A: DECEPTION INTELLIGENCE WORKSPACE */}
      {activeTab === "deception" && (
        <div className="space-y-6">
          {/* Deception Threat Interpretations Box */}
          {overview?.deception_interpretations && overview.deception_interpretations.length > 0 && (
            <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-800/40 space-y-2.5">
              <span className="font-bold text-xs text-purple-300 flex items-center gap-1.5 uppercase tracking-wider">
                <Shield className="w-4 h-4 text-purple-400" />
                Adversary Deception Intelligence Interpretations:
              </span>
              <div className="space-y-1.5 text-xs text-slate-300 leading-relaxed">
                {overview.deception_interpretations.map((interp, idx) => (
                  <div key={idx} className="p-2 rounded bg-purple-950/30 border border-purple-900/40 flex items-start gap-2">
                    <span className="text-purple-400 font-bold">&bull;</span>
                    <p>{interp}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Configured Decoy Inventory Cards */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Server className="w-4 h-4 text-purple-400" />
                Configured Deception Canary Assets ({deceptionAssets.length})
              </h2>
              <span className="text-[11px] text-slate-500">Live operational telemetry status</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
              {deceptionAssets.map((decoy) => {
                const isTouched = (decoy.total_interactions ?? 0) > 0;
                const primaryIp = decoy.ips ? (Object.values(decoy.ips)[0] as string) || "N/A" : "N/A";

                return (
                  <Card
                    key={decoy.name}
                    className={cn(
                      "border transition-all shadow-md relative overflow-hidden bg-slate-900/60",
                      isTouched
                        ? "border-purple-600/70 shadow-[0_0_15px_rgba(168,85,247,0.2)]"
                        : "border-slate-800"
                    )}
                  >
                    <CardHeader className="p-4 pb-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <CardTitle className="text-sm font-bold text-slate-100">
                            {decoy.name}
                          </CardTitle>
                          {decoy.hostname && (
                            <span className="text-[10px] text-slate-400 px-1.5 py-0.5 rounded bg-slate-800">
                              as &apos;{decoy.hostname}&apos;
                            </span>
                          )}
                        </div>

                        <Badge
                          variant="outline"
                          className={cn(
                            "text-[9px] uppercase py-0",
                            isTouched
                              ? "bg-purple-950/80 text-purple-300 border-purple-600"
                              : "bg-slate-800/80 text-slate-400 border-slate-700"
                          )}
                        >
                          {decoy.status}
                        </Badge>
                      </div>

                      <CardDescription className="text-xs text-slate-400 mt-1">
                        {decoy.role.replace(/_/g, " ")} &bull; {primaryIp} ({decoy.zone.toUpperCase()})
                      </CardDescription>
                    </CardHeader>

                    <CardContent className="p-4 pt-2 space-y-2.5">
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div className="p-2 rounded bg-slate-950 border border-slate-800">
                          <span className="text-[10px] text-slate-500 block">Interactions</span>
                          <span className="text-base font-bold text-purple-300">
                            {decoy.total_interactions}
                          </span>
                        </div>
                        <div className="p-2 rounded bg-slate-950 border border-slate-800">
                          <span className="text-[10px] text-slate-500 block">Trapped Sources</span>
                          <span className="text-base font-bold text-red-400">
                            {decoy.unique_source_ips?.length ?? 0}
                          </span>
                        </div>
                      </div>

                      <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
                        <span>Last Trapped:</span>
                        <span className="text-slate-200">
                          {decoy.last_seen ? new Date(decoy.last_seen).toLocaleTimeString() : "Untouched"}
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>

          {/* Deception Activity Feed */}
          <div className="space-y-3">
            <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-purple-400" />
              Chronological Deception Activity Feed ({activities.length})
            </h2>
            <DeceptionFeed
              activities={activities}
              onSelectActivity={(act) => setSelectedDeceptionActivity(act)}
              selectedActivityId={selectedDeceptionActivity?.activity_id}
            />
          </div>
        </div>
      )}

      {/* TAB B: LIVING-OFF-THE-LAND (LotL) DECEPTION WORKSPACE */}
      {activeTab === "lotl" && (
        <div className="space-y-6">
          {/* Sub-tab Navigation */}
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setLotlSubTab("inventory")}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5",
                  lotlSubTab === "inventory"
                    ? "bg-purple-600 text-white"
                    : "bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800"
                )}
              >
                <Layers className="w-3.5 h-3.5" /> Lure Inventory ({lotlLures.length})
              </button>
              <button
                type="button"
                onClick={() => setLotlSubTab("feed")}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5",
                  lotlSubTab === "feed"
                    ? "bg-purple-600 text-white"
                    : "bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800"
                )}
              >
                <Activity className="w-3.5 h-3.5" /> Live Touches Feed ({lotlInteractions.length})
              </button>
              <button
                type="button"
                onClick={() => setLotlSubTab("analytics")}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5",
                  lotlSubTab === "analytics"
                    ? "bg-purple-600 text-white"
                    : "bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800"
                )}
              >
                <HeartPulse className="w-3.5 h-3.5" /> Analytics &amp; Health
              </button>
            </div>

            <div className="text-[11px] text-slate-400 hidden sm:flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Engine Status: {lotlHealth?.sensors_healthy ? "HEALTHY" : "DEGRADED"}</span>
            </div>
          </div>

          {/* Subtab Content */}
          {lotlSubTab === "inventory" && (
            <LotLInventory
              lures={lotlLures}
              interactions={lotlInteractions}
              onToggleEnabled={handleToggleLotLEnabled}
              onDeployAll={handleDeployAllLotL}
              onVerifyAll={handleVerifyAllLotL}
              isDeploying={isDeployingLotL}
            />
          )}

          {lotlSubTab === "feed" && (
            <LotLFeed
              interactions={lotlInteractions}
              onSelectInteraction={(interaction) => {
                const lure = lotlLures.find((l) => l.lure_id === interaction.lure_id) || null;
                setSelectedLotLLure(lure);
              }}
            />
          )}

          {lotlSubTab === "analytics" && (
            <LotLAnalyticsView
              analytics={lotlAnalytics}
              health={lotlHealth}
            />
          )}
        </div>
      )}

      {/* TAB C: RESPONSE SAFETY GUARD INTERLOCK WORKSPACE */}
      {activeTab === "guard" && (
        <div className="space-y-4">
          <div className="p-3 rounded-xl bg-blue-950/30 border border-blue-800/60 flex items-start gap-3">
            <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            <div className="text-[11px] font-sans text-slate-300 leading-relaxed">
              <strong className="text-blue-300 font-semibold font-mono block mb-0.5">
                ADVISORY SAFETY MODE — NO AUTOMATIC EXECUTION
              </strong>
              SentinelX Response Safety Guard evaluates containment actions against authoritative OT process safety policies.
              An <strong className="text-emerald-400 font-mono">ALLOW</strong> decision does not automatically execute commands against production networks. All containment must be performed manually by authorized operators.
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Interactive Pre-Execution Interlock Tester */}
          <div className="lg:col-span-5 space-y-4">
            <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
              <CardHeader className="pb-3 border-b border-slate-800/80">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-bold text-slate-100 flex items-center gap-2">
                    <Zap className="w-4 h-4 text-amber-400" />
                    Response Guard Policy Interlock
                  </CardTitle>
                  <span className="text-[10px] uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                    Pre-Execution
                  </span>
                </div>
                <CardDescription className="text-xs text-slate-400">
                  Deterministically evaluate containment actions against OT physical process safety policies.
                </CardDescription>
              </CardHeader>

              <CardContent className="pt-4 space-y-4">
                {/* Demo Quick Presets */}
                <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1.5">
                  <span className="text-[10px] uppercase text-slate-400 font-bold block">
                    Fast Scenario Presets:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    <button
                      type="button"
                      onClick={() => handlePresetDemo("isolate_host", "plc-sim")}
                      className="px-2 py-1 rounded bg-red-950/40 border border-red-800/60 text-red-300 hover:bg-red-900/40 text-[10px] transition"
                    >
                      1. Isolate PLC Controller (OT)
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

                {/* Form Controls */}
                <div className="space-y-3">
                  <div className="space-y-1">
                    <label className="text-[11px] text-slate-400">Proposed Containment Action:</label>
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
                      <option value="">None (Independent Safety Check)</option>
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
                    className="w-full gap-2 bg-blue-600 hover:bg-blue-500 text-white font-bold py-2.5 rounded-lg"
                  >
                    <Send className="w-3.5 h-3.5" />
                    {testing ? "Evaluating Policy Matrix..." : "Evaluate Safety Guard Policy"}
                  </Button>
                </div>

                {/* Outcome Display Card */}
                {latestDecision && (
                  <div
                    className={cn(
                      "p-4 rounded-xl border space-y-3 animate-in fade-in duration-200",
                      latestDecision.decision === "deny"
                        ? "bg-red-950/40 border-red-700/80 text-red-200 shadow-[0_0_15px_rgba(239,68,68,0.25)]"
                        : latestDecision.decision === "allow"
                        ? "bg-emerald-950/40 border-emerald-700/80 text-emerald-200 shadow-[0_0_15px_rgba(16,185,129,0.25)]"
                        : "bg-amber-950/40 border-amber-700/80 text-amber-200 shadow-[0_0_15px_rgba(245,158,11,0.25)]"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-sm uppercase flex items-center gap-1.5">
                        {latestDecision.decision === "deny" && <XCircle className="w-4 h-4 text-red-400" />}
                        {latestDecision.decision === "allow" && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                        {latestDecision.decision === "needs_human" && <AlertTriangle className="w-4 h-4 text-amber-400" />}
                        DECISION: {latestDecision.decision.toUpperCase()}
                      </span>

                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                        Rule: {latestDecision.rule_ids?.[0] || "POL-SAFETY"}
                      </span>
                    </div>

                    <div className="space-y-1 text-slate-200 text-xs leading-relaxed">
                      {(Array.isArray(latestDecision.reasons) ? latestDecision.reasons : [(latestDecision as unknown as Record<string, string>).reasoning || "Policy evaluated."]).map((r, idx) => (
                        <p key={idx} className={cn(r.toLowerCase().includes("safer alternative") ? "text-emerald-300 font-bold pt-1 border-t border-slate-800" : "")}>
                          &bull; {r}
                        </p>
                      ))}
                    </div>

                    <div className="flex items-center justify-between pt-1 border-t border-slate-800/60 text-[10px] text-slate-400">
                      <span>Criticality: <strong className="text-slate-100">{latestDecision.asset_criticality || "standard"}</strong></span>
                      <span>Target Zone: <strong className="text-slate-100 uppercase">{latestDecision.target_zone || "IT"}</strong></span>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Right Column: Live Feed of Guard Decisions & Approvals */}
          <div className="lg:col-span-7 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                <Clock className="w-4 h-4 text-blue-400" />
                Safety Guard Decision Audit Trail ({guardDecisions.length})
              </h2>
              <span className="text-[11px] text-slate-500">Live WebSocket stream &bull; Auditable record</span>
            </div>

            <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
              <CardContent className="p-0">
                <ScrollArea className="h-[560px]">
                  <div className="divide-y divide-slate-800/60">
                    {guardDecisions.length === 0 ? (
                      <div className="p-16 text-center text-slate-500 space-y-2">
                        <Shield className="w-8 h-8 mx-auto opacity-40 text-slate-400" />
                        <p>No containment actions evaluated yet.</p>
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
                                  {dec.rule_ids?.[0] || "GUARD-DEFAULT"}
                                </Badge>
                                <span>{new Date(dec.ts).toLocaleTimeString()}</span>
                              </div>
                            </div>

                            <p className="text-xs text-slate-300 leading-relaxed">
                              {dec.reasons?.[0]}
                            </p>

                            {dec.reasons && dec.reasons.length > 2 && dec.reasons[2].toLowerCase().includes("safer alternative") && (
                              <div className="p-2 rounded bg-emerald-950/20 border border-emerald-800/40 text-emerald-300 text-xs">
                                {dec.reasons[2]}
                              </div>
                            )}

                            <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-800/40">
                              <span>Criticality: {dec.asset_criticality || "standard"} &bull; Zone: {dec.target_zone?.toUpperCase() || "IT"}</span>
                              <span>
                                Approval: <strong className="uppercase text-slate-300">{dec.approval_status || "not_required"}</strong>
                                {dec.approved_by && ` (by ${dec.approved_by})`}
                              </span>
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
      )}

      {/* Deception Activity Inspection Modal */}
      <DeceptionModal
        activity={selectedDeceptionActivity}
        onClose={() => setSelectedDeceptionActivity(null)}
      />

      {/* LotL Lure Inspection Modal */}
      <LotLModal
        lure={selectedLotLLure}
        interactions={lotlInteractions}
        onClose={() => setSelectedLotLLure(null)}
        onToggleEnabled={handleToggleLotLEnabled}
      />
    </div>
  );
}

export default function DeceptionGuardPage() {
  return (
    <Suspense fallback={<div className="p-8 text-slate-400 font-mono text-xs">Loading deception &amp; safety workspace...</div>}>
      <DeceptionGuardContent />
    </Suspense>
  );
}
