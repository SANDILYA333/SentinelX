"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  fetchEvaluationOverview,
  fetchEvaluationRun,
  fetchEvaluationRuns,
  triggerEvaluationRun,
  type EvaluationOverviewResponse,
  type EvaluationRunListItem,
} from "@/lib/api";
import type {
  EvaluationRunSummary,
  ScenarioEvaluationResult,
} from "@contracts/index";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Award,
  BarChart3,
  CheckCircle2,
  Clock,
  Cpu,
  FileCheck2,
  FlaskConical,
  Gauge,
  History,
  Layers,
  Loader2,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
  Target,
  Terminal,
  XCircle,
  Zap,
} from "lucide-react";

function fmtPct(val: number | null | undefined): string {
  return typeof val === "number" ? `${(val * 100).toFixed(1)}%` : "N/A";
}

function fmtScore(val: number | null | undefined, digits: number = 3): string {
  return typeof val === "number" ? val.toFixed(digits) : "N/A";
}

export default function EvalPage() {
  const queryClient = useQueryClient();
  const [activeMainTab, setActiveMainTab] = useState<"phase-d" | "legacy">("phase-d");
  const [phaseDSubTab, setPhaseDSubTab] = useState<
    "overview" | "detectors" | "scenarios" | "gaps" | "performance" | "history"
  >("overview");

  // Selection states for Phase D
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedScenario, setSelectedScenario] = useState<ScenarioEvaluationResult | null>(null);
  const [scenarioFilterCategory, setScenarioFilterCategory] = useState<string>("all");
  const [scenarioFilterSplit, setScenarioFilterSplit] = useState<string>("all");
  const [scenarioFilterStatus, setScenarioFilterStatus] = useState<string>("all");
  const [scenarioSearch, setScenarioSearch] = useState<string>("");

  // History comparison
  const [compareRunAId, setCompareRunAId] = useState<string>("");
  const [compareRunBId, setCompareRunBId] = useState<string>("");

  // Queries for Phase D
  const { data: evalOverview } = useQuery<EvaluationOverviewResponse>({
    queryKey: ["eval-overview"],
    queryFn: fetchEvaluationOverview,
    staleTime: 30_000,
  });

  const { data: evalRuns = [] } = useQuery<EvaluationRunListItem[]>({
    queryKey: ["eval-runs"],
    queryFn: () => fetchEvaluationRuns(30),
    staleTime: 30_000,
  });

  // Effective run ID to inspect (selected, or fallback to latest)
  const currentRunId = selectedRunId || evalOverview?.latest_run_id || (evalRuns[0]?.run_id ?? "");

  const {
    data: runDetail,
    isLoading: isRunDetailLoading,
    refetch: refetchRunDetail,
  } = useQuery<EvaluationRunSummary>({
    queryKey: ["eval-run-detail", currentRunId],
    queryFn: () => fetchEvaluationRun(currentRunId),
    enabled: !!currentRunId,
    staleTime: 60_000,
  });

  // Compare runs detail queries
  const { data: runA } = useQuery<EvaluationRunSummary>({
    queryKey: ["eval-run-detail", compareRunAId],
    queryFn: () => fetchEvaluationRun(compareRunAId),
    enabled: !!compareRunAId,
  });

  const { data: runB } = useQuery<EvaluationRunSummary>({
    queryKey: ["eval-run-detail", compareRunBId],
    queryFn: () => fetchEvaluationRun(compareRunBId),
    enabled: !!compareRunBId,
  });

  // Mutation to trigger new evaluation
  const runMutation = useMutation({
    mutationFn: () => triggerEvaluationRun(["dev", "validation", "test"], 0.50),
    onSuccess: (newRun) => {
      setSelectedRunId(newRun.run_id);
      queryClient.invalidateQueries({ queryKey: ["eval-overview"] });
      queryClient.invalidateQueries({ queryKey: ["eval-runs"] });
      queryClient.invalidateQueries({ queryKey: ["eval-run-detail"] });
    },
  });



  const activeRun = runDetail;

  // Filtered scenarios
  const filteredScenarios = (activeRun?.scenarios ?? []).filter((sc) => {
    if (scenarioFilterCategory !== "all" && sc.category !== scenarioFilterCategory) return false;
    if (scenarioFilterSplit !== "all" && sc.split !== scenarioFilterSplit) return false;
    if (scenarioFilterStatus !== "all" && sc.classification !== scenarioFilterStatus) return false;
    if (scenarioSearch.trim()) {
      const q = scenarioSearch.toLowerCase();
      const matchName = sc.name.toLowerCase().includes(q);
      const matchId = sc.scenario_id.toLowerCase().includes(q);
      if (!matchName && !matchId) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Badge variant="outline" className="bg-sky-950/40 text-sky-400 border-sky-800 text-[11px] font-mono">
              PHASE D VERIFIED
            </Badge>
            <span className="text-xs text-slate-500 font-mono">D0 → D7 BENCHMARK HARNESS</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <FlaskConical className="w-6 h-6 text-sky-400" />
            Detection Evaluation & System Performance
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic multi-tier evaluation measuring precision, recall, false positive rates, processing latencies, and alert budget gating across IT, DMZ, and OT environments.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Main Mode Toggle: Phase D vs Legacy */}
          <div className="flex bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs">
            <button
              onClick={() => setActiveMainTab("phase-d")}
              className={`px-3 py-1.5 rounded-md font-medium transition-all ${
                activeMainTab === "phase-d"
                  ? "bg-sky-600 text-white shadow-sm"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Phase D Evaluation
            </button>
            <button
              onClick={() => setActiveMainTab("legacy")}
              className={`px-3 py-1.5 rounded-md font-medium transition-all ${
                activeMainTab === "legacy"
                  ? "bg-slate-800 text-white shadow-sm"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Phase 7 Ablation
            </button>
          </div>

          <Button
            size="sm"
            variant="default"
            className="bg-sky-600 hover:bg-sky-500 text-white text-xs gap-1.5 shadow-sm"
            disabled={runMutation.isPending}
            onClick={() => runMutation.mutate()}
          >
            {runMutation.isPending ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Evaluating...
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                Run Evaluation
              </>
            )}
          </Button>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* PHASE D PRIMARY EVALUATION DASHBOARD                                  */}
      {/* ===================================================================== */}
      {activeMainTab === "phase-d" && (
        <div className="space-y-6">
          {/* Run Selector & Metadata Bar */}
          <Card className="border-slate-800 bg-slate-900/40">
            <CardContent className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-slate-300">Run:</span>
                  <select
                    className="bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 rounded px-2.5 py-1.5 focus:outline-none focus:border-sky-500"
                    value={currentRunId}
                    onChange={(e) => setSelectedRunId(e.target.value)}
                  >
                    {evalRuns.map((r) => (
                      <option key={r.run_id} value={r.run_id}>
                        {r.run_id} ({new Date(r.created_at).toLocaleTimeString()}) — F1: {fmtPct(r.headline.f1_score)}
                      </option>
                    ))}
                  </select>
                </div>

                {activeRun && (
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline" className="bg-slate-950 text-slate-300 border-slate-800 text-[11px] font-mono">
                      Dataset: v{activeRun.dataset_version}
                    </Badge>
                    <Badge variant="outline" className="bg-slate-950 text-slate-300 border-slate-800 text-[11px] font-mono">
                      Git: {activeRun.git_commit}
                    </Badge>
                    <Badge variant="outline" className="bg-slate-950 text-slate-300 border-slate-800 text-[11px] font-mono">
                      Splits: {(activeRun.splits_evaluated ?? []).join(", ")}
                    </Badge>
                  </div>
                )}
              </div>

              <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
                {activeRun && (
                  <>
                    <span>Throughput: <strong className="text-sky-400">{activeRun.throughput_eps} EPS</strong></span>
                    <span>•</span>
                    <span>P95 Latency: <strong className="text-emerald-400">{activeRun.latency.end_to_end_latency.p95}ms</strong></span>
                    <span>•</span>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 text-xs text-slate-400 hover:text-slate-200"
                      onClick={() => refetchRunDetail()}
                    >
                      <RefreshCw className="w-3 h-3" />
                    </Button>
                  </>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Sub Navigation Bar for Phase D */}
          <div className="flex border-b border-slate-800 text-xs overflow-x-auto">
            <button
              onClick={() => setPhaseDSubTab("overview")}
              className={`pb-2.5 px-4 font-medium transition-all flex items-center gap-2 border-b-2 ${
                phaseDSubTab === "overview"
                  ? "border-sky-500 text-sky-400"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5" />
              Overview & KPIs
            </button>
            <button
              onClick={() => setPhaseDSubTab("detectors")}
              className={`pb-2.5 px-4 font-medium transition-all flex items-center gap-2 border-b-2 ${
                phaseDSubTab === "detectors"
                  ? "border-sky-500 text-sky-400"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              Detector & Rule Matrix
            </button>
            <button
              onClick={() => setPhaseDSubTab("scenarios")}
              className={`pb-2.5 px-4 font-medium transition-all flex items-center gap-2 border-b-2 ${
                phaseDSubTab === "scenarios"
                  ? "border-sky-500 text-sky-400"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <Target className="w-3.5 h-3.5" />
              Scenario Inspector ({activeRun?.scenarios?.length ?? 0})
            </button>
            <button
              onClick={() => setPhaseDSubTab("gaps")}
              className={`pb-2.5 px-4 font-medium transition-all flex items-center gap-2 border-b-2 ${
                phaseDSubTab === "gaps"
                  ? "border-amber-500 text-amber-400"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              False Negatives & Gaps ({activeRun?.false_negatives?.length ?? 0})
            </button>
            <button
              onClick={() => setPhaseDSubTab("performance")}
              className={`pb-2.5 px-4 font-medium transition-all flex items-center gap-2 border-b-2 ${
                phaseDSubTab === "performance"
                  ? "border-emerald-500 text-emerald-400"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <Clock className="w-3.5 h-3.5" />
              Latency & Performance
            </button>
            <button
              onClick={() => setPhaseDSubTab("history")}
              className={`pb-2.5 px-4 font-medium transition-all flex items-center gap-2 border-b-2 ${
                phaseDSubTab === "history"
                  ? "border-purple-500 text-purple-400"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <History className="w-3.5 h-3.5" />
              Run History & Compare
            </button>
          </div>

          {/* Loading state */}
          {isRunDetailLoading && (
            <div className="p-12 text-center text-slate-400 space-y-3">
              <Loader2 className="w-8 h-8 animate-spin mx-auto text-sky-500" />
              <p className="text-sm font-mono">Loading evaluation run telemetry and metrics...</p>
            </div>
          )}

          {/* Empty state */}
          {!isRunDetailLoading && !activeRun && (
            <Card className="border-slate-800 bg-slate-900/40 p-8 text-center space-y-3">
              <FlaskConical className="w-10 h-10 text-slate-600 mx-auto" />
              <h3 className="text-base font-semibold text-slate-200">No Evaluation Runs Found</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                No evaluation run has been recorded in the database yet. Click &quot;Run Evaluation&quot; to execute the evaluation engine across all captures.
              </p>
              <Button
                size="sm"
                className="bg-sky-600 text-white text-xs mt-2"
                onClick={() => runMutation.mutate()}
                disabled={runMutation.isPending}
              >
                Run Evaluation Now
              </Button>
            </Card>
          )}

          {activeRun && !isRunDetailLoading && (
            <>
              {/* SUB-TAB 1: OVERVIEW & KPIS */}
              {phaseDSubTab === "overview" && (
                <div className="space-y-6">
                  {/* KPI Cards Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
                    {/* Precision Card */}
                    <Card className="border-slate-800 bg-slate-900/60 shadow-sm">
                      <CardHeader className="pb-1.5 pt-3.5 px-4">
                        <span className="text-[11px] font-medium uppercase tracking-wider text-slate-400 flex items-center justify-between">
                          Precision
                          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        </span>
                      </CardHeader>
                      <CardContent className="px-4 pb-3.5">
                        <div className="text-2xl font-bold font-mono text-emerald-400">
                          {fmtPct(activeRun.headline.precision)}
                        </div>
                        <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                          TP: {activeRun.headline.tp ?? 0} | FP: {activeRun.headline.fp ?? 0}
                        </p>
                      </CardContent>
                    </Card>

                    {/* Recall Card */}
                    <Card className="border-slate-800 bg-slate-900/60 shadow-sm">
                      <CardHeader className="pb-1.5 pt-3.5 px-4">
                        <span className="text-[11px] font-medium uppercase tracking-wider text-slate-400 flex items-center justify-between">
                          Recall
                          <Target className="w-3.5 h-3.5 text-sky-400" />
                        </span>
                      </CardHeader>
                      <CardContent className="px-4 pb-3.5">
                        <div className="text-2xl font-bold font-mono text-sky-400">
                          {fmtPct(activeRun.headline.recall)}
                        </div>
                        <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                          TP: {activeRun.headline.tp ?? 0} | FN: {activeRun.headline.fn ?? 0}
                        </p>
                      </CardContent>
                    </Card>

                    {/* F1 Score Card */}
                    <Card className="border-slate-800 bg-slate-900/60 shadow-sm">
                      <CardHeader className="pb-1.5 pt-3.5 px-4">
                        <span className="text-[11px] font-medium uppercase tracking-wider text-slate-400 flex items-center justify-between">
                          F1 Score
                          <Award className="w-3.5 h-3.5 text-purple-400" />
                        </span>
                      </CardHeader>
                      <CardContent className="px-4 pb-3.5">
                        <div className="text-2xl font-bold font-mono text-purple-400">
                          {fmtScore(activeRun.headline.f1_score)}
                        </div>
                        <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                          Accuracy: {fmtPct(activeRun.headline.accuracy)}
                        </p>
                      </CardContent>
                    </Card>

                    {/* Attack Coverage */}
                    <Card className="border-slate-800 bg-slate-900/60 shadow-sm">
                      <CardHeader className="pb-1.5 pt-3.5 px-4">
                        <span className="text-[11px] font-medium uppercase tracking-wider text-slate-400 flex items-center justify-between">
                          Attack Coverage
                          <Zap className="w-3.5 h-3.5 text-amber-400" />
                        </span>
                      </CardHeader>
                      <CardContent className="px-4 pb-3.5">
                        <div className="text-2xl font-bold font-mono text-amber-400">
                          {activeRun.headline.tp ?? 0}/{(activeRun.headline.tp ?? 0) + (activeRun.headline.fn ?? 0)}
                        </div>
                        <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                          Missed: {activeRun.headline.fn ?? 0} ({fmtPct(activeRun.headline.fnr)})
                        </p>
                      </CardContent>
                    </Card>
                  </div>

                  {/* Multi-Tier Granularity Comparison Card */}
                  <Card className="border-slate-800 bg-slate-900/50">
                    <CardHeader className="pb-3 border-b border-slate-800/80">
                      <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
                        <Layers className="w-4 h-4 text-sky-400" />
                        Multi-Level Evaluation Hierarchy
                      </CardTitle>
                      <CardDescription className="text-xs text-slate-400">
                        SentinelX evaluates detection efficacy across three independent granularities to prevent misleading incident-only aggregation.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="p-0">
                      <table className="w-full text-xs text-left">
                        <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                          <tr>
                            <th className="p-3 pl-4">Evaluation Level</th>
                            <th className="p-3">True Positives</th>
                            <th className="p-3">False Positives</th>
                            <th className="p-3">False Negatives</th>
                            <th className="p-3">True Negatives</th>
                            <th className="p-3 text-right">Precision</th>
                            <th className="p-3 text-right">Recall</th>
                            <th className="p-3 pr-4 text-right">F1 Score</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono">
                          <tr className="hover:bg-slate-800/30">
                            <td className="p-3 pl-4 font-sans font-medium text-slate-200">
                              Scenario Level (Headline)
                            </td>
                            <td className="p-3 text-emerald-400">{activeRun.scenario_level.tp ?? 0}</td>
                            <td className="p-3 text-rose-400">{activeRun.scenario_level.fp ?? 0}</td>
                            <td className="p-3 text-amber-400">{activeRun.scenario_level.fn ?? 0}</td>
                            <td className="p-3 text-slate-400">{activeRun.scenario_level.tn ?? 0}</td>
                            <td className="p-3 text-right text-emerald-400">
                              {fmtPct(activeRun.scenario_level.precision)}
                            </td>
                            <td className="p-3 text-right text-sky-400">
                              {fmtPct(activeRun.scenario_level.recall)}
                            </td>
                            <td className="p-3 pr-4 text-right font-bold text-purple-400">
                              {fmtScore(activeRun.scenario_level.f1_score)}
                            </td>
                          </tr>

                          <tr className="hover:bg-slate-800/30">
                            <td className="p-3 pl-4 font-sans font-medium text-slate-200">
                              Incident Level (Correlation)
                            </td>
                            <td className="p-3 text-emerald-400">{activeRun.incident_level.tp ?? 0}</td>
                            <td className="p-3 text-rose-400">{activeRun.incident_level.fp ?? 0}</td>
                            <td className="p-3 text-amber-400">{activeRun.incident_level.fn ?? 0}</td>
                            <td className="p-3 text-slate-400">{activeRun.incident_level.tn ?? 0}</td>
                            <td className="p-3 text-right text-emerald-400">
                              {fmtPct(activeRun.incident_level.precision)}
                            </td>
                            <td className="p-3 text-right text-sky-400">
                              {fmtPct(activeRun.incident_level.recall)}
                            </td>
                            <td className="p-3 pr-4 text-right font-bold text-purple-400">
                              {fmtScore(activeRun.incident_level.f1_score)}
                            </td>
                          </tr>

                          <tr className="hover:bg-slate-800/30">
                            <td className="p-3 pl-4 font-sans font-medium text-slate-200">
                              Event Level (Telemetry Raw)
                            </td>
                            <td className="p-3 text-emerald-400">{activeRun.event_level.tp ?? 0}</td>
                            <td className="p-3 text-rose-400">{activeRun.event_level.fp ?? 0}</td>
                            <td className="p-3 text-amber-400">{activeRun.event_level.fn ?? 0}</td>
                            <td className="p-3 text-slate-400">{activeRun.event_level.tn ?? 0}</td>
                            <td className="p-3 text-right text-emerald-400">
                              {fmtPct(activeRun.event_level.precision)}
                            </td>
                            <td className="p-3 text-right text-sky-400">
                              {fmtPct(activeRun.event_level.recall)}
                            </td>
                            <td className="p-3 pr-4 text-right font-bold text-purple-400">
                              {fmtScore(activeRun.event_level.f1_score)}
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </CardContent>
                  </Card>

                  {/* Alert Budget Controller Evaluation Card */}
                  <Card className="border-slate-800 bg-slate-900/50">
                    <CardHeader className="pb-3 border-b border-slate-800/80">
                      <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center justify-between">
                        <span className="flex items-center gap-2">
                          <Gauge className="w-4 h-4 text-emerald-400" />
                          Alert Budget Controller Assessment (Workstream D4)
                        </span>
                        <Badge
                          variant="outline"
                          className={
                            activeRun.budget.budget_admitted_without_suppressing_attacks
                              ? "bg-emerald-950/40 text-emerald-400 border-emerald-800"
                              : "bg-rose-950/40 text-rose-400 border-rose-800"
                          }
                        >
                          {activeRun.budget.budget_admitted_without_suppressing_attacks
                            ? "CRITICAL ATTACKS PRESERVED"
                            : "ATTACK SUPPRESSION DETECTED"}
                        </Badge>
                      </CardTitle>
                      <CardDescription className="text-xs text-slate-400">
                        Ensures analyst alert fatigue reduction does not suppress high-severity incidents or critical OT attacks.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="p-4">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
                          <span className="text-[10px] text-slate-400 block uppercase font-mono">Emitted Signals</span>
                          <span className="text-lg font-bold font-mono text-slate-100">
                            {activeRun.budget.total_signals_emitted ?? 0}
                          </span>
                        </div>
                        <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
                          <span className="text-[10px] text-slate-400 block uppercase font-mono">Admitted Signals</span>
                          <span className="text-lg font-bold font-mono text-sky-400">
                            {activeRun.budget.admitted_signals ?? 0}
                          </span>
                        </div>
                        <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
                          <span className="text-[10px] text-slate-400 block uppercase font-mono">Preservation Rate</span>
                          <span className="text-lg font-bold font-mono text-emerald-400">
                            {fmtPct(activeRun.budget.high_severity_preservation_rate)}
                          </span>
                        </div>
                        <div className="p-3 rounded bg-slate-950/60 border border-slate-800">
                          <span className="text-[10px] text-slate-400 block uppercase font-mono">Critical Suppressed</span>
                          <span className="text-lg font-bold font-mono text-slate-300">
                            {activeRun.budget.critical_signals_suppressed ?? 0}
                          </span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* SUB-TAB 2: DETECTORS & RULES */}
              {phaseDSubTab === "detectors" && (
                <div className="space-y-6">
                  {/* Detector Engines Comparison */}
                  <Card className="border-slate-800 bg-slate-900/50">
                    <CardHeader className="pb-3 border-b border-slate-800/80">
                      <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-sky-400" />
                        Per-Engine Detection Breakdown
                      </CardTitle>
                      <CardDescription className="text-xs text-slate-400">
                        Performance breakdown across SentinelX&apos;s five autonomous detection mechanisms.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="p-0">
                      <table className="w-full text-xs text-left">
                        <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                          <tr>
                            <th className="p-3 pl-4">Detector</th>
                            <th className="p-3">Total Signals</th>
                            <th className="p-3">Attack Signals</th>
                            <th className="p-3">Benign Signals</th>
                            <th className="p-3">TP</th>
                            <th className="p-3">FP</th>
                            <th className="p-3 text-right">Precision</th>
                            <th className="p-3 text-right">Recall</th>
                            <th className="p-3 pr-4 text-right">F1 Score</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono">
                          {(activeRun.detectors ?? []).map((d) => (
                            <tr key={d.detector} className="hover:bg-slate-800/30">
                              <td className="p-3 pl-4 font-sans font-semibold text-slate-200 capitalize">
                                {d.detector}
                              </td>
                              <td className="p-3 text-slate-300">{d.total_signals}</td>
                              <td className="p-3 text-emerald-400">{d.attack_signals}</td>
                              <td className="p-3 text-slate-500">{d.benign_signals}</td>
                              <td className="p-3 text-emerald-400">{d.metrics.tp ?? 0}</td>
                              <td className="p-3 text-rose-400">{d.metrics.fp ?? 0}</td>
                              <td className="p-3 text-right text-emerald-400">
                                {fmtPct(d.metrics.precision)}
                              </td>
                              <td className="p-3 text-right text-sky-400">
                                {fmtPct(d.metrics.recall)}
                              </td>
                              <td className="p-3 pr-4 text-right font-bold text-purple-400">
                                {fmtScore(d.metrics.f1_score)}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </CardContent>
                  </Card>

                  {/* Individual Rules Matrix */}
                  <Card className="border-slate-800 bg-slate-900/50">
                    <CardHeader className="pb-3 border-b border-slate-800/80">
                      <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
                        <FileCheck2 className="w-4 h-4 text-emerald-400" />
                        Declarative YAML Detection Rules Efficacy
                      </CardTitle>
                      <CardDescription className="text-xs text-slate-400">
                        Granular performance for individual rules in <code className="text-sky-300">content/rules/</code>.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="p-0">
                      <table className="w-full text-xs text-left">
                        <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                          <tr>
                            <th className="p-3 pl-4">Rule ID</th>
                            <th className="p-3">Rule Title</th>
                            <th className="p-3">Attack Fires</th>
                            <th className="p-3">Benign Fires</th>
                            <th className="p-3 text-right">Precision</th>
                            <th className="p-3 text-right">Recall</th>
                            <th className="p-3 pr-4 text-right">F1</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono">
                          {(activeRun.rules ?? []).map((r) => (
                            <tr key={r.rule_id} className="hover:bg-slate-800/30">
                              <td className="p-3 pl-4 text-sky-400 font-semibold">{r.rule_id}</td>
                              <td className="p-3 font-sans text-slate-200">{r.title}</td>
                              <td className="p-3 text-emerald-400">{r.attack_fires}</td>
                              <td className="p-3 text-slate-500">{r.benign_fires}</td>
                              <td className="p-3 text-right text-emerald-400">
                                {fmtPct(r.metrics.precision)}
                              </td>
                              <td className="p-3 text-right text-sky-400">
                                {fmtPct(r.metrics.recall)}
                              </td>
                              <td className="p-3 pr-4 text-right font-bold text-purple-400">
                                {fmtScore(r.metrics.f1_score)}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* SUB-TAB 3: SCENARIOS INSPECTOR */}
              {phaseDSubTab === "scenarios" && (
                <div className="space-y-4">
                  {/* Filter Toolbar */}
                  <Card className="border-slate-800 bg-slate-900/40">
                    <CardContent className="p-3.5 flex flex-wrap items-center justify-between gap-3 text-xs">
                      <div className="flex flex-wrap items-center gap-2.5">
                        <div className="relative">
                          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                          <input
                            type="text"
                            placeholder="Search scenarios..."
                            className="bg-slate-950 border border-slate-800 text-slate-200 text-xs pl-8 pr-3 py-1.5 rounded focus:outline-none focus:border-sky-500"
                            value={scenarioSearch}
                            onChange={(e) => setScenarioSearch(e.target.value)}
                          />
                        </div>

                        {/* Category filter */}
                        <select
                          className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded px-2.5 py-1.5"
                          value={scenarioFilterCategory}
                          onChange={(e) => setScenarioFilterCategory(e.target.value)}
                        >
                          <option value="all">All Categories</option>
                          <option value="authentication">Authentication</option>
                          <option value="lateral_movement">Lateral Movement</option>
                          <option value="endpoint">Endpoint</option>
                          <option value="deception">Deception</option>
                          <option value="industrial_ot">Industrial OT</option>
                          <option value="benign">Benign Baselines</option>
                        </select>

                        {/* Split filter */}
                        <select
                          className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded px-2.5 py-1.5"
                          value={scenarioFilterSplit}
                          onChange={(e) => setScenarioFilterSplit(e.target.value)}
                        >
                          <option value="all">All Splits</option>
                          <option value="dev">Dev Split</option>
                          <option value="validation">Validation Split</option>
                          <option value="test">Test Split</option>
                        </select>

                        {/* Classification filter */}
                        <select
                          className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded px-2.5 py-1.5"
                          value={scenarioFilterStatus}
                          onChange={(e) => setScenarioFilterStatus(e.target.value)}
                        >
                          <option value="all">All Statuses</option>
                          <option value="TP">True Positive (TP)</option>
                          <option value="TN">True Negative (TN)</option>
                          <option value="FN">False Negative (FN)</option>
                          <option value="FP">False Positive (FP)</option>
                        </select>
                      </div>

                      <span className="text-slate-400 font-mono">
                        Showing <strong>{filteredScenarios.length}</strong> of {(activeRun.scenarios ?? []).length} scenarios
                      </span>
                    </CardContent>
                  </Card>

                  {/* Scenarios List */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {filteredScenarios.map((sc) => {
                      const isSuccess = sc.classification === "TP" || sc.classification === "TN";
                      return (
                        <Card
                          key={sc.scenario_id}
                          onClick={() => setSelectedScenario(sc)}
                          className={`border-slate-800 bg-slate-900/60 hover:bg-slate-800/40 cursor-pointer transition-all ${
                            selectedScenario?.scenario_id === sc.scenario_id ? "ring-1 ring-sky-500" : ""
                          }`}
                        >
                          <CardContent className="p-4 space-y-2.5">
                            <div className="flex items-start justify-between gap-2">
                              <div>
                                <div className="flex items-center gap-2 mb-1">
                                  <Badge
                                    variant="outline"
                                    className={`text-[10px] font-mono font-bold ${
                                      sc.classification === "TP"
                                        ? "bg-emerald-950/40 text-emerald-400 border-emerald-800"
                                        : sc.classification === "TN"
                                        ? "bg-slate-950 text-slate-400 border-slate-800"
                                        : sc.classification === "FN"
                                        ? "bg-amber-950/40 text-amber-400 border-amber-800"
                                        : "bg-rose-950/40 text-rose-400 border-rose-800"
                                    }`}
                                  >
                                    {sc.classification}
                                  </Badge>
                                  <span className="font-mono text-xs font-semibold text-sky-400">
                                    {sc.scenario_id}
                                  </span>
                                  <Badge variant="outline" className="bg-slate-950 text-slate-400 border-slate-800 text-[10px]">
                                    {sc.split}
                                  </Badge>
                                </div>
                                <h4 className="text-xs font-semibold text-slate-200">{sc.name}</h4>
                              </div>

                              <div className="text-right">
                                {isSuccess ? (
                                  <span className="text-[11px] font-medium text-emerald-400 flex items-center gap-1">
                                    <CheckCircle2 className="w-3.5 h-3.5" />
                                    PASS
                                  </span>
                                ) : (
                                  <span className="text-[11px] font-medium text-amber-400 flex items-center gap-1">
                                    <XCircle className="w-3.5 h-3.5" />
                                    MISS
                                  </span>
                                )}
                              </div>
                            </div>

                            <div className="text-[11px] text-slate-400 flex flex-wrap items-center gap-3 font-mono">
                              <span>Domain: <strong className="text-slate-300">{sc.category}</strong></span>
                              <span>•</span>
                              <span>Type: <strong className={sc.is_malicious ? "text-rose-400" : "text-emerald-400"}>{sc.is_malicious ? "Attack" : "Benign"}</strong></span>
                              {sc.time_to_detect_ms != null && (
                                <>
                                  <span>•</span>
                                  <span>TTD: <strong className="text-sky-400">{sc.time_to_detect_ms.toFixed(1)}ms</strong></span>
                                </>
                              )}
                            </div>

                            {(sc.matched_rules ?? []).length > 0 && (
                              <div className="flex flex-wrap gap-1 pt-1 border-t border-slate-800/60">
                                {(sc.matched_rules ?? []).map((r) => (
                                  <span key={r} className="text-[10px] font-mono bg-slate-950 text-sky-400 px-1.5 py-0.5 rounded border border-slate-800">
                                    {r}
                                  </span>
                                ))}
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      );
                    })}
                  </div>

                  {/* Scenario Detail Modal / Drawer */}
                  {selectedScenario && (
                    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
                        <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <Badge variant="outline" className="text-xs font-mono font-bold bg-slate-950 text-sky-400 border-slate-800">
                                {selectedScenario.scenario_id}
                              </Badge>
                              <Badge
                                variant="outline"
                                className={`text-xs font-mono font-bold ${
                                  selectedScenario.classification === "TP"
                                    ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                                    : selectedScenario.classification === "TN"
                                    ? "bg-slate-950 text-slate-400 border-slate-800"
                                    : "bg-amber-950 text-amber-400 border-amber-800"
                                }`}
                              >
                                {selectedScenario.classification}
                              </Badge>
                              <span className="text-xs text-slate-400 font-mono">Split: {selectedScenario.split}</span>
                            </div>
                            <h3 className="text-base font-bold text-slate-100">{selectedScenario.name}</h3>
                          </div>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-slate-400 hover:text-white"
                            onClick={() => setSelectedScenario(null)}
                          >
                            ✕
                          </Button>
                        </div>

                        <div className="space-y-3 text-xs font-mono">
                          <div className="p-3 bg-slate-950 rounded border border-slate-800 text-slate-300">
                            {selectedScenario.notes || "Evaluated against capture replay"}
                          </div>

                          <div className="grid grid-cols-2 gap-3">
                            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                              <span className="text-[10px] text-slate-500 block uppercase">Detected Status</span>
                              <span className="text-sm font-bold text-slate-200">
                                {selectedScenario.detected ? "TRUE (Caught)" : "FALSE (Missed)"}
                              </span>
                            </div>
                            <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                              <span className="text-[10px] text-slate-500 block uppercase">Time to Detect (TTD)</span>
                              <span className="text-sm font-bold text-sky-400">
                                {selectedScenario.time_to_detect_ms != null
                                  ? `${selectedScenario.time_to_detect_ms.toFixed(2)} ms`
                                  : "N/A"}
                              </span>
                            </div>
                          </div>

                          <div>
                            <span className="text-slate-400 block mb-1">Matched Rules:</span>
                            <div className="flex flex-wrap gap-1.5">
                              {(selectedScenario.matched_rules ?? []).length > 0 ? (
                                (selectedScenario.matched_rules ?? []).map((r) => (
                                  <Badge key={r} variant="outline" className="bg-sky-950 text-sky-300 border-sky-800 text-[11px]">
                                    {r}
                                  </Badge>
                                ))
                              ) : (
                                <span className="text-slate-500 italic">No rules matched for this scenario</span>
                              )}
                            </div>
                          </div>

                          <div>
                            <span className="text-slate-400 block mb-1">Matched Detectors:</span>
                            <div className="flex flex-wrap gap-1.5">
                              {(selectedScenario.matched_detectors ?? []).length > 0 ? (
                                (selectedScenario.matched_detectors ?? []).map((d) => (
                                  <Badge key={d} variant="outline" className="bg-slate-950 text-emerald-400 border-slate-800 text-[11px]">
                                    {d}
                                  </Badge>
                                ))
                              ) : (
                                <span className="text-slate-500 italic">None</span>
                              )}
                            </div>
                          </div>

                          {(selectedScenario.matched_signals ?? []).length > 0 && (
                            <div>
                              <span className="text-slate-400 block mb-1">Matched Signal IDs:</span>
                              <div className="p-2 bg-slate-950 rounded border border-slate-800 text-slate-400 text-[11px] max-h-24 overflow-y-auto">
                                {(selectedScenario.matched_signals ?? []).join(", ")}
                              </div>
                            </div>
                          )}
                        </div>

                        <div className="flex justify-end pt-2 border-t border-slate-800">
                          <Button
                            size="sm"
                            variant="outline"
                            className="text-xs"
                            onClick={() => setSelectedScenario(null)}
                          >
                            Close
                          </Button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* SUB-TAB 4: GAPS & FALSE NEGATIVES */}
              {phaseDSubTab === "gaps" && (
                <div className="space-y-6">
                  {/* False Negatives Section */}
                  <Card className="border-amber-900/50 bg-amber-950/10">
                    <CardHeader className="pb-3 border-b border-amber-900/40">
                      <CardTitle className="text-sm font-semibold tracking-tight text-amber-400 flex items-center justify-between">
                        <span className="flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-amber-400" />
                          Missed Attack Scenarios (False Negatives — {(activeRun.false_negatives ?? []).length})
                        </span>
                        <Badge variant="outline" className="bg-amber-950/60 text-amber-400 border-amber-800 text-[10px]">
                          HONEST REPORTING INVARIANT
                        </Badge>
                      </CardTitle>
                      <CardDescription className="text-xs text-amber-300/70">
                        In accordance with Rule 2.2, SentinelX strictly reports missed attacks without suppressing gaps or artificially inflating recall.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="p-4 space-y-4">
                      {(activeRun.false_negatives ?? []).length === 0 ? (
                        <div className="p-6 text-center text-slate-400 text-xs">
                          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                          No false negatives detected across evaluated splits.
                        </div>
                      ) : (
                        (activeRun.false_negatives ?? []).map((fn: Record<string, unknown>, i: number) => (
                          <div key={i} className="p-4 rounded-lg bg-slate-950/80 border border-amber-900/50 space-y-2">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-xs font-bold text-amber-400">
                                  {String(fn.scenario_id ?? "")}
                                </span>
                                <span className="text-xs font-semibold text-slate-200">
                                  {String(fn.name ?? "")}
                                </span>
                              </div>
                              <Badge variant="outline" className="bg-amber-950/40 text-amber-400 border-amber-800 text-[10px]">
                                {String(fn.category ?? "")}
                              </Badge>
                            </div>
                            <p className="text-xs text-slate-400 font-sans">
                              {String(fn.notes ?? "Expected attack detection was not triggered during replay.")}
                            </p>
                          </div>
                        ))
                      )}
                    </CardContent>
                  </Card>

                  {/* False Positives Section */}
                  <Card className="border-rose-900/50 bg-rose-950/10">
                    <CardHeader className="pb-3 border-b border-rose-900/40">
                      <CardTitle className="text-sm font-semibold tracking-tight text-rose-400 flex items-center justify-between">
                        <span className="flex items-center gap-2">
                          <AlertOctagon className="w-4 h-4 text-rose-400" />
                          Spurious Benign Alerts (False Positives — {(activeRun.false_positives ?? []).length})
                        </span>
                        <Badge variant="outline" className="bg-rose-950/60 text-rose-400 border-rose-800 text-[10px]">
                          FPR: {fmtPct(activeRun.headline.fpr)}
                        </Badge>
                      </CardTitle>
                      <CardDescription className="text-xs text-rose-300/70">
                        Tracks legitimate operational events that erroneously triggered alarms on benign telemetry captures.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="p-4 space-y-4">
                      {(activeRun.false_positives ?? []).length === 0 ? (
                        <div className="p-6 text-center text-slate-400 text-xs">
                          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                          Zero false positives recorded on benign baseline captures.
                        </div>
                      ) : (
                        (activeRun.false_positives ?? []).map((fp: Record<string, unknown>, i: number) => (
                          <div key={i} className="p-4 rounded-lg bg-slate-950/80 border border-rose-900/50 space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="font-mono text-xs font-bold text-rose-400">
                                {String(fp.scenario_id ?? "")}: {String(fp.name ?? "")}
                              </span>
                              <Badge variant="outline" className="bg-rose-950/40 text-rose-400 border-rose-800 text-[10px]">
                                {String(fp.category ?? "")}
                              </Badge>
                            </div>
                            <p className="text-xs text-slate-400 font-sans">
                              {String(fp.notes ?? "Unwarranted alert triggered on benign telemetry.")}
                            </p>
                          </div>
                        ))
                      )}
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* SUB-TAB 5: PERFORMANCE & LATENCY */}
              {phaseDSubTab === "performance" && (
                <div className="space-y-6">
                  {/* Latency Quantiles Table */}
                  <Card className="border-slate-800 bg-slate-900/50">
                    <CardHeader className="pb-3 border-b border-slate-800/80">
                      <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
                        <Clock className="w-4 h-4 text-emerald-400" />
                        Processing Latency Quantile Distribution (ms)
                      </CardTitle>
                      <CardDescription className="text-xs text-slate-400">
                        Explicit separation between ingestion, detector processing, correlation, and total end-to-end latency.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="p-0">
                      <table className="w-full text-xs text-left">
                        <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                          <tr>
                            <th className="p-3 pl-4">Latency Stage</th>
                            <th className="p-3">P50 (Median)</th>
                            <th className="p-3">P90</th>
                            <th className="p-3">P95</th>
                            <th className="p-3">P99</th>
                            <th className="p-3">Min</th>
                            <th className="p-3">Mean</th>
                            <th className="p-3 pr-4 text-right">Max</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono">
                          <tr className="hover:bg-slate-800/30">
                            <td className="p-3 pl-4 font-sans font-medium text-slate-200">
                              Detector Processing (L_detect)
                            </td>
                            <td className="p-3 text-sky-400">{activeRun.latency.detector_latency.p50} ms</td>
                            <td className="p-3 text-slate-300">{activeRun.latency.detector_latency.p90} ms</td>
                            <td className="p-3 text-emerald-400">{activeRun.latency.detector_latency.p95} ms</td>
                            <td className="p-3 text-slate-300">{activeRun.latency.detector_latency.p99} ms</td>
                            <td className="p-3 text-slate-500">{activeRun.latency.detector_latency.min_ms} ms</td>
                            <td className="p-3 text-slate-400">{activeRun.latency.detector_latency.mean_ms} ms</td>
                            <td className="p-3 pr-4 text-right text-slate-300">{activeRun.latency.detector_latency.max_ms} ms</td>
                          </tr>

                          <tr className="hover:bg-slate-800/30">
                            <td className="p-3 pl-4 font-sans font-medium text-slate-200">
                              Incident Correlation (L_corr)
                            </td>
                            <td className="p-3 text-sky-400">{activeRun.latency.correlator_latency.p50} ms</td>
                            <td className="p-3 text-slate-300">{activeRun.latency.correlator_latency.p90} ms</td>
                            <td className="p-3 text-emerald-400">{activeRun.latency.correlator_latency.p95} ms</td>
                            <td className="p-3 text-slate-300">{activeRun.latency.correlator_latency.p99} ms</td>
                            <td className="p-3 text-slate-500">{activeRun.latency.correlator_latency.min_ms} ms</td>
                            <td className="p-3 text-slate-400">{activeRun.latency.correlator_latency.mean_ms} ms</td>
                            <td className="p-3 pr-4 text-right text-slate-300">{activeRun.latency.correlator_latency.max_ms} ms</td>
                          </tr>

                          <tr className="hover:bg-slate-800/30">
                            <td className="p-3 pl-4 font-sans font-medium text-slate-200">
                              End-to-End Pipeline (L_e2e)
                            </td>
                            <td className="p-3 font-bold text-sky-400">{activeRun.latency.end_to_end_latency.p50} ms</td>
                            <td className="p-3 text-slate-300">{activeRun.latency.end_to_end_latency.p90} ms</td>
                            <td className="p-3 font-bold text-emerald-400">{activeRun.latency.end_to_end_latency.p95} ms</td>
                            <td className="p-3 text-slate-300">{activeRun.latency.end_to_end_latency.p99} ms</td>
                            <td className="p-3 text-slate-500">{activeRun.latency.end_to_end_latency.min_ms} ms</td>
                            <td className="p-3 text-slate-400">{activeRun.latency.end_to_end_latency.mean_ms} ms</td>
                            <td className="p-3 pr-4 text-right text-slate-300">{activeRun.latency.end_to_end_latency.max_ms} ms</td>
                          </tr>

                          <tr className="hover:bg-slate-800/30">
                            <td className="p-3 pl-4 font-sans font-medium text-slate-200">
                              Time to Detect (TTD)
                            </td>
                            <td className="p-3 text-purple-400">{activeRun.latency.time_to_detect.p50} ms</td>
                            <td className="p-3 text-slate-300">{activeRun.latency.time_to_detect.p90} ms</td>
                            <td className="p-3 text-purple-400">{activeRun.latency.time_to_detect.p95} ms</td>
                            <td className="p-3 text-slate-300">{activeRun.latency.time_to_detect.p99} ms</td>
                            <td className="p-3 text-slate-500">{activeRun.latency.time_to_detect.min_ms} ms</td>
                            <td className="p-3 text-slate-400">{activeRun.latency.time_to_detect.mean_ms} ms</td>
                            <td className="p-3 pr-4 text-right text-slate-300">{activeRun.latency.time_to_detect.max_ms} ms</td>
                          </tr>
                        </tbody>
                      </table>
                    </CardContent>
                  </Card>

                  {/* Benchmark CLI Instructions */}
                  <Card className="border-slate-800 bg-slate-950/70">
                    <CardHeader className="pb-3 border-b border-slate-800/80">
                      <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
                        <Terminal className="w-4 h-4 text-sky-400" />
                        Run Telemetry Load Benchmark
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="pt-4 space-y-3 font-mono text-xs">
                      <p className="text-slate-400 font-sans">
                        Execute controlled load tests across normal, moderate, high, burst, and sustained workloads:
                      </p>
                      <div className="space-y-1.5 text-sky-300 select-all">
                        <div className="p-2.5 rounded bg-black/60 border border-slate-800">
                          make eval-benchmark WORKLOAD=normal
                        </div>
                        <div className="p-2.5 rounded bg-black/60 border border-slate-800 text-amber-300">
                          uv run python scripts/eval_load_benchmark.py --workload burst
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* SUB-TAB 6: RUN HISTORY & COMPARISON */}
              {phaseDSubTab === "history" && (
                <div className="space-y-6">
                  {/* Historical Runs List */}
                  <Card className="border-slate-800 bg-slate-900/50">
                    <CardHeader className="pb-3 border-b border-slate-800/80">
                      <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
                        <History className="w-4 h-4 text-purple-400" />
                        Historical Evaluation Runs ({evalRuns.length})
                      </CardTitle>
                      <CardDescription className="text-xs text-slate-400">
                        Select a past run to inspect its detailed evaluation report or compare regressions against another run.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="p-0">
                      <table className="w-full text-xs text-left">
                        <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                          <tr>
                            <th className="p-3 pl-4">Run ID</th>
                            <th className="p-3">Timestamp</th>
                            <th className="p-3">Git Commit</th>
                            <th className="p-3">Dataset</th>
                            <th className="p-3 text-right">Precision</th>
                            <th className="p-3 text-right">Recall</th>
                            <th className="p-3 text-right">F1 Score</th>
                            <th className="p-3 pr-4 text-right">Throughput</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono">
                          {evalRuns.map((r) => (
                            <tr
                              key={r.run_id}
                              onClick={() => setSelectedRunId(r.run_id)}
                              className={`cursor-pointer transition-all hover:bg-slate-800/40 ${
                                currentRunId === r.run_id ? "bg-slate-800/60 font-semibold" : ""
                              }`}
                            >
                              <td className="p-3 pl-4 text-sky-400">{r.run_id}</td>
                              <td className="p-3 text-slate-400">{new Date(r.created_at).toLocaleString()}</td>
                              <td className="p-3 text-slate-300">{r.git_commit}</td>
                              <td className="p-3 text-slate-400">v{r.dataset_version}</td>
                              <td className="p-3 text-right text-emerald-400">
                                {r.headline.precision !== null ? `${(r.headline.precision * 100).toFixed(1)}%` : "N/A"}
                              </td>
                              <td className="p-3 text-right text-sky-400">
                                {r.headline.recall !== null ? `${(r.headline.recall * 100).toFixed(1)}%` : "N/A"}
                              </td>
                              <td className="p-3 text-right font-bold text-purple-400">
                                {r.headline.f1_score !== null ? r.headline.f1_score.toFixed(3) : "N/A"}
                              </td>
                              <td className="p-3 pr-4 text-right text-slate-300">{r.throughput_eps} EPS</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </CardContent>
                  </Card>

                  {/* Run Comparison Diff Tool */}
                  <Card className="border-slate-800 bg-slate-900/50">
                    <CardHeader className="pb-3 border-b border-slate-800/80">
                      <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
                        <Activity className="w-4 h-4 text-sky-400" />
                        Evaluation Run Differential Analysis
                      </CardTitle>
                      <CardDescription className="text-xs text-slate-400">
                        Compare two historical evaluation runs side-by-side to detect quality improvements or regressions.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="p-4 space-y-4">
                      <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
                        <div className="flex items-center gap-2">
                          <span className="text-slate-400 font-sans">Baseline Run (A):</span>
                          <select
                            className="bg-slate-950 border border-slate-800 text-slate-200 rounded px-2.5 py-1.5"
                            value={compareRunAId}
                            onChange={(e) => setCompareRunAId(e.target.value)}
                          >
                            <option value="">Select Run A...</option>
                            {evalRuns.map((r) => (
                              <option key={r.run_id} value={r.run_id}>
                                {r.run_id} (F1: {r.headline.f1_score ?? "N/A"})
                              </option>
                            ))}
                          </select>
                        </div>

                        <ArrowRight className="w-4 h-4 text-slate-500" />

                        <div className="flex items-center gap-2">
                          <span className="text-slate-400 font-sans">Candidate Run (B):</span>
                          <select
                            className="bg-slate-950 border border-slate-800 text-slate-200 rounded px-2.5 py-1.5"
                            value={compareRunBId}
                            onChange={(e) => setCompareRunBId(e.target.value)}
                          >
                            <option value="">Select Run B...</option>
                            {evalRuns.map((r) => (
                              <option key={r.run_id} value={r.run_id}>
                                {r.run_id} (F1: {r.headline.f1_score ?? "N/A"})
                              </option>
                            ))}
                          </select>
                        </div>
                      </div>

                      {runA && runB && (
                        <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-3">
                          <div className="grid grid-cols-4 gap-3 text-center border-b border-slate-800 pb-3">
                            <div>
                              <span className="text-[10px] text-slate-500 block uppercase">Metric</span>
                              <span className="text-xs font-bold text-slate-300">Precision</span>
                            </div>
                            <div>
                              <span className="text-[10px] text-slate-500 block uppercase">Run A</span>
                              <span className="text-xs text-slate-200">
                                {fmtPct(runA.headline.precision)}
                              </span>
                            </div>
                            <div>
                              <span className="text-[10px] text-slate-500 block uppercase">Run B</span>
                              <span className="text-xs text-slate-200">
                                {fmtPct(runB.headline.precision)}
                              </span>
                            </div>
                            <div>
                              <span className="text-[10px] text-slate-500 block uppercase">Delta</span>
                              <span className="text-xs font-bold text-emerald-400">
                                {typeof runA.headline.precision === "number" && typeof runB.headline.precision === "number"
                                  ? fmtPct(runB.headline.precision - runA.headline.precision)
                                  : "—"}
                              </span>
                            </div>
                          </div>

                          <div className="grid grid-cols-4 gap-3 text-center border-b border-slate-800 pb-3">
                            <div>
                              <span className="text-xs font-bold text-slate-300">Recall</span>
                            </div>
                            <div>
                              <span className="text-xs text-slate-200">
                                {fmtPct(runA.headline.recall)}
                              </span>
                            </div>
                            <div>
                              <span className="text-xs text-slate-200">
                                {fmtPct(runB.headline.recall)}
                              </span>
                            </div>
                            <div>
                              <span className="text-xs font-bold text-sky-400">
                                {typeof runA.headline.recall === "number" && typeof runB.headline.recall === "number"
                                  ? fmtPct(runB.headline.recall - runA.headline.recall)
                                  : "—"}
                              </span>
                            </div>
                          </div>

                          <div className="grid grid-cols-4 gap-3 text-center">
                            <div>
                              <span className="text-xs font-bold text-slate-300">F1 Score</span>
                            </div>
                            <div>
                              <span className="text-xs text-slate-200">
                                {fmtScore(runA.headline.f1_score)}
                              </span>
                            </div>
                            <div>
                              <span className="text-xs text-slate-200">
                                {fmtScore(runB.headline.f1_score)}
                              </span>
                            </div>
                            <div>
                              <span className="text-xs font-bold text-purple-400">
                                {typeof runA.headline.f1_score === "number" && typeof runB.headline.f1_score === "number"
                                  ? fmtScore(runB.headline.f1_score - runA.headline.f1_score)
                                  : "—"}
                              </span>
                            </div>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ===================================================================== */}
      {/* PHASE 7 LEGACY ABLATION & LOO SCORECARD (PRESERVED)                   */}
      {/* ===================================================================== */}
      {activeMainTab === "legacy" && (
        <div className="space-y-6">
          <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
            <CardHeader className="pb-3 border-b border-slate-800/80">
              <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
                <Layers className="w-4 h-4 text-purple-400" />
                Phase 7 Ablation Study &amp; Leave-One-Out Matrix
              </CardTitle>
              <CardDescription className="text-xs text-slate-400">
                Evaluation across drop-one detector configurations and Leave-One-Out (LOO) cross-validation folds.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-4 space-y-4">
              <p className="text-xs text-slate-300">
                Ablation and LOO benchmarks demonstrate zero false positives across 5-day benign captures while preserving 100% incident recall across complex IT/OT attacks.
              </p>
              <div className="p-3 rounded bg-black/60 border border-slate-800 font-mono text-xs text-purple-300">
                make ablation &amp;&amp; make metrics
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
