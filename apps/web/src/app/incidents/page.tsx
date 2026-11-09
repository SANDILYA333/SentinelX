"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import type { IncidentSummaryResponse, Signal, Technique } from "@contracts/index";
import {
  fetchIncidentById,
  fetchIncidentSummary,
  fetchMitreTechniques,
  generateIncidentSummary,
  type IncidentWithEvidence,
} from "@/lib/api";
import { useEventStream } from "@/hooks/useEventStream";
import { useEventStore } from "@/lib/store";
import { useEvidenceDrawer } from "@/components/evidence-drawer";
import {
  getDetectorStyle,
  getSeverityStyle,
  sortKillChainStages,
  STAGE_META,
} from "@/lib/theme";
import { EvidenceLink } from "@/components/evidence-link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  GitGraph,
  Loader2,
  RefreshCw,
  Search,
  Server,
  Shield,
  Sparkles,
  User,
} from "lucide-react";
import { cn } from "@/lib/utils";

function IncidentsContent() {
  useEventStream();
  const searchParams = useSearchParams();
  const initialId = searchParams.get("id");

  const { incidents, status, presenterMode } = useEventStore();
  const { openEvidence } = useEvidenceDrawer();
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(initialId);
  const [incidentDetail, setIncidentDetail] = useState<IncidentWithEvidence | null>(null);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>("");

  // LLM / Template Analyst Summary state
  const [summary, setSummary] = useState<IncidentSummaryResponse | null>(null);
  const [summaryStatus, setSummaryStatus] = useState<"none" | "generating" | "llm" | "template" | "error">("none");
  const [summaryError, setSummaryError] = useState<string | null>(null);

  // MITRE Techniques catalog
  const { data: mitreTechniques } = useQuery({
    queryKey: ["mitreTechniques"],
    queryFn: fetchMitreTechniques,
    staleTime: 60000,
  });

  const mitreMap = useMemo(() => {
    const map = new Map<string, Technique>();
    if (mitreTechniques) {
      for (const t of mitreTechniques) {
        map.set(t.technique_id.toUpperCase(), t);
      }
    }
    return map;
  }, [mitreTechniques]);

  // Sync initial query param ID
  useEffect(() => {
    if (initialId && !selectedIncidentId) {
      setSelectedIncidentId(initialId);
    }
  }, [initialId, selectedIncidentId]);

  // Load incident detail when selection changes
  useEffect(() => {
    if (!selectedIncidentId) {
      setIncidentDetail(null);
      return;
    }

    let active = true;
    setLoadingDetail(true);

    fetchIncidentById(selectedIncidentId)
      .then((detail) => {
        if (active) {
          setIncidentDetail(detail);
        }
      })
      .catch((err) => {
        console.error("Failed to load incident detail:", err);
      })
      .finally(() => {
        if (active) {
          setLoadingDetail(false);
        }
      });

    return () => {
      active = false;
    };
  }, [selectedIncidentId]);

  // Fetch summary whenever selected incident changes
  useEffect(() => {
    if (!selectedIncidentId) {
      setSummary(null);
      setSummaryStatus("none");
      setSummaryError(null);
      return;
    }

    let active = true;
    setSummary(null);
    setSummaryStatus("none");
    setSummaryError(null);

    fetchIncidentSummary(selectedIncidentId)
      .then((data) => {
        if (active) {
          setSummary(data);
          setSummaryStatus(data.mode === "llm" ? "llm" : "template");
        }
      })
      .catch(() => {
        // 404 is normal before summary generation
        if (active) {
          setSummary(null);
          setSummaryStatus("none");
        }
      });

    return () => {
      active = false;
    };
  }, [selectedIncidentId]);

  const handleGenerateSummary = async (refresh: boolean = false) => {
    if (!selectedIncidentId) return;
    setSummaryStatus("generating");
    setSummaryError(null);
    try {
      const data = await generateIncidentSummary(selectedIncidentId, refresh);
      setSummary(data);
      setSummaryStatus(data.mode === "llm" ? "llm" : "template");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to generate summary";
      setSummaryError(msg);
      setSummaryStatus("error");
    }
  };

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      const idMatch = inc.incident_id.toLowerCase().includes(q);
      const sevMatch = inc.severity.toLowerCase().includes(q);
      const entityMatch = inc.entities.some((e) => e.value.toLowerCase().includes(q));
      const stageMatch = inc.kill_chain_stages.some((s) => s.toLowerCase().includes(q));
      return idMatch || sevMatch || entityMatch || stageMatch;
    });
  }, [incidents, searchQuery]);

  // Group signals by detector type for "Why Flagged" panel
  const signalsByDetector = useMemo(() => {
    const groups: Record<string, Signal[]> = {
      rule: [],
      deception: [],
      graph: [],
      anomaly: [],
      baseline: [],
    };
    if (incidentDetail?.signals) {
      for (const sig of incidentDetail.signals) {
        const det = sig.detector in groups ? sig.detector : "rule";
        groups[det].push(sig);
      }
    }
    return groups;
  }, [incidentDetail]);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto w-full">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <AlertTriangle className="w-6 h-6 text-red-400" />
            Correlated Security Incidents
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Multi-stage attack campaign progression, MITRE ATT&amp;CK matrix correlation, and TTFMA metrics.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Badge
            variant="outline"
            className={cn(
              "px-3 py-1 font-mono text-xs",
              status === "open"
                ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/60"
                : "bg-amber-950/60 text-amber-400 border-amber-800/60"
            )}
          >
            {status === "open" ? "Live Correlation" : "Connecting..."}
          </Badge>
          <Badge variant="outline" className="bg-slate-900 border-slate-800 text-slate-300 font-mono text-xs">
            {incidents.length} Total ({incidents.filter((i) => i.score >= 0.50).length} Active)
          </Badge>
        </div>
      </div>

      {/* Main Grid: Left Column (Incident List) / Right Column (Incident Detail) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Incidents List */}
        <div className="lg:col-span-5 space-y-3">
          {/* Search box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search incidents by entity, stage, ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 focus:outline-hidden focus:border-blue-500"
            />
          </div>

          <div className="space-y-3">
            {filteredIncidents.length === 0 ? (
              <Card className="border-slate-800 bg-slate-900/40 p-8 text-center space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto opacity-60" />
                <h4 className="text-sm font-semibold text-slate-300">Zero Incidents Match</h4>
                <p className="text-xs text-slate-500">
                  {incidents.length === 0
                    ? "No multi-stage attack incidents have been correlated yet. All telemetry within baseline."
                    : "No incidents matched your search filter."}
                </p>
              </Card>
            ) : (
              filteredIncidents.map((inc) => {
                const isSelected = inc.incident_id === selectedIncidentId;
                const sevStyle = getSeverityStyle(inc.severity);
                const userEnt = inc.entities.find((e) => e.type === "user")?.value;
                const hostEnt = inc.entities.find((e) => e.type === "host")?.value;

                return (
                  <div
                    key={inc.incident_id}
                    onClick={() => setSelectedIncidentId(inc.incident_id)}
                    className={cn(
                      "p-4 rounded-xl border transition-all cursor-pointer space-y-3",
                      isSelected
                        ? "bg-slate-900/90 border-blue-500/80 shadow-lg shadow-blue-950/30"
                        : "bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60"
                    )}
                  >
                    {/* Top Row: Severity, ID, Score, TTFMA */}
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={cn("text-[10px] font-mono uppercase", sevStyle.badge)}>
                          {inc.severity}
                        </Badge>
                        <span className="font-mono text-xs font-bold text-slate-200">
                          {inc.incident_id}
                        </span>
                        {inc.novelty_only && (
                          <Badge variant="outline" className="bg-amber-950/60 text-amber-300 border-amber-600/40 text-[10px] font-mono">
                            novelty-only, score capped
                          </Badge>
                        )}
                      </div>

                      <div className="flex items-center gap-2 text-xs font-mono">
                        {inc.ttfma_seconds != null && (
                          <span className="text-emerald-400 text-[11px]">
                            TTFMA: <strong>{inc.ttfma_seconds.toFixed(1)}s</strong>
                          </span>
                        )}
                        <span className="text-slate-300 font-bold">
                          {(inc.score * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>

                    {/* Score Bar */}
                    <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                      <div
                        className={cn("h-full transition-all duration-300", sevStyle.bar)}
                        style={{ width: `${Math.min(100, inc.score * 100)}%` }}
                      />
                    </div>

                    {/* Kill Chain Stage Pills (In Logical Order) */}
                    <div className="flex flex-wrap gap-1">
                      {sortKillChainStages(inc.kill_chain_stages).map((stage) => {
                        const meta = STAGE_META[stage];
                        return (
                          <span
                            key={stage}
                            className={cn(
                              "text-[10px] px-1.5 py-0.5 rounded border font-medium",
                              meta?.badge || "bg-slate-800 text-slate-300 border-slate-700"
                            )}
                          >
                            {meta?.short || stage}
                          </span>
                        );
                      })}
                    </div>

                    {/* Bottom Metadata & Badges */}
                    <div className="flex items-center justify-between text-xs text-slate-400 font-mono pt-1 border-t border-slate-800/60 text-[11px]">
                      <div className="flex items-center gap-3">
                        {userEnt && (
                          <span className="flex items-center gap-1">
                            <User className="w-3 h-3 text-slate-500" /> {userEnt}
                          </span>
                        )}
                        {hostEnt && (
                          <span className="flex items-center gap-1">
                            <Server className="w-3 h-3 text-slate-500" /> {hostEnt}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-1.5">
                        {inc.decoy_touched && (
                          <span className="text-purple-400 text-[10px] font-semibold">
                            &bull; Decoy
                          </span>
                        )}
                        {inc.ot_touched && (
                          <span className="text-rose-400 text-[10px] font-semibold">
                            &bull; OT
                          </span>
                        )}
                        <span className="text-slate-500">
                          {inc.signal_ids.length} sigs
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Detailed Incident Drilldown */}
        <div className="lg:col-span-7">
          {loadingDetail && (
            <Card className="border-slate-800 bg-slate-900/40 p-12 text-center text-slate-400 space-y-3">
              <div className="w-8 h-8 border-2 border-slate-700 border-t-blue-500 rounded-full animate-spin mx-auto" />
              <p className="text-xs font-mono">Loading incident evidence &amp; signals...</p>
            </Card>
          )}

          {!loadingDetail && incidentDetail && (
            <div className="space-y-6">
              {/* Incident Header Card */}
              <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
                <CardHeader className="pb-3 border-b border-slate-800/80">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={getSeverityStyle(incidentDetail.severity).badge}>
                          {incidentDetail.severity.toUpperCase()} SEVERITY
                        </Badge>
                        <CardTitle className="text-base font-bold font-mono text-slate-100">
                          {incidentDetail.incident_id}
                        </CardTitle>
                        {incidentDetail.novelty_only && (
                          <Badge variant="outline" className="bg-amber-950/60 text-amber-300 border-amber-600/40 text-xs font-mono">
                            novelty-only, score capped
                          </Badge>
                        )}
                      </div>
                      <CardDescription className="text-xs text-slate-400 mt-1">
                        First signal {new Date(incidentDetail.first_signal_ts || incidentDetail.created_at).toISOString()} &bull; Updated {new Date(incidentDetail.updated_at).toISOString()}
                      </CardDescription>
                    </div>

                    <div className="flex items-center gap-2">
                      <Link
                        href={`/graph?incident_id=${encodeURIComponent(incidentDetail.incident_id)}`}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 border border-blue-500/40 text-xs font-medium transition"
                      >
                        <GitGraph className="w-3.5 h-3.5" />
                        <span>Interactive Attack Graph</span>
                        <ArrowRight className="w-3 h-3" />
                      </Link>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="pt-4 space-y-4">
                  {/* Summary Metric Strip */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 uppercase font-mono block">Progression Score</span>
                      <span className="text-lg font-bold font-mono text-slate-100">
                        {incidentDetail.score.toFixed(2)}
                      </span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 uppercase font-mono block">TTFMA Latency</span>
                      <span className="text-lg font-bold font-mono text-emerald-400">
                        {incidentDetail.ttfma_seconds != null ? `${incidentDetail.ttfma_seconds.toFixed(2)}s` : "N/A"}
                      </span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 uppercase font-mono block">Contributing Signals</span>
                      <span className="text-lg font-bold font-mono text-purple-300">
                        {incidentDetail.signal_ids.length}
                      </span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 uppercase font-mono block">Evidence Telemetry</span>
                      <span className="text-lg font-bold font-mono text-sky-300">
                        {incidentDetail.event_ids.length} evts
                      </span>
                    </div>
                  </div>

                  {/* MITRE ATT&CK & ICS Techniques Rollup */}
                  {incidentDetail.techniques && incidentDetail.techniques.length > 0 && (
                    <div className="space-y-2 pt-2 border-t border-slate-800/80">
                      <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5 text-blue-400" />
                        Correlated ATT&amp;CK / ATT&amp;CK-ICS Techniques ({incidentDetail.techniques.length})
                      </span>

                      <div className="flex flex-wrap gap-1.5">
                        {incidentDetail.techniques.map((t) => {
                          const catalogInfo = mitreMap.get(t.technique_id.toUpperCase());
                          const techName = catalogInfo?.name || t.name;
                          const techTactic = catalogInfo?.tactic || t.tactic;

                          return (
                            <div
                              key={t.technique_id}
                              className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-xs font-mono flex items-center gap-1.5 text-slate-200"
                              title={`${t.technique_id}: ${techName} (${techTactic})`}
                            >
                              <span className="text-blue-400 font-bold">{t.technique_id}</span>
                              <span className="text-slate-400 text-[11px] truncate max-w-[180px]">
                                {techName}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Analyst Summary Card */}
              <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
                <CardHeader className="pb-3 border-b border-slate-800/80">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <Sparkles className="w-4 h-4 text-purple-400" />
                        <CardTitle className="text-sm font-semibold tracking-tight text-slate-100">
                          Analyst Summary
                        </CardTitle>
                        {summaryStatus === "llm" && summary && (
                          <Badge variant="outline" className="bg-purple-950/60 text-purple-300 border-purple-600/40 text-[10px] font-mono">
                            LLM ({summary.verified_count}/{summary.total_count} verified{summary.dropped_count > 0 ? `, ${summary.dropped_count} dropped` : ""})
                          </Badge>
                        )}
                        {summaryStatus === "template" && (
                          <Badge variant="outline" className="bg-slate-800 text-slate-300 border-slate-700 text-[10px] font-mono">
                            Deterministic Fallback (LLM unavailable)
                          </Badge>
                        )}
                        {summary?.is_stale && (
                          <Badge variant="outline" className="bg-amber-950/60 text-amber-300 border-amber-600/50 text-[10px] font-mono">
                            stale - regenerate
                          </Badge>
                        )}
                        {summaryStatus === "error" && (
                          <Badge variant="outline" className="bg-rose-950/60 text-rose-300 border-rose-600/40 text-[10px] font-mono">
                            Error
                          </Badge>
                        )}
                      </div>
                      <CardDescription className="text-xs text-slate-400">
                        {summary
                          ? `Model: ${summary.model} • covers ${summary.events_covered ?? (summary.claims ?? []).reduce((acc, c) => acc + (c.event_ids?.length || 0), 0)} of ${summary.total_events ?? incidentDetail?.event_ids?.length ?? "—"} current events • cached, generated ${new Date(summary.generated_at).toLocaleTimeString()}`
                          : "Grounded incident synthesis with strict citation verification"}
                      </CardDescription>
                    </div>

                    <div className="flex items-center gap-2">
                      {(summaryStatus === "none" || summaryStatus === "generating") && (
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={summaryStatus === "generating"}
                          onClick={() => handleGenerateSummary(false)}
                          className="h-8 text-xs font-mono bg-purple-950/40 text-purple-300 border-purple-700/60 hover:bg-purple-900/60 hover:text-purple-200"
                        >
                          {summaryStatus === "generating" ? (
                            <>
                              <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                              Generating summary...
                            </>
                          ) : (
                            <>
                              <Sparkles className="w-3.5 h-3.5 mr-1.5" />
                              Generate summary (~5-10s)
                            </>
                          )}
                        </Button>
                      )}
                      {(summaryStatus === "llm" || summaryStatus === "template" || summaryStatus === "error") && !presenterMode && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleGenerateSummary(true)}
                          className="h-8 text-xs font-mono bg-slate-900 border-slate-700 text-slate-300 hover:text-white hover:bg-slate-800"
                        >
                          <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
                          Regenerate
                        </Button>
                      )}
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="pt-4 space-y-4">
                  {summaryStatus === "generating" && (
                    <div className="py-8 text-center space-y-3">
                      <div className="w-6 h-6 border-2 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto" />
                      <p className="text-xs text-slate-400 font-mono">
                        Extracting bounded evidence packet and verifying citations...
                      </p>
                    </div>
                  )}

                  {summaryStatus === "none" && (
                    <div className="py-6 text-center space-y-2">
                      <p className="text-xs text-slate-400 font-mono">
                        No summary generated for this incident yet.
                      </p>
                      <p className="text-[11px] text-slate-500 max-w-md mx-auto">
                        Generates a structured incident briefing. Citations are strictly verified against normalized telemetry.
                      </p>
                    </div>
                  )}

                  {summaryStatus === "error" && (
                    <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300 font-mono flex items-center justify-between">
                      <span>{summaryError || "Failed to generate summary."}</span>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleGenerateSummary(false)}
                        className="h-7 text-xs font-mono bg-rose-900/60 border-rose-700 text-rose-200 hover:bg-rose-800"
                      >
                        Retry
                      </Button>
                    </div>
                  )}

                  {(summaryStatus === "llm" || summaryStatus === "template") && summary && (
                    <div className="space-y-3">
                      {/* Plain text headline */}
                      <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
                        <p className="text-xs font-bold font-mono text-slate-100">
                          {summary.headline}
                        </p>
                      </div>

                      {/* Verified / Deterministic Claims */}
                      <div className="space-y-2">
                        {(summary.claims ?? []).map((claim, idx) => (
                          <div
                            key={idx}
                            className="p-3 rounded-lg bg-slate-950/50 border border-slate-800/60 space-y-2"
                          >
                            <div className="flex items-start justify-between gap-2">
                              {/* Plain text claim text - no dangerouslySetInnerHTML */}
                              <p className="text-xs text-slate-300 font-mono leading-relaxed">
                                {claim.text}
                              </p>
                              {claim.deterministic ? (
                                <Badge variant="outline" className="shrink-0 bg-slate-800 text-slate-400 border-slate-700 text-[9px] font-mono">
                                  deterministic
                                </Badge>
                              ) : claim.verified ? (
                                <Badge variant="outline" className="shrink-0 bg-emerald-950/60 text-emerald-300 border-emerald-800/40 text-[9px] font-mono">
                                  grounding verified
                                </Badge>
                              ) : null}
                            </div>

                            {/* Evidence Chips */}
                            <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-800/40 text-[10px] font-mono">
                              <span className="text-slate-500">Citations:</span>
                              {(claim.event_ids ?? []).map((eid) => (
                                <button
                                  key={eid}
                                  type="button"
                                  onClick={() => openEvidence(eid)}
                                  className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 hover:border-blue-500 hover:text-blue-300 text-slate-300 transition cursor-pointer"
                                  title={`Inspect event ${eid}`}
                                >
                                  {eid.length > 12 ? `${eid.slice(0, 4)}...${eid.slice(-4)}` : eid}
                                </button>
                              ))}

                              {(claim.technique_ids ?? []).map((tid) => (
                                <span
                                  key={tid}
                                  className="px-1.5 py-0.5 rounded bg-blue-950/60 border border-blue-800/50 text-blue-300"
                                >
                                  {tid}
                                </span>
                              ))}

                              {(claim.entities ?? []).map((ent) => (
                                <span
                                  key={ent}
                                  className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400"
                                >
                                  {ent}
                                </span>
                              ))}
                            </div>

                            {/* Cited Telemetry Context */}
                            {claim.event_ids && claim.event_ids.length > 0 && incidentDetail?.evidence_events && (
                              <div className="space-y-1 pt-1.5 border-t border-slate-800/30 text-[11px] font-mono">
                                {claim.event_ids.map((eid) => {
                                  const ev = incidentDetail.evidence_events.find((e) => e.event_id === eid);
                                  if (!ev) return null;
                                  const snippet = ev.cmdline || ev.action || "telemetry event";
                                  return (
                                    <div key={eid} className="text-slate-400 flex items-start gap-1.5 pl-1.5 border-l border-slate-700">
                                      <span className="text-slate-500 font-semibold">{ev.host || ev.source_tool}:</span>
                                      <span className="truncate text-slate-300" title={snippet}>{snippet}</span>
                                    </div>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>

                      {/* Verifier Notice Footer */}
                      <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-2 border-t border-slate-800/60">
                        <span>grounding verified by code, not semantics</span>
                        <span>strictly advisory &bull; no automated containment</span>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Chronological Attack Narrative Timeline */}
              <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
                <CardHeader className="pb-3 border-b border-slate-800/80">
                  <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
                    <Clock className="w-4 h-4 text-emerald-400" />
                    Attack Progression Narrative Timeline
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400">
                    Step-by-step kill-chain evolution derived directly from correlation engine narrative
                  </CardDescription>
                </CardHeader>

                <CardContent className="pt-4">
                  {incidentDetail.explanation && incidentDetail.explanation.length > 0 ? (
                    <div className="space-y-3 relative before:absolute before:inset-0 before:left-3 before:w-0.5 before:bg-slate-800">
                      {incidentDetail.explanation.map((line, idx) => {
                        // Find potential signal / rule id match in line (e.g. RULE-AUTH-001)
                        const ruleMatch = line.match(/\((RULE-[A-Z0-9-]+|GRAPH-[A-Z0-9-]+|BASE-[A-Z0-9-]+|ANOM-[A-Z0-9-]+)\)/);
                        const matchedRule = ruleMatch ? ruleMatch[1] : null;

                        return (
                          <div key={idx} className="relative flex items-start gap-4 pl-7 text-xs">
                            <span className="absolute left-1.5 top-1.5 w-3.5 h-3.5 rounded-full border-2 border-slate-950 bg-blue-500 shadow-xs" />
                            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 flex-1 space-y-1.5">
                              <p className="text-slate-200 leading-relaxed font-mono text-[11px]">
                                {line}
                              </p>

                              {matchedRule && (
                                <div className="flex items-center gap-2 pt-1 border-t border-slate-800/60 text-[10px]">
                                  <span className="text-slate-500">Evidence Citation:</span>
                                  <Badge variant="outline" className="bg-slate-900 border-slate-700 text-purple-300 font-mono py-0">
                                    {matchedRule}
                                  </Badge>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 py-4 font-mono">
                      No narrative explanation entries generated.
                    </p>
                  )}
                </CardContent>
              </Card>

              {/* "Why Flagged" Panel (Grouped by Detector) */}
              <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
                <CardHeader className="pb-3 border-b border-slate-800/80">
                  <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-purple-400" />
                    Why Flagged: Contributing Detection Signals
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400">
                    Independent detector signals linked to this incident with underlying evidence events
                  </CardDescription>
                </CardHeader>

                <CardContent className="pt-4 space-y-4">
                  {Object.entries(signalsByDetector).map(([detector, sigs]) => {
                    if (sigs.length === 0) return null;
                    const detStyle = getDetectorStyle(detector);

                    return (
                      <div key={detector} className="space-y-2">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={cn("text-xs uppercase font-mono", detStyle.badge)}>
                            {detector} ({sigs.length})
                          </Badge>
                        </div>

                        <div className="space-y-2">
                          {sigs.map((sig) => (
                            <div
                              key={sig.signal_id}
                              className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-2"
                            >
                              <div className="flex items-center justify-between text-xs">
                                <span className="font-semibold text-slate-200">
                                  {sig.title}
                                </span>
                                <span className="font-mono text-[11px] text-purple-300">
                                  {sig.rule_id}
                                </span>
                              </div>

                              <p className="text-[11px] text-slate-400 font-mono leading-relaxed">
                                {sig.explanation}
                              </p>

                              <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-800/60 text-[10px] font-mono">
                                <div className="flex items-center gap-2">
                                  <span className="text-slate-500">
                                    Conf: <strong className="text-slate-300">{(sig.confidence * 100).toFixed(0)}%</strong>
                                  </span>
                                  <span className="text-slate-500">
                                    Score: <strong className="text-slate-300">{sig.score.toFixed(2)}</strong>
                                  </span>
                                </div>

                                {/* Clickable evidence event links */}
                                <div className="flex items-center gap-1">
                                  <span className="text-slate-500 mr-1">Events:</span>
                                  {sig.evidence_event_ids.map((eid) => (
                                    <EvidenceLink key={eid} id={eid} label={eid.slice(-8)} />
                                  ))}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </CardContent>
              </Card>
            </div>
          )}

          {!loadingDetail && !incidentDetail && (
            <Card className="border-slate-800 bg-slate-900/40 p-16 text-center space-y-3">
              <AlertTriangle className="w-10 h-10 text-slate-600 mx-auto" />
              <h3 className="text-base font-semibold text-slate-300">No Incident Selected</h3>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                Select an incident from the list on the left to inspect its chronological narrative timeline, contributing detection signals, and ATT&amp;CK mappings.
              </p>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

export default function IncidentsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-slate-400 font-mono text-xs">Loading incident feed...</div>}>
      <IncidentsContent />
    </Suspense>
  );
}
