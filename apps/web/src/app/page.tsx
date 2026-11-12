"use client";

import * as React from "react";
import Link from "next/link";
import type { SourceHealth } from "@contracts/index";
import { useQuery } from "@tanstack/react-query";
import { emitTestEvent, fetchSourcesHealth, fetchStats } from "@/lib/api";
import { useEventStream } from "@/hooks/useEventStream";
import { useEventStore } from "@/lib/store";
import { getDetectorStyle, getDomainStyle, getSeverityStyle } from "@/lib/theme";
import { BudgetGauge } from "@/components/budget-gauge";
import { EvidenceLink } from "@/components/evidence-link";
import { RecentIncidentCard } from "@/components/recent-incident-card";
import { ReplayStatusBar } from "@/components/replay-status-bar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { MetricCard } from "@/components/ui/metric-card";
import { StatusBadge } from "@/components/ui/status-badge";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { useToast } from "@/components/ui/toast";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Cpu,
  Eye,
  Flame,
  GitGraph,
  Search,
  Send,
  Server,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { cn } from "@/lib/utils";

const DEFAULT_TELEMETRY_SOURCES: SourceHealth[] = [
  { source_key: "wazuh", source_tool: "wazuh", relative_path: "wazuh/archives.json", status: "idle", expected_active: true, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "zeek_it_conn", source_tool: "zeek", relative_path: "zeek-it/conn.log", status: "idle", expected_active: true, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "zeek_it_dns", source_tool: "zeek", relative_path: "zeek-it/dns.log", status: "idle", expected_active: false, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "zeek_dmz_conn", source_tool: "zeek", relative_path: "zeek-dmz/conn.log", status: "idle", expected_active: false, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "zeek_dmz_dns", source_tool: "zeek", relative_path: "zeek-dmz/dns.log", status: "idle", expected_active: false, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "zeek_ot_conn", source_tool: "zeek", relative_path: "zeek-ot/conn.log", status: "idle", expected_active: true, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "zeek_ot_dns", source_tool: "zeek", relative_path: "zeek-ot/dns.log", status: "idle", expected_active: false, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "zeek_ot_modbus", source_tool: "zeek", relative_path: "zeek-ot/modbus.log", status: "idle", expected_active: true, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "cowrie", source_tool: "cowrie", relative_path: "cowrie/cowrie.json", status: "idle", expected_active: false, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "opencanary", source_tool: "opencanary", relative_path: "opencanary/opencanary.log", status: "idle", expected_active: false, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "plc_sim_writes", source_tool: "modbus", relative_path: "plc/plc-sim-writes.jsonl", status: "idle", expected_active: true, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "plc_sim_state", source_tool: "modbus", relative_path: "plc/plc-sim-state.jsonl", status: "idle", expected_active: true, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
  { source_key: "decoy_plc", source_tool: "modbus", relative_path: "plc/decoy-plc.jsonl", status: "idle", expected_active: false, lines_read: 0, events_emitted: 0, ignored: {}, unparsed: 0, errors: 0, last_event_ts: null, last_event_age_sec: null, last_error: null },
];

function formatTimestamp(isoString: string): string {
  try {
    const d = new Date(isoString);
    return d.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return isoString;
  }
}

function formatRelativeTime(isoString?: string | null): string {
  if (!isoString) return "No activity";
  try {
    const d = new Date(isoString);
    const diffSec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    return `${Math.floor(diffSec / 3600)}h ago`;
  } catch {
    return isoString;
  }
}

export default function OverviewPage() {
  const { events, signals, incidents, guardDecisions, status } = useEventStream();
  const { presenterMode } = useEventStore();
  const { success, error: toastError } = useToast();

  const [activeActivityTab, setActiveActivityTab] = React.useState<"events" | "signals" | "guard">("events");
  const [selectedDomain, setSelectedDomain] = React.useState<string>("all");
  const [selectedSource] = React.useState<string>("all");
  const [searchQuery, setSearchQuery] = React.useState<string>("");
  const [isEmitting, setIsEmitting] = React.useState<boolean>(false);
  const [isSourcesExpanded, setIsSourcesExpanded] = React.useState<boolean>(false);

  // Poll source health every 3 seconds via TanStack Query
  const { data: fetchedSourcesHealth } = useQuery({
    queryKey: ["sourcesHealth"],
    queryFn: fetchSourcesHealth,
    refetchInterval: 3000,
  });

  const sourcesHealth = fetchedSourcesHealth && fetchedSourcesHealth.length > 0
    ? fetchedSourcesHealth
    : DEFAULT_TELEMETRY_SOURCES;

  // Poll global telemetry stats every 3 seconds
  const { data: telemetryStats } = useQuery({
    queryKey: ["telemetryStats"],
    queryFn: () => fetchStats(300),
    refetchInterval: 3000,
  });

  const handleEmit = async () => {
    setIsEmitting(true);
    try {
      await emitTestEvent();
      success("Test Event Dispatched", "Ingested synthetic test event into SentinelX pipeline.");
    } catch (err) {
      toastError("Dispatch Error", err instanceof Error ? err.message : "Failed to emit test event");
    } finally {
      setIsEmitting(false);
    }
  };

  // Active incidents prioritized by score
  const activeIncidents = React.useMemo(() => {
    return incidents.filter((i) => i.score >= 0.50).sort((a, b) => b.score - a.score);
  }, [incidents]);

  const criticalIncidentsCount = incidents.filter((i) => i.severity === "critical").length;
  const highIncidentsCount = incidents.filter((i) => i.severity === "high").length;
  const otThreatsCount = incidents.filter((i) =>
    i.ot_touched ||
    i.entities.some((e) => e.value.toLowerCase().includes("plc") || e.value.toLowerCase().includes("eng-ws"))
  ).length;

  // Filter events
  const filteredEvents = React.useMemo(() => {
    return events.filter((ev) => {
      if (selectedDomain !== "all" && ev.domain !== selectedDomain) return false;
      if (selectedSource !== "all" && ev.source_tool !== selectedSource) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const host = (ev.host || "").toLowerCase();
        const user = (ev.user || "").toLowerCase();
        const action = (ev.action || "").toLowerCase();
        const category = (ev.category || "").toLowerCase();
        const cmdline = (ev.cmdline || "").toLowerCase();
        const srcIp = (ev.src_ip || "").toLowerCase();
        const dstIp = (ev.dst_ip || "").toLowerCase();
        const tags = (ev.tags || []).join(" ").toLowerCase();
        if (
          !host.includes(q) &&
          !user.includes(q) &&
          !action.includes(q) &&
          !category.includes(q) &&
          !cmdline.includes(q) &&
          !srcIp.includes(q) &&
          !dstIp.includes(q) &&
          !tags.includes(q)
        ) {
          return false;
        }
      }
      return true;
    });
  }, [events, selectedDomain, selectedSource, searchQuery]);

  return (
    <div className="p-6 md:p-8 space-y-6 max-w-7xl mx-auto w-full font-sans">
      {/* Unified Page Header */}
      <PageHeader
        title="Security Operations & Telemetry Center"
        subtitle="Real-time cyber-physical detection, multi-zone correlation across IT/OT environments, and autonomous safety guard enforcement."
        icon={Activity}
        actions={
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono">
              <span className="text-slate-400">Rate:</span>
              <span className="text-emerald-400 font-bold">{telemetryStats?.events_per_sec ?? 0} eps</span>
              <span className="text-slate-700">|</span>
              <span className="text-slate-400">5m Vol:</span>
              <span className="text-slate-200 font-semibold">{telemetryStats?.total_events ?? 0}</span>
            </div>

            <StatusBadge
              status={status === "open" ? "live" : status === "connecting" ? "connecting" : "offline"}
              label={status === "open" ? "LIVE STREAM" : status === "connecting" ? "CONNECTING" : "OFFLINE"}
            />

            {!presenterMode && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleEmit}
                disabled={isEmitting}
                className="gap-1.5 font-mono text-xs border-slate-700 hover:border-slate-600 bg-slate-900/60 cursor-pointer"
              >
                <Send className="w-3.5 h-3.5 text-blue-400" />
                {isEmitting ? "Emitting..." : "Dev Emit"}
              </Button>
            )}
          </div>
        }
      />

      {/* Global Ingest Replay Status Bar */}
      <ReplayStatusBar />

      {/* Primary KPI Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard
          label="Active Incidents"
          value={activeIncidents.length}
          subValue={`${incidents.length} total correlated`}
          variant={activeIncidents.length > 0 ? "critical" : "success"}
          icon={AlertTriangle}
          trend={activeIncidents.length > 0 ? "ACTION REQ" : "NORMAL"}
          trendDirection={activeIncidents.length > 0 ? "down" : "up"}
        />

        <MetricCard
          label="Critical & High Detections"
          value={criticalIncidentsCount + highIncidentsCount}
          subValue={`${criticalIncidentsCount} critical, ${highIncidentsCount} high`}
          variant={criticalIncidentsCount > 0 ? "critical" : highIncidentsCount > 0 ? "warning" : "default"}
          icon={Flame}
        />

        <MetricCard
          label="OT / ICS Threats"
          value={otThreatsCount}
          subValue="Modbus & engineering pivot"
          variant={otThreatsCount > 0 ? "critical" : "default"}
          icon={Cpu}
        />

        <MetricCard
          label="Guard Containment Decisions"
          value={guardDecisions.length}
          subValue={`${guardDecisions.filter(d => d.decision === "deny").length} denied unsafe, ${guardDecisions.filter(d => d.decision === "needs_human").length} human review`}
          variant="info"
          icon={ShieldCheck}
        />
      </div>

      {/* Investigation Queue: Prominent Active Incidents Table */}
      {activeIncidents.length > 0 && (
        <Card className="border-red-900/60 bg-red-950/10 shadow-xl overflow-hidden">
          <CardHeader className="py-3 px-5 border-b border-red-900/40 bg-red-950/20 flex flex-row items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
              <CardTitle className="text-sm font-bold tracking-tight text-red-200 uppercase font-mono">
                Active Priority Investigation Queue ({activeIncidents.length})
              </CardTitle>
            </div>
            <Link
              href="/incidents"
              className="text-xs font-mono text-red-300 hover:text-red-100 flex items-center gap-1"
            >
              View Full Incident Queue <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-slate-800/80">
              {activeIncidents.slice(0, 3).map((inc) => (
                <div
                  key={inc.incident_id}
                  className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-slate-900/40 transition-colors"
                >
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs font-bold text-slate-100">
                        {inc.incident_id}
                      </span>
                      <Badge variant="outline" className={getSeverityStyle(inc.severity).badge}>
                        {inc.severity.toUpperCase()}
                      </Badge>
                      <span className="text-[11px] font-mono text-slate-400">
                        Score: <strong className="text-red-400">{inc.score.toFixed(2)}</strong>
                      </span>
                      <span className="text-slate-600">|</span>
                      <span className="text-[11px] font-mono text-slate-400">
                        Age: {formatRelativeTime(inc.created_at)}
                      </span>
                    </div>

                    <h4 className="text-sm font-semibold text-slate-200 truncate">
                      {inc.summary || "Multi-stage cyber-physical progression detected"}
                    </h4>

                    <div className="flex items-center gap-2 text-xs text-slate-400 flex-wrap">
                      <span>Entities:</span>
                      {(inc.entities || []).slice(0, 3).map((target) => (
                        <span
                          key={target.value}
                          className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300"
                        >
                          {target.value}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <Link href={`/incidents?id=${encodeURIComponent(inc.incident_id)}`}>
                      <Button
                        size="sm"
                        variant="outline"
                        className="gap-1.5 font-mono text-xs border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200"
                      >
                        <Eye className="w-3.5 h-3.5 text-blue-400" />
                        Details
                      </Button>
                    </Link>
                    <Link href={`/graph?incident_id=${encodeURIComponent(inc.incident_id)}`}>
                      <Button
                        size="sm"
                        className="gap-1.5 font-mono text-xs bg-red-600 hover:bg-red-700 text-white font-bold"
                      >
                        <GitGraph className="w-3.5 h-3.5" />
                        Investigate Graph
                      </Button>
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Core Centerpiece Visuals: Alert Budget Controller & Correlated Incident Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <BudgetGauge />
        <RecentIncidentCard />
      </div>

      {/* Collapsible Telemetry Sources Overview */}
      <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
        <CardHeader className="py-3 px-5 border-b border-slate-800 flex flex-row items-center justify-between cursor-pointer select-none" onClick={() => setIsSourcesExpanded(!isSourcesExpanded)}>
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-sky-400" />
            <CardTitle className="text-sm font-semibold tracking-tight text-slate-200">
              Telemetry Ingestion Pipelines ({sourcesHealth.length} Monitored Sensors)
            </CardTitle>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-400 font-mono hidden sm:inline">
              {sourcesHealth.filter((s) => s.status === "live").length} Live / {sourcesHealth.length} Total
            </span>
            {isSourcesExpanded ? (
              <ChevronUp className="w-4 h-4 text-slate-400" />
            ) : (
              <ChevronDown className="w-4 h-4 text-slate-400" />
            )}
          </div>
        </CardHeader>

        {isSourcesExpanded && (
          <CardContent className="p-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {sourcesHealth.map((src) => {
                const isLive = src.status === "live";
                return (
                  <div
                    key={src.source_key}
                    className="p-3 rounded-lg border border-slate-800/80 bg-slate-950/60 flex flex-col justify-between font-mono text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between gap-1.5">
                      <span className="font-bold text-slate-200 truncate">{src.source_key}</span>
                      <StatusBadge
                        status={src.status}
                        className="text-[10px] px-1.5 py-0"
                        showDot={isLive}
                      />
                    </div>
                    <div className="text-[11px] text-slate-400 truncate">
                      Tool: <span className="text-slate-300">{src.source_tool}</span>
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-800/60">
                      <span>Events: {src.events_emitted}</span>
                      <span>{src.last_event_ts ? formatRelativeTime(src.last_event_ts) : "Standby"}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        )}
      </Card>

      {/* Real-time Activity Feed with Tabbed Views */}
      <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
        <CardHeader className="py-3 px-5 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-blue-400" />
            <CardTitle className="text-sm font-semibold tracking-tight text-slate-200">
              Live Pipeline Stream
            </CardTitle>
          </div>

          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 font-mono text-xs">
            <button
              type="button"
              onClick={() => setActiveActivityTab("events")}
              className={cn(
                "px-3 py-1 rounded transition-colors cursor-pointer",
                activeActivityTab === "events"
                  ? "bg-blue-600 text-white font-bold"
                  : "text-slate-400 hover:text-slate-200"
              )}
            >
              Events ({events.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveActivityTab("signals")}
              className={cn(
                "px-3 py-1 rounded transition-colors cursor-pointer",
                activeActivityTab === "signals"
                  ? "bg-purple-600 text-white font-bold"
                  : "text-slate-400 hover:text-slate-200"
              )}
            >
              Signals ({signals.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveActivityTab("guard")}
              className={cn(
                "px-3 py-1 rounded transition-colors cursor-pointer",
                activeActivityTab === "guard"
                  ? "bg-emerald-600 text-white font-bold"
                  : "text-slate-400 hover:text-slate-200"
              )}
            >
              Guard Decisions ({guardDecisions.length})
            </button>
          </div>
        </CardHeader>

        <CardContent className="p-4 space-y-4">
          {activeActivityTab === "events" && (
            <>
              {/* Event Filters */}
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="text-slate-400">Domain:</span>
                  {["all", "it", "ot", "decoy"].map((dom) => (
                    <button
                      key={dom}
                      type="button"
                      onClick={() => setSelectedDomain(dom)}
                      className={cn(
                        "px-2 py-0.5 rounded uppercase font-semibold text-[11px] transition-colors cursor-pointer",
                        selectedDomain === dom
                          ? "bg-blue-600 text-white"
                          : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"
                      )}
                    >
                      {dom}
                    </button>
                  ))}
                </div>

                <div className="relative w-72">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Search events, IPs, commands..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {filteredEvents.length === 0 ? (
                <EmptyState
                  title="No Events Found"
                  description={
                    events.length === 0
                      ? "Awaiting incoming telemetry streams. Start replay mode or run benign lab traffic."
                      : "No events match the specified domain and search criteria."
                  }
                  actionLabel={searchQuery || selectedDomain !== "all" ? "Reset Filters" : undefined}
                  onAction={() => {
                    setSearchQuery("");
                    setSelectedDomain("all");
                  }}
                />
              ) : (
                <ScrollArea className="h-96 rounded-xl border border-slate-800 bg-slate-950/60">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] sticky top-0 z-10 border-b border-slate-800">
                      <tr>
                        <th className="p-2.5">Time</th>
                        <th className="p-2.5">Domain</th>
                        <th className="p-2.5">Source</th>
                        <th className="p-2.5">Host / IP</th>
                        <th className="p-2.5">Action</th>
                        <th className="p-2.5">Detail</th>
                        <th className="p-2.5 text-right">Evidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {filteredEvents.slice(0, 100).map((ev) => (
                        <tr key={ev.event_id} className="hover:bg-slate-900/50 transition-colors">
                          <td className="p-2.5 text-slate-400 whitespace-nowrap">
                            {formatTimestamp(ev.ts)}
                          </td>
                          <td className="p-2.5">
                            <Badge variant="outline" className={cn("text-[10px] uppercase font-bold", getDomainStyle(ev.domain).badge)}>
                              {ev.domain}
                            </Badge>
                          </td>
                          <td className="p-2.5 text-slate-300">{ev.source_tool}</td>
                          <td className="p-2.5 text-slate-300 truncate max-w-[140px]">
                            {ev.host || ev.dst_ip || "N/A"}
                          </td>
                          <td className="p-2.5 text-slate-200 font-semibold">{ev.action}</td>
                          <td className="p-2.5 text-slate-400 truncate max-w-[240px]">
                            {ev.cmdline || (ev.ot?.is_write ? `Modbus Write Reg ${ev.ot.register}=${ev.ot.value}` : ev.category)}
                          </td>
                          <td className="p-2.5 text-right whitespace-nowrap">
                            <EvidenceLink id={ev.event_id} type="event" />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </ScrollArea>
              )}
            </>
          )}

          {activeActivityTab === "signals" && (
            <div className="space-y-3">
              {signals.length === 0 ? (
                <EmptyState
                  title="No Detection Signals Emitted"
                  description="Threat detector engines (Rules, Baselines, Isolation Forest, Graph, Deception) have not emitted any alarms."
                />
              ) : (
                <ScrollArea className="h-96 rounded-xl border border-slate-800 bg-slate-950/60 p-3 space-y-2.5">
                  {signals.slice(0, 50).map((sig) => {
                    const dStyle = getDetectorStyle(sig.detector);
                    const sigSeverity = sig.score >= 0.8 ? "critical" : sig.score >= 0.6 ? "high" : sig.score >= 0.4 ? "medium" : "low";
                    const sStyle = getSeverityStyle(sigSeverity);
                    return (
                      <div
                        key={sig.signal_id}
                        className="p-3 mb-2 rounded-lg border border-slate-800 bg-slate-900/40 flex items-start justify-between gap-3 font-mono text-xs"
                      >
                        <div className="space-y-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={sStyle.badge}>
                              {sigSeverity.toUpperCase()}
                            </Badge>
                            <Badge variant="outline" className={dStyle.badge}>
                              {sig.detector.toUpperCase()}
                            </Badge>
                            <span className="font-bold text-slate-200">{sig.rule_id}</span>
                            <span className="text-[11px] text-slate-500">
                              Confidence: {(sig.confidence * 100).toFixed(0)}%
                            </span>
                          </div>
                          <p className="text-slate-300 font-sans text-xs">{sig.explanation}</p>
                        </div>
                        <EvidenceLink id={sig.signal_id} type="signal" />
                      </div>
                    );
                  })}
                </ScrollArea>
              )}
            </div>
          )}

          {activeActivityTab === "guard" && (
            <div className="space-y-3">
              {guardDecisions.length === 0 ? (
                <EmptyState
                  title="No Safety Guard Decisions Logged"
                  description="Response Safety Guard policy evaluations will be streamed here as containment recommendations are analyzed."
                />
              ) : (
                <ScrollArea className="h-96 rounded-xl border border-slate-800 bg-slate-950/60 p-3 space-y-2.5">
                  {guardDecisions.slice(0, 30).map((dec) => (
                    <div
                      key={dec.decision_id}
                      className={cn(
                        "p-3 mb-2 rounded-lg border font-mono text-xs flex items-start justify-between gap-3",
                        dec.decision === "deny"
                          ? "border-red-800/80 bg-red-950/20"
                          : dec.decision === "allow"
                          ? "border-emerald-800/80 bg-emerald-950/20"
                          : "border-amber-800/80 bg-amber-950/20"
                      )}
                    >
                      <div className="space-y-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <StatusBadge status={dec.decision} />
                          <span className="font-bold text-slate-200">
                            {dec.action.toUpperCase()} ➔ {dec.target}
                          </span>
                          <span className="text-[11px] text-slate-500">
                            Rules: {dec.rule_ids?.join(", ") || "Safety Engine"}
                          </span>
                        </div>
                        <p className="text-slate-300 font-sans text-xs">
                          {dec.reasons?.join("; ") || "Response Safety Guard evaluated policy constraints."}
                        </p>
                      </div>
                      <span className="text-[11px] text-slate-500 shrink-0">
                        {formatTimestamp(dec.ts)}
                      </span>
                    </div>
                  ))}
                </ScrollArea>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
