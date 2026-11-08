"use client";

import * as React from "react";
import type { SourceHealth } from "@contracts/index";
import { useQuery } from "@tanstack/react-query";
import { emitTestEvent, fetchSourcesHealth, fetchStats } from "@/lib/api";
import { useEventStream } from "@/hooks/useEventStream";
import { useEventStore } from "@/lib/store";
import { getDomainStyle } from "@/lib/theme";
import { BudgetGauge } from "@/components/budget-gauge";
import { EvidenceLink } from "@/components/evidence-link";
import { RecentIncidentCard } from "@/components/recent-incident-card";
import { ReplayStatusBar } from "@/components/replay-status-bar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Activity,
  AlertCircle,
  Filter,
  Radio,
  RefreshCw,
  Search,
  Send,
  Server,
  Terminal,
  User as UserIcon,
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

function getStatusBadge(status: string) {
  switch (status) {
    case "live":
      return (
        <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-400">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          live
        </span>
      );
    case "idle":
      return (
        <span className="flex items-center gap-1.5 text-xs font-medium text-sky-400">
          <span className="inline-flex rounded-full h-2 w-2 bg-sky-500"></span>
          idle
        </span>
      );
    case "stale":
      return (
        <span className="flex items-center gap-1.5 text-xs font-medium text-amber-400">
          <span className="inline-flex rounded-full h-2 w-2 bg-amber-500"></span>
          stale
        </span>
      );
    case "error":
      return (
        <span className="flex items-center gap-1.5 text-xs font-medium text-rose-400">
          <span className="inline-flex rounded-full h-2 w-2 bg-rose-500"></span>
          error
        </span>
      );
    default:
      return <span className="text-xs text-slate-400">{status}</span>;
  }
}

function formatTimestamp(isoString: string): string {
  try {
    const d = new Date(isoString);
    return d.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return isoString;
  }
}

function getSourceTitle(src: SourceHealth): string {
  if (src.source_tool.toLowerCase() === "zeek") {
    const tag = `${src.source_key} ${src.relative_path}`.toLowerCase();
    if (tag.includes("dmz")) return "Zeek — DMZ";
    if (tag.includes("ot")) return "Zeek — OT";
    if (tag.includes("it")) return "Zeek — IT";
    return "Zeek";
  }
  if (src.source_tool.toLowerCase() === "modbus") {
    if (src.source_key.includes("decoy")) return "Decoy PLC (Decoy)";
    if (src.source_key.includes("write")) return "PLC Sim (Writes)";
    if (src.source_key.includes("state")) return "PLC Sim (State)";
    return "Modbus PLC";
  }
  if (src.source_tool.toLowerCase() === "cowrie") {
    return "Cowrie (SSH Decoy)";
  }
  if (src.source_tool.toLowerCase() === "opencanary") {
    return "OpenCanary (Canary)";
  }
  if (src.source_tool.toLowerCase() === "wazuh") {
    return "Wazuh (Host EDR)";
  }
  return src.source_tool.charAt(0).toUpperCase() + src.source_tool.slice(1);
}

export default function OverviewPage() {
  const { events, status, forceReconnect } = useEventStream();
  const { presenterMode } = useEventStore();
  const [selectedDomain, setSelectedDomain] = React.useState<string>("all");
  const [selectedSource, setSelectedSource] = React.useState<string>("all");
  const [searchQuery, setSearchQuery] = React.useState<string>("");
  const [isEmitting, setIsEmitting] = React.useState<boolean>(false);

  // Poll source health every 2 seconds via TanStack Query
  const {
    data: fetchedSourcesHealth,
    isError: sourcesError,
    refetch: refetchSources,
  } = useQuery({
    queryKey: ["sourcesHealth"],
    queryFn: fetchSourcesHealth,
    refetchInterval: 2000,
  });

  const sourcesHealth = fetchedSourcesHealth && fetchedSourcesHealth.length > 0
    ? fetchedSourcesHealth
    : DEFAULT_TELEMETRY_SOURCES;

  // Poll global telemetry stats every 2 seconds
  const { data: telemetryStats } = useQuery({
    queryKey: ["telemetryStats"],
    queryFn: () => fetchStats(300),
    refetchInterval: 2000,
  });

  const handleEmit = async () => {
    setIsEmitting(true);
    try {
      await emitTestEvent();
    } catch (err) {
      console.warn("Emit test event error:", err);
    } finally {
      setIsEmitting(false);
    }
  };

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

  // Unique source tools for dropdown
  const availableSources = React.useMemo(() => {
    const set = new Set<string>();
    if (sourcesHealth) {
      sourcesHealth.forEach((s) => set.add(s.source_tool));
    }
    events.forEach((e) => set.add(e.source_tool));
    return Array.from(set).sort();
  }, [sourcesHealth, events]);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto w-full">
      {/* Header bar with title and WS live badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-blue-400" />
            Security Telemetry &amp; Detection Operations
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time telemetry correlation across IT enterprise, ICS/OT networks, and canary deception assets.
          </p>
        </div>

        {/* Global rates and WebSocket status */}
        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-3 bg-slate-900/80 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono">
            <span className="text-slate-400">Global Rate:</span>
            <span className="text-emerald-400 font-semibold">{telemetryStats?.events_per_sec ?? 0} evt/s</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">5m Vol:</span>
            <span className="text-slate-200 font-semibold">{telemetryStats?.total_events ?? 0}</span>
          </div>

          <div className="flex items-center gap-2">
            {status === "open" && (
              <Badge variant="outline" className="gap-1.5 px-3 py-1 font-mono text-xs bg-emerald-950/60 text-emerald-400 border-emerald-800/60">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                LIVE WS
              </Badge>
            )}
            {status === "connecting" && (
              <Badge variant="outline" className="gap-1.5 px-3 py-1 font-mono text-xs bg-amber-950/60 text-amber-400 border-amber-800/60">
                <Radio className="w-3 h-3 animate-spin text-amber-400" />
                CONNECTING
              </Badge>
            )}
            {status === "closed" && (
              <button
                type="button"
                onClick={forceReconnect}
                title="Click to reconnect WebSocket"
                className="flex items-center gap-1.5 px-3 py-1 rounded-md font-mono text-xs bg-rose-950/60 text-rose-300 border border-rose-800/60 hover:bg-rose-900/60 transition-colors cursor-pointer"
              >
                <Radio className="w-3 h-3 text-rose-400" />
                DISCONNECTED (Retry)
              </button>
            )}

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
        </div>
      </div>

      {/* Ingest Mode & Replay Status */}
      <ReplayStatusBar />

      {/* Core Centerpiece Visuals: Budget Controller & Recent Incident */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <BudgetGauge />
        <RecentIncidentCard />
      </div>

      {/* Source Health Cards Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Server className="w-4 h-4 text-sky-400" />
            Telemetry Sources ({sourcesHealth.length})
          </h2>
          <span className="text-xs text-slate-500 font-mono">
            {fetchedSourcesHealth ? "Polled live via REST" : "Topology registered (standby)"}
          </span>
        </div>

        {/* Informative offline / standby notice if backend is not currently responding */}
        {sourcesError && (
          <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-800/50 text-xs font-mono text-amber-300 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-xs">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>
                Telemetry ingestion backend is offline. Start the service with <code className="bg-slate-900 px-1.5 py-0.5 rounded text-amber-200 border border-slate-800">make ingest-live</code> or <code className="bg-slate-900 px-1.5 py-0.5 rounded text-amber-200 border border-slate-800">make api</code>.
              </span>
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() => refetchSources()}
              className="text-xs font-mono border-amber-700/60 bg-amber-950/50 hover:bg-amber-900/50 text-amber-200 shrink-0"
            >
              <RefreshCw className="w-3 h-3 mr-1.5" /> Reconnect Feeds
            </Button>
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
          {sourcesHealth.map((src: SourceHealth) => (
            <Card
              key={src.source_key}
              className="border-slate-800 bg-slate-900/50 hover:bg-slate-900/80 transition-colors shadow-xs"
            >
              <CardHeader className="p-3.5 pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-bold text-slate-200 truncate">
                    {getSourceTitle(src)}
                  </CardTitle>
                  {getStatusBadge(src.status)}
                </div>
                <CardDescription className="text-[11px] text-slate-400 truncate">
                  {src.relative_path ? src.relative_path.split("/").pop() : "No log file"}
                </CardDescription>
              </CardHeader>
              <CardContent className="p-3.5 pt-0 space-y-1 text-xs font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>Events:</span>
                  <span className="text-slate-200 font-semibold">{src.events_emitted}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Lines:</span>
                  <span className="text-slate-300 font-semibold">{src.lines_read}</span>
                </div>
                <div className="flex justify-between text-slate-500 text-[10px]">
                  <span>Last:</span>
                  <span>{src.last_event_age_sec != null ? `${src.last_event_age_sec.toFixed(0)}s ago` : src.last_event_ts ? formatTimestamp(src.last_event_ts) : "standby"}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Real-time Telemetry Stream */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-emerald-400" />
            <h2 className="text-lg font-bold tracking-tight text-slate-200">
              Live Telemetry Stream
            </h2>
            <Badge variant="outline" className="font-mono text-xs bg-slate-800 text-slate-400">
              {filteredEvents.length} events
            </Badge>
          </div>

          {/* Filtering Controls */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search event host, user, IP..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1 bg-slate-900 border border-slate-800 rounded-md text-xs text-slate-200 focus:outline-hidden focus:border-blue-500 font-mono w-48 sm:w-64"
              />
            </div>

            {/* Domain filter */}
            <select
              value={selectedDomain}
              onChange={(e) => setSelectedDomain(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-xs text-slate-300 rounded-md px-2.5 py-1 focus:outline-hidden font-mono"
            >
              <option value="all">All Domains</option>
              <option value="it">IT Domain</option>
              <option value="ot">OT Domain</option>
              <option value="decoy">Decoy Domain</option>
            </select>

            {/* Source filter */}
            <select
              value={selectedSource}
              onChange={(e) => setSelectedSource(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-xs text-slate-300 rounded-md px-2.5 py-1 focus:outline-hidden font-mono"
            >
              <option value="all">All Sources</option>
              {availableSources.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Live Event Stream Card */}
        <Card className="border-slate-800 bg-slate-950/70 shadow-lg overflow-hidden">
          <CardContent className="p-0">
            <ScrollArea className="h-[420px]">
              <div className="divide-y divide-slate-800/60 font-mono text-xs">
                {filteredEvents.length === 0 ? (
                  <div className="p-12 text-center text-slate-500 space-y-2">
                    <Filter className="w-6 h-6 mx-auto opacity-40 text-slate-400" />
                    <p className="text-slate-400 font-medium">No live telemetry events currently buffered.</p>
                    <p className="text-[11px] text-slate-500 max-w-md mx-auto">
                      Events appear in real-time as the telemetry pipeline processes incoming logs. Click <span className="text-blue-400">Dev Emit</span> above to inject an instant test event.
                    </p>
                  </div>
                ) : (
                  filteredEvents.map((ev) => {
                    const domStyle = getDomainStyle(ev.domain);
                    return (
                      <div
                        key={ev.event_id}
                        className="px-4 py-2.5 hover:bg-slate-900/60 transition-colors flex items-center justify-between gap-4 group"
                      >
                        {/* Left column: Time, Domain, Tool */}
                        <div className="flex items-center gap-3 shrink-0">
                          <span className="text-[11px] text-slate-500 w-16">
                            {formatTimestamp(ev.ts)}
                          </span>

                          <span className={cn("w-2 h-2 rounded-full", domStyle.dot)} />

                          <Badge variant="outline" className={cn("text-[10px] uppercase py-0", domStyle.badge)}>
                            {ev.domain}
                          </Badge>

                          <span className="text-slate-400 text-[11px] font-semibold w-16">
                            {ev.source_tool}
                          </span>
                        </div>

                        {/* Middle column: Action, Host, User, Details */}
                        <div className="flex-1 truncate flex items-center gap-2">
                          <span className="font-semibold text-slate-200">
                            {ev.action}
                          </span>

                          {ev.host && (
                            <span className="text-slate-400 flex items-center gap-1 text-[11px]">
                              <Server className="w-3 h-3 text-slate-600" />
                              {ev.host}
                            </span>
                          )}

                          {ev.user && (
                            <span className="text-slate-400 flex items-center gap-1 text-[11px]">
                              <UserIcon className="w-3 h-3 text-slate-600" />
                              {ev.user}
                            </span>
                          )}

                          {ev.ot && (
                            <span className="text-amber-400 text-[11px] font-semibold">
                              [reg={ev.ot.register} val={String(ev.ot.value)}]
                            </span>
                          )}

                          {ev.cmdline && (
                            <span className="text-slate-500 truncate text-[11px]">
                              `{ev.cmdline}`
                            </span>
                          )}
                        </div>

                        {/* Right column: Outcome badge & Clickable Evidence Link */}
                        <div className="flex items-center gap-2 shrink-0">
                          <span
                            className={cn(
                              "text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded",
                              ev.outcome === "success"
                                ? "bg-emerald-950/60 text-emerald-400"
                                : "bg-red-950/60 text-red-400"
                            )}
                          >
                            {ev.outcome}
                          </span>

                          <EvidenceLink id={ev.event_id} label={ev.event_id.slice(-8)} />
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
  );
}
