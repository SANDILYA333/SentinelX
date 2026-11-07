"use client";

import * as React from "react";
import type { Domain, Event, SourceHealth } from "@contracts/index";
import { useQuery } from "@tanstack/react-query";
import { emitTestEvent, fetchSourcesHealth, fetchStats } from "@/lib/api";
import { useEventStream } from "@/hooks/useEventStream";
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
  Cpu,
  Database,
  Filter,
  Radio,
  Search,
  Send,
  Server,
  Terminal,
  User as UserIcon,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";

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

function getDomainDotClass(domain: Domain): string {
  switch (domain) {
    case "it":
      return "bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.7)]";
    case "ot":
      return "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.7)]";
    case "decoy":
      return "bg-purple-400 shadow-[0_0_8px_rgba(192,132,252,0.7)]";
    default:
      return "bg-slate-400";
  }
}

function getDomainBadgeVariant(domain: Domain): "default" | "secondary" | "warning" | "destructive" | "outline" {
  switch (domain) {
    case "it":
      return "outline";
    case "ot":
      return "warning";
    case "decoy":
      return "destructive";
    default:
      return "secondary";
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

export default function OverviewPage() {
  const { events, status } = useEventStream();
  const [selectedDomain, setSelectedDomain] = React.useState<string>("all");
  const [selectedSource, setSelectedSource] = React.useState<string>("all");
  const [searchQuery, setSearchQuery] = React.useState<string>("");
  const [selectedEvent, setSelectedEvent] = React.useState<Event | null>(null);
  const [showRawPayload, setShowRawPayload] = React.useState<boolean>(false);
  const [isEmitting, setIsEmitting] = React.useState<boolean>(false);

  // Poll source health every 2 seconds via TanStack Query
  const { data: sourcesHealth } = useQuery({
    queryKey: ["sourcesHealth"],
    queryFn: fetchSourcesHealth,
    refetchInterval: 2000,
  });

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
      console.error("Emit error:", err);
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
    <div className="p-8 space-y-6 max-w-7xl">
      {/* Header bar with title and WS live badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-blue-400" />
            Security Telemetry Pipeline
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time live telemetry correlation across IT enterprise, ICS/OT networks, and canary deception assets.
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
              <Badge variant="success" className="gap-1.5 px-3 py-1 font-mono text-xs">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                LIVE WS
              </Badge>
            )}
            {status === "connecting" && (
              <Badge variant="warning" className="gap-1.5 px-3 py-1 font-mono text-xs">
                <Radio className="w-3 h-3 animate-spin text-amber-400" />
                CONNECTING
              </Badge>
            )}
            {status === "closed" && (
              <Badge variant="destructive" className="gap-1.5 px-3 py-1 font-mono text-xs">
                <Radio className="w-3 h-3 text-rose-400" />
                DISCONNECTED
              </Badge>
            )}

            <Button
              variant="outline"
              size="sm"
              onClick={handleEmit}
              disabled={isEmitting}
              className="gap-1.5 font-mono text-xs border-slate-700 hover:border-slate-600 bg-slate-900/60"
            >
              <Send className="w-3.5 h-3.5 text-blue-400" />
              {isEmitting ? "Emitting..." : "Dev Emit"}
            </Button>
          </div>
        </div>
      </div>

      {/* Source Health Cards Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Server className="w-4 h-4 text-sky-400" />
            Telemetry Sources ({sourcesHealth?.length ?? 0})
          </h2>
          <span className="text-xs text-slate-500 font-mono">Polled every 2s via TanStack Query</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {sourcesHealth?.map((src: SourceHealth) => {
            const ignoredCount = Object.values(src.ignored || {}).reduce((a, b) => a + b, 0);
            return (
              <div
                key={src.source_key}
                className="bg-slate-900/70 border border-slate-800/80 rounded-lg p-3 hover:border-slate-700 transition-colors flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1.5">
                    <span className="font-mono text-xs font-medium text-slate-200 truncate" title={src.source_key}>
                      {src.source_key}
                    </span>
                    {getStatusBadge(src.status)}
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono truncate" title={src.relative_path}>
                    {src.source_tool}
                  </div>
                </div>

                <div className="mt-2.5 pt-2 border-t border-slate-800/60 text-[11px] font-mono text-slate-400 space-y-0.5">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Emitted:</span>
                    <span className="text-slate-200">{src.events_emitted}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Age:</span>
                    <span className={src.last_event_age_sec !== undefined && src.last_event_age_sec !== null && src.last_event_age_sec < 60 ? "text-emerald-400" : "text-slate-400"}>
                      {src.last_event_age_sec !== undefined && src.last_event_age_sec !== null ? `${src.last_event_age_sec}s` : "N/A"}
                    </span>
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-500">
                    <span>ign/unp:</span>
                    <span>{ignoredCount}/{src.unparsed}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/60 border border-slate-800 p-3 rounded-lg">
        {/* Domain Chips */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs font-mono text-slate-400 mr-1 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Domain:
          </span>
          {["all", "it", "ot", "decoy"].map((d) => (
            <button
              key={d}
              onClick={() => setSelectedDomain(d)}
              className={cn(
                "px-2.5 py-1 text-xs font-mono rounded border transition-colors uppercase",
                selectedDomain === d
                  ? "bg-blue-600/30 border-blue-500 text-blue-300 font-semibold"
                  : "bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700"
              )}
            >
              {d}
            </button>
          ))}
        </div>

        {/* Search & Source filter */}
        <div className="flex items-center gap-2">
          {/* Source dropdown */}
          <select
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-300 text-xs font-mono rounded px-2.5 py-1.5 focus:outline-none focus:border-slate-700"
          >
            <option value="all">All Sources</option>
            {availableSources.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          {/* Text search input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search host, user, cmd..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono rounded pl-8 pr-3 py-1.5 focus:outline-none focus:border-slate-700 w-48 sm:w-60"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-2 top-2 text-slate-500 hover:text-slate-300"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Live Event Stream Card */}
      <Card className="border-slate-800/80 bg-slate-900/40 backdrop-blur">
        <CardHeader className="pb-3 border-b border-slate-800/60 flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-base font-semibold text-slate-200 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Live Telemetry Feed ({filteredEvents.length})
            </CardTitle>
            <CardDescription className="text-xs text-slate-400 font-mono">
              Showing newest events. Click any row to inspect normalized schema & raw provenance.
            </CardDescription>
          </div>
          <span className="text-xs font-mono text-slate-500">Rate limited &le; 20 evt/s to UI</span>
        </CardHeader>
        <CardContent className="p-0">
          <ScrollArea className="h-[480px]">
            {filteredEvents.length === 0 ? (
              <div className="p-12 text-center text-slate-500 font-mono text-sm">
                No telemetry events matching the current filter criteria.
              </div>
            ) : (
              <div className="divide-y divide-slate-800/60 font-mono text-xs">
                {filteredEvents.map((ev) => (
                  <div
                    key={ev.event_id}
                    onClick={() => setSelectedEvent(ev)}
                    className="p-3 hover:bg-slate-800/40 cursor-pointer transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                  >
                    <div className="flex items-center gap-3">
                      <span className={cn("w-2 h-2 rounded-full shrink-0", getDomainDotClass(ev.domain))} />
                      <span className="text-slate-500 text-[11px] shrink-0">
                        {formatTimestamp(ev.ts)}
                      </span>
                      <Badge variant={getDomainBadgeVariant(ev.domain)} className="uppercase text-[10px] px-1.5 py-0">
                        {ev.domain}
                      </Badge>
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-slate-700 text-slate-400">
                        {ev.source_tool}
                      </Badge>
                      <span className="font-semibold text-slate-200">
                        {ev.category}/{ev.action}
                      </span>
                    </div>

                    <div className="flex items-center gap-4 text-slate-400 text-[11px] truncate">
                      {ev.host && (
                        <span className="flex items-center gap-1 text-slate-300">
                          <Server className="w-3 h-3 text-slate-500" />
                          {ev.host}
                        </span>
                      )}
                      {ev.user && (
                        <span className="flex items-center gap-1 text-sky-400">
                          <UserIcon className="w-3 h-3" />
                          {ev.user}
                        </span>
                      )}
                      {ev.cmdline && (
                        <span className="text-slate-400 truncate max-w-[260px]" title={ev.cmdline}>
                          `{ev.cmdline}`
                        </span>
                      )}
                      {ev.ot && (
                        <span className="text-amber-400 truncate">
                          reg:{ev.ot.register} val:{String(ev.ot.value)} (w:{String(ev.ot.is_write)})
                        </span>
                      )}
                      {ev.tags && ev.tags.length > 0 && (
                        <div className="flex gap-1 shrink-0">
                          {ev.tags.slice(0, 2).map((t) => (
                            <span key={t} className="bg-slate-800 text-slate-400 px-1 rounded text-[10px]">
                              {t}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Slide-over Event Provenance Drawer */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-hidden">
            {/* Drawer Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <Badge variant={getDomainBadgeVariant(selectedEvent.domain)} className="uppercase text-xs font-mono">
                    {selectedEvent.domain}
                  </Badge>
                  <span className="font-mono text-xs text-slate-400">{selectedEvent.event_id}</span>
                </div>
                <h3 className="text-base font-bold text-slate-100">
                  {selectedEvent.category} &rarr; {selectedEvent.action}
                </h3>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSelectedEvent(null)}
                className="h-8 w-8 p-0 border-slate-700"
              >
                <X className="w-4 h-4 text-slate-400" />
              </Button>
            </div>

            {/* Drawer Content */}
            <ScrollArea className="flex-1 p-5 space-y-6">
              {/* Normalized Attributes Grid */}
              <div className="space-y-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
                  Normalized Event Attributes
                </h4>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono bg-slate-950/80 p-3 rounded-lg border border-slate-800/80">
                  <div>
                    <span className="text-slate-500">Timestamp:</span>
                    <p className="text-slate-200">{selectedEvent.ts}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Ingested At:</span>
                    <p className="text-slate-200">{selectedEvent.ingested_at}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Source Tool:</span>
                    <p className="text-slate-200">{selectedEvent.source_tool}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Outcome:</span>
                    <p className="text-slate-200 capitalize">{selectedEvent.outcome}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Host:</span>
                    <p className="text-slate-200">{selectedEvent.host || "N/A"}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">User:</span>
                    <p className="text-slate-200">{selectedEvent.user || "N/A"}</p>
                  </div>
                  <div>
                    <span className="text-slate-500">Src IP:Port:</span>
                    <p className="text-slate-200">
                      {selectedEvent.src_ip ? `${selectedEvent.src_ip}:${selectedEvent.src_port || ""}` : "N/A"}
                    </p>
                  </div>
                  <div>
                    <span className="text-slate-500">Dst IP:Port:</span>
                    <p className="text-slate-200">
                      {selectedEvent.dst_ip ? `${selectedEvent.dst_ip}:${selectedEvent.dst_port || ""}` : "N/A"}
                    </p>
                  </div>
                  {selectedEvent.process && (
                    <div className="col-span-2">
                      <span className="text-slate-500">Process:</span>
                      <p className="text-slate-200">{selectedEvent.process}</p>
                    </div>
                  )}
                  {selectedEvent.cmdline && (
                    <div className="col-span-2">
                      <span className="text-slate-500">Commandline:</span>
                      <p className="text-amber-300 break-all bg-slate-900 p-1.5 rounded mt-0.5">{selectedEvent.cmdline}</p>
                    </div>
                  )}
                </div>
              </div>

              {/* OT Fields (if ICS/Modbus) */}
              {selectedEvent.ot && (
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-amber-400 font-mono flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5" /> OT / Modbus Telemetry
                  </h4>
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono bg-slate-950/80 p-3 rounded-lg border border-amber-900/40">
                    <div>
                      <span className="text-slate-500">Register:</span>
                      <p className="text-amber-300 font-bold">{selectedEvent.ot.register}</p>
                    </div>
                    <div>
                      <span className="text-slate-500">Value:</span>
                      <p className="text-amber-300 font-bold">{String(selectedEvent.ot.value)}</p>
                    </div>
                    <div>
                      <span className="text-slate-500">Function Code:</span>
                      <p className="text-slate-200">{selectedEvent.ot.function_code}</p>
                    </div>
                    <div>
                      <span className="text-slate-500">Is Write:</span>
                      <p className="text-slate-200">{String(selectedEvent.ot.is_write)}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Tags */}
              {selectedEvent.tags && selectedEvent.tags.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
                    Enrichment Tags
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedEvent.tags.map((t) => (
                      <Badge key={t} variant="secondary" className="font-mono text-[11px] bg-slate-800 text-slate-300">
                        {t}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Provenance and Raw JSON */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-1.5">
                    <Database className="w-3.5 h-3.5 text-blue-400" /> Provenance & Raw Log
                  </h4>
                  <button
                    onClick={() => setShowRawPayload(!showRawPayload)}
                    className="text-[11px] text-blue-400 hover:text-blue-300 font-mono underline"
                  >
                    {showRawPayload ? "Show Raw Ref Only" : "Show Full Event JSON"}
                  </button>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono text-slate-400 space-y-1">
                  <div>
                    <span className="text-slate-500">Source File:</span>{" "}
                    <span className="text-slate-300">{String(selectedEvent.raw_ref.file || selectedEvent.raw_ref.source || "N/A")}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Byte Offset:</span>{" "}
                    <span className="text-slate-300">{String(selectedEvent.raw_ref.offset ?? "N/A")}</span>
                  </div>
                </div>

                <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto max-h-64">
                  {JSON.stringify(showRawPayload ? selectedEvent : selectedEvent.raw, null, 2)}
                </pre>
              </div>
            </ScrollArea>
          </div>
        </div>
      )}
    </div>
  );
}
