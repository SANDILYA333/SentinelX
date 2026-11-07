"use client";

import * as React from "react";
import type { Domain, Event } from "@contracts/index";
import { emitTestEvent } from "@/lib/api";
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
  Radio,
  Send,
  Server,
  User as UserIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";

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
  const [isEmitting, setIsEmitting] = React.useState<boolean>(false);
  const [emitError, setEmitError] = React.useState<string | null>(null);

  const handleEmit = async () => {
    setIsEmitting(true);
    setEmitError(null);
    try {
      await emitTestEvent();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to emit event";
      setEmitError(msg);
      console.error("Emit error:", err);
    } finally {
      setIsEmitting(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl">
      {/* Header bar with title and WS live badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-blue-400" />
            Security Telemetry Overview
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time live telemetry correlation across IT enterprise, ICS/OT networks, and canary deception assets.
          </p>
        </div>

        {/* WebSocket status badge */}
        <div className="flex items-center gap-3">
          {status === "open" && (
            <Badge variant="success" className="gap-1.5 px-3 py-1 font-mono text-xs">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              Live
            </Badge>
          )}

          {status === "connecting" && (
            <Badge variant="warning" className="gap-1.5 px-3 py-1 font-mono text-xs">
              <span className="inline-block h-2 w-2 rounded-full bg-amber-400 animate-pulse"></span>
              Connecting
            </Badge>
          )}

          {status === "closed" && (
            <Badge variant="destructive" className="gap-1.5 px-3 py-1 font-mono text-xs">
              <span className="inline-block h-2 w-2 rounded-full bg-red-400"></span>
              Disconnected
            </Badge>
          )}

          {/* Dev Emit Button */}
          <Button
            onClick={handleEmit}
            disabled={isEmitting}
            variant="outline"
            size="sm"
            className="border-blue-700/60 bg-blue-950/40 text-blue-200 hover:bg-blue-900/60 hover:text-blue-100 gap-1.5 text-xs font-mono"
          >
            <Send className="w-3.5 h-3.5 text-blue-400" />
            {isEmitting ? "Emitting..." : "Emit test event (dev)"}
          </Button>
        </div>
      </div>

      {emitError && (
        <div className="p-3 rounded-lg border border-red-800 bg-red-950/50 text-red-300 text-xs font-mono">
          Emission Error: {emitError}
        </div>
      )}

      {/* Live Event Feed Card */}
      <Card className="border-slate-800 bg-slate-900/40 shadow-xl backdrop-blur-sm">
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <div>
            <CardTitle className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400" />
              Live event feed
            </CardTitle>
            <CardDescription className="text-xs text-slate-400 mt-0.5">
              Streaming newest-first normalized telemetry ({events.length} buffered)
            </CardDescription>
          </div>
          <div className="flex items-center gap-4 text-xs text-slate-400 font-mono">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-sky-400"></span> IT
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-amber-400"></span> OT
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-purple-400"></span> Decoy
            </span>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {events.length === 0 ? (
            <div className="p-12 text-center text-slate-500 text-sm">
              <Radio className="w-8 h-8 mx-auto mb-2 opacity-40 animate-pulse" />
              Waiting for incoming telemetry events... Click &quot;Emit test event (dev)&quot; to trigger a sample record.
            </div>
          ) : (
            <ScrollArea className="max-h-[640px] divide-y divide-slate-800/60">
              {events.map((evt: Event) => (
                <div
                  key={evt.event_id}
                  className="px-6 py-3.5 hover:bg-slate-800/30 transition-colors flex items-center justify-between gap-4 text-xs font-mono"
                >
                  {/* Left: Domain indicator dot, timestamp, source badge, domain badge, action */}
                  <div className="flex items-center gap-3 min-w-0">
                    {/* Domain indicator colored dot */}
                    <span
                      title={`Domain: ${evt.domain}`}
                      className={cn("h-2.5 w-2.5 rounded-full shrink-0", getDomainDotClass(evt.domain))}
                    />

                    {/* Timestamp */}
                    <span className="text-slate-400 shrink-0 font-medium">
                      {formatTimestamp(evt.ts)}
                    </span>

                    {/* Source Tool Badge */}
                    <Badge variant="secondary" className="text-[11px] px-2 py-0.5 shrink-0 bg-slate-800 border-slate-700">
                      {evt.source_tool}
                    </Badge>

                    {/* Domain Badge */}
                    <Badge variant={getDomainBadgeVariant(evt.domain)} className="text-[11px] px-2 py-0.5 shrink-0 uppercase">
                      {evt.domain}
                    </Badge>

                    {/* Action */}
                    <span className="text-slate-200 font-semibold truncate">
                      {evt.action}
                    </span>

                    {/* Category pill */}
                    <span className="text-[11px] text-slate-500 hidden md:inline">
                      ({evt.category})
                    </span>
                  </div>

                  {/* Right: Host / User / OT Details */}
                  <div className="flex items-center gap-4 text-slate-400 shrink-0 text-right">
                    {evt.user && (
                      <span className="flex items-center gap-1 text-slate-300">
                        <UserIcon className="w-3.5 h-3.5 text-slate-500" />
                        {evt.user}
                      </span>
                    )}

                    {evt.host && (
                      <span className="flex items-center gap-1 text-slate-400">
                        <Server className="w-3.5 h-3.5 text-slate-600" />
                        {evt.host}
                      </span>
                    )}

                    {evt.ot && (
                      <span className="flex items-center gap-1 text-amber-400/90 text-[11px] bg-amber-950/40 px-2 py-0.5 rounded border border-amber-800/40">
                        <Cpu className="w-3 h-3 text-amber-400" />
                        PLC Reg {evt.ot.register} (FC:{evt.ot.function_code})
                      </span>
                    )}

                    {/* Event ID */}
                    <span className="text-[10px] text-slate-600 font-mono hidden lg:inline">
                      {evt.event_id}
                    </span>
                  </div>
                </div>
              ))}
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
