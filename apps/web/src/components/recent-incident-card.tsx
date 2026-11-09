"use client";

import Link from "next/link";
import { useEventStore } from "@/lib/store";
import { getSeverityStyle, sortKillChainStages, STAGE_META } from "@/lib/theme";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Radio,
  Server,
  ShieldAlert,
  User,
} from "lucide-react";
import { cn } from "@/lib/utils";

export function RecentIncidentCard() {
  const { incidents } = useEventStore();

  const activeIncidents = incidents.filter((i) => i.score >= 0.50);
  const mostRecent = incidents[0] || null;

  return (
    <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
      <CardHeader className="pb-3 border-b border-slate-800/80">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            Correlated Incident Feed
          </CardTitle>
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-400">Active Incidents:</span>
            <span className={cn(
              "font-bold px-2 py-0.5 rounded",
              activeIncidents.length > 0
                ? "bg-red-950/80 text-red-400 border border-red-800/60 animate-pulse"
                : "bg-emerald-950/60 text-emerald-400 border border-emerald-800/60"
            )}>
              {activeIncidents.length}
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">Total Tracked:</span>
            <span className="text-slate-200 font-semibold">{incidents.length}</span>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pt-4">
        {mostRecent ? (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-slate-100">
                  {mostRecent.incident_id}
                </span>
                <Badge variant="outline" className={getSeverityStyle(mostRecent.severity).badge}>
                  {mostRecent.severity.toUpperCase()}
                </Badge>
                {mostRecent.novelty_only && (
                  <Badge variant="outline" className="bg-amber-950/60 text-amber-300 border-amber-600/40 text-[10px] font-mono">
                    novelty-only, score capped
                  </Badge>
                )}
                {mostRecent.decoy_touched && (
                  <Badge variant="outline" className="bg-purple-950/60 text-purple-300 border-purple-800/60 text-[10px]">
                    <ShieldAlert className="w-3 h-3 mr-1" /> Decoy Touched
                  </Badge>
                )}
                {mostRecent.ot_touched && (
                  <Badge variant="outline" className="bg-rose-950/60 text-rose-300 border-rose-800/60 text-[10px]">
                    <Cpu className="w-3 h-3 mr-1" /> OT Impact
                  </Badge>
                )}
              </div>

              <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                {mostRecent.ttfma_seconds != null && (
                  <span className="text-emerald-400">
                    TTFMA: <strong>{mostRecent.ttfma_seconds.toFixed(2)}s</strong>
                  </span>
                )}
                <span>Score: <strong className="text-slate-100">{mostRecent.score.toFixed(2)}</strong></span>
              </div>
            </div>

            {/* Stage Pills */}
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] text-slate-500 mr-1">Progression:</span>
              {sortKillChainStages(mostRecent.kill_chain_stages).map((stage) => {
                const meta = STAGE_META[stage];
                return (
                  <Badge
                    key={stage}
                    variant="outline"
                    className={cn("text-[10px] py-0.5", meta?.badge || "bg-slate-800 text-slate-300")}
                  >
                    {meta?.label || stage}
                  </Badge>
                );
              })}
            </div>

            {/* Entities & Click-through link */}
            <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs">
              <div className="flex items-center gap-3 text-slate-400 font-mono text-[11px]">
                <span className="flex items-center gap-1">
                  <User className="w-3 h-3 text-slate-500" />
                  {mostRecent.entities.find((e) => e.type === "user")?.value || "N/A"}
                </span>
                <span className="flex items-center gap-1">
                  <Server className="w-3 h-3 text-slate-500" />
                  {mostRecent.entities.find((e) => e.type === "host")?.value || "N/A"}
                </span>
                <span className="flex items-center gap-1">
                  <Radio className="w-3 h-3 text-slate-500" />
                  {mostRecent.signal_ids.length} signals ({mostRecent.event_ids.length} evts)
                </span>
              </div>

              <Link
                href={`/incidents?id=${encodeURIComponent(mostRecent.incident_id)}`}
                className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 font-medium"
              >
                <span>Investigate Incident</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            </div>
          </div>
        ) : (
          <div className="py-6 flex flex-col items-center justify-center text-center space-y-2">
            <div className="w-10 h-10 rounded-full bg-emerald-950/60 border border-emerald-800/60 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-semibold text-slate-200">
                Zero Security Incidents Active
              </h4>
              <p className="text-xs text-slate-400 mt-0.5 max-w-sm">
                Clean state: all telemetry feeds operating within baseline. No multi-stage attack chains detected above budget threshold (0.50).
              </p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
