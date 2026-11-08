"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchSystemStatus } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { FastForward, Radio } from "lucide-react";
import { cn } from "@/lib/utils";

export function ReplayStatusBar() {
  const { data: status } = useQuery({
    queryKey: ["systemStatus"],
    queryFn: fetchSystemStatus,
    refetchInterval: 3000,
  });

  if (!status) return null;

  const isReplay = status.ingest_mode === "replay";

  return (
    <div className="flex items-center justify-between px-4 py-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono">
      <div className="flex items-center gap-3">
        <span className="text-slate-400 flex items-center gap-1.5">
          {isReplay ? (
            <FastForward className="w-4 h-4 text-purple-400" />
          ) : (
            <Radio className="w-4 h-4 text-emerald-400" />
          )}
          Mode:
        </span>
        <Badge
          variant="outline"
          className={cn(
            "text-[11px] font-mono uppercase",
            isReplay
              ? "bg-purple-950/60 text-purple-300 border-purple-800/60"
              : "bg-emerald-950/60 text-emerald-300 border-emerald-800/60"
          )}
        >
          {status.ingest_mode}
        </Badge>

        {isReplay && (
          <span className="text-slate-300">
            Speed: <strong className="text-purple-300 font-bold">{status.replay_speed}x</strong>
          </span>
        )}

        <span className="text-slate-500">|</span>

        <span className="text-slate-400">Status:</span>
        <span className={cn(
          "font-semibold",
          status.ingest_running ? "text-emerald-400" : "text-slate-400"
        )}>
          {status.ingest_running ? "DISPATCHING" : "IDLE"}
        </span>
      </div>

      <div className="hidden sm:flex items-center gap-4 text-slate-400 text-[11px]">
        <div>
          Events Ingested: <strong className="text-slate-200">{status.events_count}</strong>
        </div>
        <div>
          Signals Generated: <strong className="text-purple-300">{status.signals_count}</strong>
        </div>
        <div>
          Active Threshold: <strong className="text-blue-400">{status.budget_threshold.toFixed(2)}</strong>
        </div>
      </div>
    </div>
  );
}
