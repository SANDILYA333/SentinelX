"use client";

import { useMemo, useState } from "react";
import {
  Clock,
  Flame,
  Radio,
  Search,
} from "lucide-react";
import { useEventStream } from "@/hooks/useEventStream";
import { useEventStore } from "@/lib/store";
import { cn } from "@/lib/utils";

const DETECTOR_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  rule: { bg: "bg-purple-950/60", text: "text-purple-300", border: "border-purple-800/60" },
  baseline: { bg: "bg-blue-950/60", text: "text-blue-300", border: "border-blue-800/60" },
  anomaly: { bg: "bg-amber-950/60", text: "text-amber-300", border: "border-amber-800/60" },
  graph: { bg: "bg-emerald-950/60", text: "text-emerald-300", border: "border-emerald-800/60" },
  deception: { bg: "bg-rose-950/60", text: "text-rose-300", border: "border-rose-800/60" },
};

export default function SignalsPage() {
  useEventStream();
  const { signals, status } = useEventStore();
  const [selectedDetector, setSelectedDetector] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const filteredSignals = useMemo(() => {
    return signals.filter((sig) => {
      if (selectedDetector !== "all" && sig.detector !== selectedDetector) {
        return false;
      }
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesTitle = sig.title.toLowerCase().includes(query);
        const matchesExplanation = sig.explanation.toLowerCase().includes(query);
        const matchesRule = sig.rule_id.toLowerCase().includes(query);
        const matchesEntity = sig.entities.some((e) => e.value.toLowerCase().includes(query));
        if (!matchesTitle && !matchesExplanation && !matchesRule && !matchesEntity) {
          return false;
        }
      }
      return true;
    });
  }, [signals, selectedDetector, searchQuery]);

  const stats = useMemo(() => {
    const counts = {
      total: signals.length,
      rule: 0,
      baseline: 0,
      anomaly: 0,
      graph: 0,
      deception: 0,
      honeytokens: 0,
    };
    for (const s of signals) {
      if (s.detector in counts) {
        counts[s.detector as keyof typeof counts]++;
      }
      const isHoney =
        Boolean(s.metadata?.confirmed_honeytoken) ||
        (Array.isArray(s.metadata?.tags) && s.metadata.tags.includes("confirmed_honeytoken"));
      if (isHoney) {
        counts.honeytokens++;
      }
    }
    return counts;
  }, [signals]);

  return (
    <div className="flex-1 p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <Radio className="w-6 h-6 text-blue-400 animate-pulse" />
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">Detection Signals</h1>
            <span
              className={cn(
                "text-xs px-2 py-0.5 rounded-full border flex items-center gap-1.5",
                status === "open"
                  ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/60"
                  : "bg-amber-950/60 text-amber-400 border-amber-800/60"
              )}
            >
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-full",
                  status === "open" ? "bg-emerald-400" : "bg-amber-400"
                )}
              />
              {status === "open" ? "Live Stream" : "Connecting..."}
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Real-time threat signals emitted independently by Rules, Baselines, Isolation Forest,
            Interaction Graph, and Deception engines.
          </p>
        </div>
      </div>

      {/* Summary Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
        <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/60">
          <div className="text-xs text-slate-400 font-medium">Total Signals</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{stats.total}</div>
        </div>
        <div className="p-3.5 rounded-lg border border-purple-900/40 bg-purple-950/20">
          <div className="text-xs text-purple-400 font-medium">Rules Engine</div>
          <div className="text-2xl font-bold text-purple-200 mt-1">{stats.rule}</div>
        </div>
        <div className="p-3.5 rounded-lg border border-blue-900/40 bg-blue-950/20">
          <div className="text-xs text-blue-400 font-medium">Baselines</div>
          <div className="text-2xl font-bold text-blue-200 mt-1">{stats.baseline}</div>
        </div>
        <div className="p-3.5 rounded-lg border border-amber-900/40 bg-amber-950/20">
          <div className="text-xs text-amber-400 font-medium">Anomaly (IF)</div>
          <div className="text-2xl font-bold text-amber-200 mt-1">{stats.anomaly}</div>
        </div>
        <div className="p-3.5 rounded-lg border border-emerald-900/40 bg-emerald-950/20">
          <div className="text-xs text-emerald-400 font-medium">Interaction Graph</div>
          <div className="text-2xl font-bold text-emerald-200 mt-1">{stats.graph}</div>
        </div>
        <div className="p-3.5 rounded-lg border border-rose-900/40 bg-rose-950/20">
          <div className="text-xs text-rose-400 font-medium flex items-center gap-1">
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>Deception</span>
          </div>
          <div className="text-2xl font-bold text-rose-200 mt-1 flex items-baseline gap-1.5">
            <span>{stats.deception}</span>
            {stats.honeytokens > 0 && (
              <span className="text-[10px] text-amber-300 font-semibold uppercase px-1 py-0.5 rounded bg-amber-950/80 border border-amber-800/80">
                {stats.honeytokens} Token
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="flex items-center gap-1.5 bg-slate-900/80 p-1 rounded-lg border border-slate-800 text-xs">
          {["all", "rule", "baseline", "anomaly", "graph", "deception"].map((det) => (
            <button
              key={det}
              type="button"
              onClick={() => setSelectedDetector(det)}
              className={cn(
                "px-3 py-1.5 rounded-md font-medium capitalize transition-colors",
                selectedDetector === det
                  ? "bg-slate-800 text-slate-100 shadow"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-850"
              )}
            >
              {det}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search signals by entity, title..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500/60"
          />
        </div>
      </div>

      {/* Signals Feed List */}
      <div className="space-y-2.5">
        {filteredSignals.length === 0 ? (
          <div className="border border-slate-800/80 rounded-xl bg-slate-900/30 p-12 text-center">
            <Radio className="w-10 h-10 text-slate-600 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-slate-300">No signals matching filter</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
              Active telemetry detectors are monitoring the event stream. Signals will appear here
              in real-time as deviations, rule violations, or decoy touches occur.
            </p>
          </div>
        ) : (
          filteredSignals.map((sig) => {
            const colors = DETECTOR_COLORS[sig.detector] || DETECTOR_COLORS.rule;
            const isConfirmedHoney =
              Boolean(sig.metadata?.confirmed_honeytoken) ||
              (Array.isArray(sig.metadata?.tags) && sig.metadata.tags.includes("confirmed_honeytoken"));

            return (
              <div
                key={sig.signal_id}
                className={cn(
                  "border rounded-xl p-4 bg-slate-900/50 hover:bg-slate-900/80 transition-colors flex flex-col md:flex-row gap-4 md:items-center justify-between",
                  isConfirmedHoney ? "border-amber-500/60 bg-amber-950/10" : "border-slate-800/80"
                )}
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={cn(
                        "text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-md border",
                        colors.bg,
                        colors.text,
                        colors.border
                      )}
                    >
                      {sig.detector}
                    </span>

                    {isConfirmedHoney && (
                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-md bg-amber-500/20 text-amber-300 border border-amber-500/50 flex items-center gap-1">
                        <Flame className="w-3 h-3 text-amber-400" />
                        Confirmed Honeytoken
                      </span>
                    )}

                    <span className="text-xs font-mono text-slate-400">{sig.rule_id}</span>

                    <span className="text-sm font-semibold text-slate-200 truncate">
                      {sig.title}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 font-mono leading-relaxed break-words">
                    {sig.explanation}
                  </p>

                  <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] text-slate-400">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-500" />
                      {new Date(sig.ts).toISOString().replace("T", " ").replace("Z", "")}
                    </span>

                    {sig.techniques && sig.techniques.length > 0 && (
                      <div className="flex items-center gap-1">
                        {sig.techniques.map((t) => (
                          <span
                            key={t.technique_id}
                            className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]"
                            title={t.name}
                          >
                            {t.technique_id}
                          </span>
                        ))}
                      </div>
                    )}

                    {sig.entities && sig.entities.length > 0 && (
                      <div className="flex items-center gap-1">
                        {sig.entities.slice(0, 3).map((e, idx) => (
                          <span
                            key={idx}
                            className="px-1.5 py-0.5 rounded bg-slate-800/60 text-slate-400 font-mono text-[10px]"
                          >
                            {e.type}:{e.value}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 self-end md:self-center shrink-0">
                  <div className="text-right">
                    <div className="text-[10px] text-slate-400 font-medium">Confidence</div>
                    <div className="text-sm font-bold text-slate-200">
                      {(sig.confidence * 100).toFixed(0)}%
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-[10px] text-slate-400 font-medium">Score</div>
                    <div className="text-sm font-bold text-blue-400">
                      {sig.score.toFixed(2)}
                    </div>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

