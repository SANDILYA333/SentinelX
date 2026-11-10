"use client";

import React, { useEffect, useRef } from "react";
import type { TimelineEvent } from "@contracts/index";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { getDomainStyle } from "@/lib/theme";
import {
  ChevronLeft,
  ChevronRight,
  Clock,
  FastForward,
  Pause,
  Play,
  RotateCcw,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface AttackTimelineProps {
  events: TimelineEvent[];
  currentIndex: number;
  isPlaying: boolean;
  playbackSpeed: number;
  onPlayPause: () => void;
  onStepForward: () => void;
  onStepBackward: () => void;
  onRestart: () => void;
  onSelectIndex: (index: number) => void;
  onSpeedChange: (speed: number) => void;
}

const PLAYBACK_SPEEDS = [0.5, 1, 2, 5, 10];

export function AttackTimeline({
  events,
  currentIndex,
  isPlaying,
  playbackSpeed,
  onPlayPause,
  onStepForward,
  onStepBackward,
  onRestart,
  onSelectIndex,
  onSpeedChange,
}: AttackTimelineProps) {
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const activeItemRef = useRef<HTMLButtonElement>(null);

  // Auto-scroll the timeline list when active item changes
  useEffect(() => {
    if (activeItemRef.current && scrollContainerRef.current) {
      const container = scrollContainerRef.current;
      const item = activeItemRef.current;
      const itemLeft = item.offsetLeft;
      const itemWidth = item.offsetWidth;
      const containerWidth = container.offsetWidth;

      container.scrollTo({
        left: itemLeft - containerWidth / 2 + itemWidth / 2,
        behavior: "smooth",
      });
    }
  }, [currentIndex]);

  const activeEvent = currentIndex >= 0 && currentIndex < events.length ? events[currentIndex] : null;

  return (
    <div className="flex flex-col bg-slate-950/95 border border-slate-800 rounded-2xl shadow-2xl backdrop-blur-md overflow-hidden shrink-0">
      {/* Playback Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 border-b border-slate-800/80 bg-slate-900/60 font-mono text-xs">
        {/* Playback buttons */}
        <div className="flex items-center gap-1.5">
          <Button
            variant="ghost"
            size="icon"
            onClick={onRestart}
            title="Restart Replay"
            className="h-8 w-8 text-slate-400 hover:text-slate-100 hover:bg-slate-800"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            onClick={onStepBackward}
            disabled={currentIndex <= 0}
            title="Step Backward (Previous Event)"
            className="h-8 w-8 text-slate-400 hover:text-slate-100 hover:bg-slate-800 disabled:opacity-30"
          >
            <ChevronLeft className="w-4 h-4" />
          </Button>

          <Button
            variant="default"
            size="sm"
            onClick={onPlayPause}
            className={cn(
              "h-8 px-3 text-xs font-bold gap-1.5 transition-all shadow-md",
              isPlaying
                ? "bg-amber-600 hover:bg-amber-500 text-amber-50 shadow-amber-900/30"
                : "bg-blue-600 hover:bg-blue-500 text-blue-50 shadow-blue-900/30"
            )}
          >
            {isPlaying ? (
              <>
                <Pause className="w-3.5 h-3.5 fill-current" /> Pause
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" /> Play
              </>
            )}
          </Button>

          <Button
            variant="ghost"
            size="icon"
            onClick={onStepForward}
            disabled={currentIndex >= events.length - 1}
            title="Step Forward (Next Event)"
            className="h-8 w-8 text-slate-400 hover:text-slate-100 hover:bg-slate-800 disabled:opacity-30"
          >
            <ChevronRight className="w-4 h-4" />
          </Button>
        </div>

        {/* Current Time and Scrubber Progress */}
        <div className="flex-1 flex items-center gap-3 min-w-[220px] max-w-xl mx-2">
          <span className="text-[11px] text-slate-400 shrink-0 flex items-center gap-1">
            <Clock className="w-3 h-3 text-blue-400" />
            {activeEvent ? new Date(activeEvent.timestamp).toLocaleTimeString() : "--:--:--"}
          </span>

          <input
            type="range"
            min={0}
            max={Math.max(0, events.length - 1)}
            value={Math.max(0, currentIndex)}
            onChange={(e) => onSelectIndex(Number(e.target.value))}
            className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-blue-500 focus:outline-hidden"
          />

          <span className="text-[11px] text-slate-400 shrink-0 tabular-nums">
            {events.length > 0 ? `${currentIndex + 1}/${events.length}` : "0/0"}
          </span>
        </div>

        {/* Speed Selector */}
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] text-slate-500 flex items-center gap-1">
            <FastForward className="w-3 h-3" /> Speed:
          </span>
          <div className="flex rounded-md bg-slate-950 p-0.5 border border-slate-800">
            {PLAYBACK_SPEEDS.map((spd) => (
              <button
                key={spd}
                onClick={() => onSpeedChange(spd)}
                className={cn(
                  "px-2 py-0.5 text-[10px] rounded transition-colors font-mono",
                  playbackSpeed === spd
                    ? "bg-blue-600 text-white font-bold"
                    : "text-slate-400 hover:text-slate-200"
                )}
              >
                {spd}x
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Chronological Event Cards Ribbon */}
      <div
        ref={scrollContainerRef}
        className="flex items-center gap-2.5 p-3 overflow-x-auto scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent select-none min-h-[96px]"
      >
        {events.length === 0 ? (
          <div className="w-full text-center text-xs text-slate-500 py-3 font-mono">
            No chronological timeline telemetry recorded for this incident.
          </div>
        ) : (
          events.map((ev, idx) => {
            const isActive = idx === currentIndex;
            const isPast = idx < currentIndex;
            const domainStyle = getDomainStyle(ev.category.includes("ot") ? "ot" : ev.category.includes("decoy") ? "decoy" : "it");

            const isOt = ev.category.includes("ot") || Boolean(ev.metadata?.ot);
            const isDecoy = ev.category.includes("decoy");

            return (
              <button
                key={ev.id}
                ref={isActive ? activeItemRef : undefined}
                onClick={() => onSelectIndex(idx)}
                className={cn(
                  "relative flex flex-col text-left p-2.5 rounded-xl border font-mono transition-all shrink-0 w-64",
                  isActive
                    ? "bg-slate-900 border-blue-500 ring-2 ring-blue-500/50 shadow-[0_0_15px_rgba(59,130,246,0.4)]"
                    : isPast
                    ? "bg-slate-950/80 border-slate-800/80 text-slate-300 hover:border-slate-700"
                    : "bg-slate-950/40 border-slate-900 text-slate-600 opacity-60 hover:opacity-100 hover:border-slate-800"
                )}
              >
                {/* Step indicator pill */}
                <div className="flex items-center justify-between gap-1 mb-1">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span
                      className={cn(
                        "w-4 h-4 rounded-full text-[9px] flex items-center justify-center font-bold",
                        isActive
                          ? "bg-blue-500 text-white animate-pulse"
                          : isPast
                          ? "bg-slate-800 text-slate-400"
                          : "bg-slate-900 text-slate-600"
                      )}
                    >
                      {idx + 1}
                    </span>

                    <Badge
                      variant="outline"
                      className={cn(
                        "text-[9px] px-1 py-0",
                        isOt
                          ? "text-rose-400 border-rose-800 bg-rose-950/40"
                          : isDecoy
                          ? "text-purple-400 border-purple-800 bg-purple-950/40"
                          : domainStyle.badge
                      )}
                    >
                      {ev.category.toUpperCase()}
                    </Badge>
                  </div>

                  <span className="text-[10px] text-slate-400 tabular-nums">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </span>
                </div>

                {/* Event Title */}
                <div
                  className={cn(
                    "text-xs font-semibold truncate",
                    isActive
                      ? "text-blue-300"
                      : isOt
                      ? "text-rose-300"
                      : isDecoy
                      ? "text-purple-300"
                      : "text-slate-200"
                  )}
                >
                  {ev.title}
                </div>

                {/* Subtitle / Actor Target */}
                <div className="text-[10px] text-slate-400 truncate mt-0.5">
                  {ev.source_node_id || "source"} → {ev.target_node_id || "target"}
                </div>

                {/* Status Indicator */}
                {isActive && (
                  <div className="mt-1 pt-1 border-t border-slate-800 flex items-center justify-between text-[9px] text-blue-400">
                    <span className="flex items-center gap-1">
                      <Zap className="w-2.5 h-2.5" /> ACTIVE EVENT
                    </span>
                    <span className="text-slate-400">{ev.evidence_reference}</span>
                  </div>
                )}
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
