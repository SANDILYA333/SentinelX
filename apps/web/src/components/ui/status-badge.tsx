"use client";

import React from "react";
import { cn } from "@/lib/utils";

export type StatusVariant =
  | "live"
  | "connecting"
  | "offline"
  | "idle"
  | "stale"
  | "active"
  | "open"
  | "closed"
  | "suppressed"
  | "resolved"
  | "allow"
  | "deny"
  | "needs_human";

interface StatusBadgeProps {
  status: StatusVariant | string;
  label?: string;
  className?: string;
  showDot?: boolean;
}

export function StatusBadge({
  status,
  label,
  className,
  showDot = true,
}: StatusBadgeProps) {
  const normalized = (status || "").toLowerCase() as StatusVariant;
  const displayLabel = label || status;

  let badgeStyle = "bg-slate-900 text-slate-300 border-slate-700";
  let dotStyle = "bg-slate-400";
  let pulse = false;

  switch (normalized) {
    case "live":
    case "open":
      badgeStyle = "bg-emerald-950/60 text-emerald-400 border-emerald-800/60";
      dotStyle = "bg-emerald-400";
      pulse = true;
      break;
    case "connecting":
      badgeStyle = "bg-amber-950/60 text-amber-400 border-amber-800/60";
      dotStyle = "bg-amber-400";
      pulse = true;
      break;
    case "offline":
    case "closed":
      badgeStyle = "bg-rose-950/60 text-rose-300 border-rose-800/60";
      dotStyle = "bg-rose-500";
      break;
    case "idle":
      badgeStyle = "bg-sky-950/60 text-sky-400 border-sky-800/60";
      dotStyle = "bg-sky-400";
      break;
    case "stale":
      badgeStyle = "bg-amber-950/60 text-amber-300 border-amber-800/60";
      dotStyle = "bg-amber-400";
      break;
    case "active":
      badgeStyle = "bg-red-950/60 text-red-400 border-red-800/60";
      dotStyle = "bg-red-400";
      pulse = true;
      break;
    case "resolved":
      badgeStyle = "bg-emerald-950/60 text-emerald-300 border-emerald-800/60";
      dotStyle = "bg-emerald-400";
      break;
    case "allow":
      badgeStyle = "bg-emerald-950/80 text-emerald-300 border-emerald-700";
      dotStyle = "bg-emerald-400";
      break;
    case "deny":
      badgeStyle = "bg-red-950/80 text-red-300 border-red-700 font-bold";
      dotStyle = "bg-red-500";
      break;
    case "needs_human":
      badgeStyle = "bg-amber-950/80 text-amber-300 border-amber-700";
      dotStyle = "bg-amber-400";
      pulse = true;
      break;
  }

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-xs font-mono uppercase tracking-wider font-semibold select-none",
        badgeStyle,
        className
      )}
    >
      {showDot && (
        <span className="relative flex h-2 w-2 shrink-0">
          {pulse && (
            <span
              className={cn(
                "animate-ping absolute inline-flex h-full w-full rounded-full opacity-75",
                dotStyle
              )}
            />
          )}
          <span className={cn("relative inline-flex rounded-full h-2 w-2", dotStyle)} />
        </span>
      )}
      <span>{displayLabel}</span>
    </span>
  );
}
