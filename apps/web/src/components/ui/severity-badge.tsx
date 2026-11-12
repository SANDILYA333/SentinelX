"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { getSeverityStyle, type SeverityLevel } from "@/lib/theme";

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  className?: string;
  showDot?: boolean;
}

export function SeverityBadge({
  severity,
  className,
  showDot = false,
}: SeverityBadgeProps) {
  const norm = (severity || "low").toLowerCase() as SeverityLevel;
  const style = getSeverityStyle(norm);

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-mono text-[11px] font-bold uppercase tracking-wider border select-none",
        style.badge,
        className
      )}
    >
      {showDot && (
        <span
          className={cn(
            "w-1.5 h-1.5 rounded-full shrink-0",
            norm === "critical"
              ? "bg-red-400 animate-pulse"
              : norm === "high"
              ? "bg-orange-400"
              : norm === "medium"
              ? "bg-amber-400"
              : "bg-blue-400"
          )}
        />
      )}
      <span>{severity}</span>
    </span>
  );
}
