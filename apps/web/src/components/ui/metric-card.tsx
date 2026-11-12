"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { type LucideIcon } from "lucide-react";

interface MetricCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  trend?: string;
  trendDirection?: "up" | "down" | "neutral";
  icon?: LucideIcon;
  variant?: "default" | "critical" | "warning" | "success" | "info";
  className?: string;
}

export function MetricCard({
  label,
  value,
  subValue,
  trend,
  trendDirection = "neutral",
  icon: Icon,
  variant = "default",
  className,
}: MetricCardProps) {
  let borderStyle = "border-slate-800 bg-slate-900/60";
  let iconColor = "text-slate-400";
  let valueColor = "text-slate-100";

  switch (variant) {
    case "critical":
      borderStyle = "border-red-900/60 bg-red-950/20";
      iconColor = "text-red-400";
      valueColor = "text-red-400";
      break;
    case "warning":
      borderStyle = "border-amber-900/60 bg-amber-950/20";
      iconColor = "text-amber-400";
      valueColor = "text-amber-400";
      break;
    case "success":
      borderStyle = "border-emerald-900/60 bg-emerald-950/20";
      iconColor = "text-emerald-400";
      valueColor = "text-emerald-400";
      break;
    case "info":
      borderStyle = "border-sky-900/60 bg-sky-950/20";
      iconColor = "text-sky-400";
      valueColor = "text-sky-400";
      break;
  }

  return (
    <div
      className={cn(
        "p-4 rounded-xl border flex flex-col justify-between transition-all",
        borderStyle,
        className
      )}
    >
      <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
        <span>{label}</span>
        {Icon && <Icon className={cn("w-4 h-4", iconColor)} />}
      </div>

      <div className="mt-2 flex items-baseline justify-between gap-2">
        <span className={cn("text-2xl font-bold tracking-tight font-mono", valueColor)}>
          {value}
        </span>
        {trend && (
          <span
            className={cn(
              "text-[11px] font-mono font-semibold px-1.5 py-0.5 rounded",
              trendDirection === "up"
                ? "bg-emerald-950/60 text-emerald-400 border border-emerald-800/60"
                : trendDirection === "down"
                ? "bg-rose-950/60 text-rose-400 border border-rose-800/60"
                : "bg-slate-800 text-slate-400 border border-slate-700/60"
            )}
          >
            {trend}
          </span>
        )}
      </div>

      {subValue && (
        <div className="mt-1 text-[11px] text-slate-500 font-mono truncate">
          {subValue}
        </div>
      )}
    </div>
  );
}
