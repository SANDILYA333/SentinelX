"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { Loader2 } from "lucide-react";

interface LoadingStateProps {
  message?: string;
  className?: string;
}

export function LoadingState({
  message = "Loading real-time telemetry...",
  className,
}: LoadingStateProps) {
  return (
    <div
      className={cn(
        "p-12 flex flex-col items-center justify-center text-center space-y-3",
        className
      )}
    >
      <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
      <p className="text-xs font-mono text-slate-400">{message}</p>
    </div>
  );
}

export function SkeletonCard({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "p-5 rounded-xl border border-slate-800 bg-slate-900/40 animate-pulse space-y-3",
        className
      )}
    >
      <div className="h-4 bg-slate-800 rounded w-1/3" />
      <div className="h-8 bg-slate-800 rounded w-2/3" />
      <div className="h-3 bg-slate-800 rounded w-1/2" />
    </div>
  );
}
