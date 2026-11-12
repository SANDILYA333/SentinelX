"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { AlertOctagon, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ErrorStateProps {
  title?: string;
  message?: string;
  error?: Error | unknown;
  onRetry?: () => void;
  className?: string;
}

export function ErrorState({
  title = "Telemetry & API Request Failed",
  message = "Unable to communicate with SentinelX engine service.",
  error,
  onRetry,
  className,
}: ErrorStateProps) {
  const errorDetails =
    error instanceof Error
      ? error.message
      : typeof error === "string"
      ? error
      : null;

  return (
    <div
      className={cn(
        "p-6 rounded-xl border border-rose-900/60 bg-rose-950/20 flex flex-col items-center justify-center text-center",
        className
      )}
    >
      <div className="w-10 h-10 rounded-xl bg-rose-900/40 border border-rose-700/60 flex items-center justify-center text-rose-400 mb-3">
        <AlertOctagon className="w-5 h-5" />
      </div>
      <h3 className="text-sm font-semibold text-rose-200 tracking-tight">{title}</h3>
      <p className="text-xs text-rose-300/80 mt-1 max-w-md">{message}</p>
      {errorDetails && (
        <div className="mt-3 p-2 rounded bg-black/40 border border-rose-900/40 font-mono text-[11px] text-rose-400 max-w-md truncate">
          {errorDetails}
        </div>
      )}
      {onRetry && (
        <Button
          variant="outline"
          size="sm"
          onClick={onRetry}
          className="mt-4 gap-1.5 font-mono text-xs border-rose-800 text-rose-300 hover:bg-rose-950/50"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Retry Request
        </Button>
      )}
    </div>
  );
}
