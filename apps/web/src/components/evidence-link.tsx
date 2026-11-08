"use client";

import React from "react";
import { useEvidenceDrawer } from "@/components/evidence-drawer";
import { ExternalLink, FileCode, Radio } from "lucide-react";
import { cn } from "@/lib/utils";

interface EvidenceLinkProps {
  id: string;
  type?: "event" | "signal";
  label?: string;
  className?: string;
  variant?: "badge" | "button" | "inline";
}

export function EvidenceLink({
  id,
  type,
  label,
  className,
  variant = "badge",
}: EvidenceLinkProps) {
  const { openEvidence } = useEvidenceDrawer();
  const isSignal = type === "signal" || id.startsWith("sig_");
  const displayLabel = label || id;

  if (variant === "button") {
    return (
      <button
        type="button"
        onClick={() => openEvidence(id, type)}
        className={cn(
          "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-medium transition-colors",
          isSignal
            ? "bg-purple-950/60 text-purple-300 border border-purple-800/60 hover:bg-purple-900/60"
            : "bg-sky-950/60 text-sky-300 border border-sky-800/60 hover:bg-sky-900/60",
          className
        )}
      >
        {isSignal ? (
          <Radio className="w-3 h-3 text-purple-400 shrink-0" />
        ) : (
          <FileCode className="w-3 h-3 text-sky-400 shrink-0" />
        )}
        <span className="truncate max-w-[140px]">{displayLabel}</span>
        <ExternalLink className="w-2.5 h-2.5 opacity-60" />
      </button>
    );
  }

  if (variant === "inline") {
    return (
      <button
        type="button"
        onClick={() => openEvidence(id, type)}
        className={cn(
          "inline-flex items-center gap-1 font-mono text-xs underline underline-offset-2 transition-colors",
          isSignal
            ? "text-purple-400 hover:text-purple-300"
            : "text-sky-400 hover:text-sky-300",
          className
        )}
      >
        <span>{displayLabel}</span>
        <ExternalLink className="w-2.5 h-2.5" />
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={() => openEvidence(id, type)}
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-mono transition-colors",
        isSignal
          ? "bg-purple-950/40 text-purple-300 border border-purple-800/50 hover:bg-purple-900/50 hover:border-purple-600"
          : "bg-slate-900 text-sky-400 border border-slate-800 hover:bg-slate-800 hover:border-slate-700",
        className
      )}
    >
      <span>{displayLabel}</span>
      <ExternalLink className="w-2.5 h-2.5 opacity-60" />
    </button>
  );
}

