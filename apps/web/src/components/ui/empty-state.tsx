"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { type LucideIcon, Inbox } from "lucide-react";
import { Button } from "@/components/ui/button";

interface EmptyStateProps {
  title: string;
  description: string;
  icon?: LucideIcon;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export function EmptyState({
  title,
  description,
  icon: Icon = Inbox,
  actionLabel,
  onAction,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "p-8 rounded-xl border border-slate-800 bg-slate-900/40 flex flex-col items-center justify-center text-center",
        className
      )}
    >
      <div className="w-12 h-12 rounded-xl bg-slate-800/60 border border-slate-700/60 flex items-center justify-center text-slate-400 mb-3">
        <Icon className="w-6 h-6" />
      </div>
      <h3 className="text-sm font-semibold text-slate-200 tracking-tight">{title}</h3>
      <p className="text-xs text-slate-400 mt-1 max-w-sm">{description}</p>
      {actionLabel && onAction && (
        <Button
          variant="outline"
          size="sm"
          onClick={onAction}
          className="mt-4 font-mono text-xs border-slate-700 hover:border-slate-600 bg-slate-900/60"
        >
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
