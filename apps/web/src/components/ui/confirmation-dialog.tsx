"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { AlertTriangle, X } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ConfirmationDialogProps {
  isOpen: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: "danger" | "warning" | "default";
  isLoading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: React.ReactNode;
}

export function ConfirmationDialog({
  isOpen,
  title,
  description,
  confirmLabel = "Confirm Action",
  cancelLabel = "Cancel",
  variant = "default",
  isLoading = false,
  onConfirm,
  onCancel,
  children,
}: ConfirmationDialogProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="fixed inset-0" onClick={onCancel} aria-hidden="true" />
      <div className="relative z-10 w-full max-w-md rounded-2xl bg-slate-950 border border-slate-800 shadow-2xl p-6 font-mono text-xs text-slate-200">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div
              className={cn(
                "w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border",
                variant === "danger"
                  ? "bg-red-950/60 border-red-800 text-red-400"
                  : variant === "warning"
                  ? "bg-amber-950/60 border-amber-800 text-amber-400"
                  : "bg-blue-950/60 border-blue-800 text-blue-400"
              )}
            >
              <AlertTriangle className="w-4 h-4" />
            </div>
            <h3 className="text-sm font-bold text-slate-100">{title}</h3>
          </div>
          <button
            type="button"
            onClick={onCancel}
            className="text-slate-400 hover:text-slate-200 p-1"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="mt-3 text-xs text-slate-400 font-sans leading-relaxed">
          {description}
        </p>

        {children && <div className="mt-4">{children}</div>}

        <div className="mt-6 flex items-center justify-end gap-2.5 pt-4 border-t border-slate-800/80">
          <Button
            variant="outline"
            size="sm"
            onClick={onCancel}
            disabled={isLoading}
            className="border-slate-800 text-slate-300 hover:bg-slate-900"
          >
            {cancelLabel}
          </Button>
          <Button
            variant={variant === "danger" ? "destructive" : "default"}
            size="sm"
            onClick={onConfirm}
            disabled={isLoading}
            className={cn(
              "font-bold",
              variant === "danger"
                ? "bg-red-600 hover:bg-red-700 text-white"
                : variant === "warning"
                ? "bg-amber-600 hover:bg-amber-700 text-white"
                : "bg-blue-600 hover:bg-blue-700 text-white"
            )}
          >
            {isLoading ? "Processing..." : confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
