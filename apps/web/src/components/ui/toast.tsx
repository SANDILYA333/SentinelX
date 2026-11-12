"use client";

import React, { createContext, useCallback, useContext, useState } from "react";
import { cn } from "@/lib/utils";
import { CheckCircle2, AlertTriangle, AlertOctagon, Info, X } from "lucide-react";

export type ToastType = "success" | "error" | "warning" | "info";

export interface ToastMessage {
  id: string;
  type: ToastType;
  title: string;
  description?: string;
  duration?: number;
}

interface ToastContextType {
  toast: (options: Omit<ToastMessage, "id">) => void;
  success: (title: string, description?: string) => void;
  error: (title: string, description?: string) => void;
  warning: (title: string, description?: string) => void;
  info: (title: string, description?: string) => void;
}

const ToastContext = createContext<ToastContextType | null>(null);

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    // Fallback safe dummy logger if rendered outside provider
    return {
      toast: () => {},
      success: (t: string) => console.log(`[Toast Success] ${t}`),
      error: (t: string) => console.error(`[Toast Error] ${t}`),
      warning: (t: string) => console.warn(`[Toast Warning] ${t}`),
      info: (t: string) => console.info(`[Toast Info] ${t}`),
    };
  }
  return ctx;
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(
    (options: Omit<ToastMessage, "id">) => {
      const id = `toast_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
      const newToast: ToastMessage = {
        id,
        duration: 4000,
        ...options,
      };

      setToasts((prev) => [...prev, newToast]);

      if (newToast.duration && newToast.duration > 0) {
        setTimeout(() => {
          removeToast(id);
        }, newToast.duration);
      }
    },
    [removeToast]
  );

  const success = useCallback((title: string, description?: string) => {
    addToast({ type: "success", title, description });
  }, [addToast]);

  const error = useCallback((title: string, description?: string) => {
    addToast({ type: "error", title, description });
  }, [addToast]);

  const warning = useCallback((title: string, description?: string) => {
    addToast({ type: "warning", title, description });
  }, [addToast]);

  const info = useCallback((title: string, description?: string) => {
    addToast({ type: "info", title, description });
  }, [addToast]);

  return (
    <ToastContext.Provider value={{ toast: addToast, success, error, warning, info }}>
      {children}
      {/* Toast viewport container */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
        {toasts.map((t) => {
          let bgStyle = "bg-slate-900 border-slate-700 text-slate-100";
          let Icon = Info;
          let iconColor = "text-sky-400";

          switch (t.type) {
            case "success":
              bgStyle = "bg-slate-950 border-emerald-800/80 text-emerald-200 shadow-emerald-950/40";
              Icon = CheckCircle2;
              iconColor = "text-emerald-400";
              break;
            case "error":
              bgStyle = "bg-slate-950 border-rose-800/80 text-rose-200 shadow-rose-950/40";
              Icon = AlertOctagon;
              iconColor = "text-rose-400";
              break;
            case "warning":
              bgStyle = "bg-slate-950 border-amber-800/80 text-amber-200 shadow-amber-950/40";
              Icon = AlertTriangle;
              iconColor = "text-amber-400";
              break;
            case "info":
              bgStyle = "bg-slate-950 border-blue-800/80 text-blue-200 shadow-blue-950/40";
              Icon = Info;
              iconColor = "text-blue-400";
              break;
          }

          return (
            <div
              key={t.id}
              className={cn(
                "pointer-events-auto p-3.5 rounded-xl border shadow-xl flex items-start gap-3 backdrop-blur-md animate-in slide-in-from-bottom-2 duration-150 font-mono text-xs",
                bgStyle
              )}
            >
              <Icon className={cn("w-4 h-4 shrink-0 mt-0.5", iconColor)} />
              <div className="flex-1 min-w-0">
                <div className="font-bold text-slate-100">{t.title}</div>
                {t.description && (
                  <div className="text-[11px] text-slate-400 font-sans mt-0.5 leading-snug">
                    {t.description}
                  </div>
                )}
              </div>
              <button
                type="button"
                onClick={() => removeToast(t.id)}
                className="text-slate-400 hover:text-slate-200 p-0.5 rounded shrink-0 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
