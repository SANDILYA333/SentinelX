"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  FlaskConical,
  GitGraph,
  Shield,
  ShieldAlert,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { label: "Overview", href: "/", icon: Activity },
  { label: "Incidents", href: "/incidents", icon: AlertTriangle },
  { label: "Attack Graph", href: "/graph", icon: GitGraph },
  { label: "Deception & Guard", href: "/deception", icon: ShieldAlert },
  { label: "Evaluation", href: "/eval", icon: FlaskConical },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-950/80 flex flex-col shrink-0 min-h-screen">
      {/* Brand header */}
      <div className="h-16 flex items-center gap-3 px-6 border-b border-slate-800">
        <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="font-bold tracking-tight text-slate-100 flex items-center gap-1.5">
            <span>SentinelX</span>
            <span className="text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800/60">
              v1.0
            </span>
          </div>
          <p className="text-[11px] text-slate-400">IT/OT Threat & Deception</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
                isActive
                  ? "bg-slate-800 text-slate-100 shadow-sm"
                  : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
              )}
            >
              <Icon className={cn("w-4 h-4", isActive ? "text-blue-400" : "text-slate-400")} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {/* Footer status */}
      <div className="p-4 border-t border-slate-800 text-xs text-slate-500">
        <div className="flex items-center justify-between">
          <span>Engine Core</span>
          <span className="text-emerald-400 font-mono text-[11px]">Ready</span>
        </div>
        <div className="mt-1 text-[11px] text-slate-500">Phase 0 Foundation</div>
      </div>
    </aside>
  );
}
