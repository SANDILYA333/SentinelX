"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  FlaskConical,
  GitGraph,
  Menu,
  Presentation,
  Radio,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import { useEventStore } from "@/lib/store";
import { cn } from "@/lib/utils";
import { AssetInventoryModal } from "@/components/asset-inventory-modal";

interface NavGroup {
  group: string;
  items: {
    label: string;
    href: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string;
  }[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    group: "Overview",
    items: [
      { label: "Dashboard", href: "/", icon: Activity },
    ],
  },
  {
    group: "Investigation",
    items: [
      { label: "Incidents", href: "/incidents", icon: AlertTriangle },
      { label: "Signals", href: "/signals", icon: Radio },
      { label: "Attack Graph", href: "/graph", icon: GitGraph },
    ],
  },
  {
    group: "Threat Intelligence",
    items: [
      { label: "Deception & Decoys", href: "/deception", icon: ShieldAlert },
      { label: "Response Safety Guard", href: "/deception?tab=guard", icon: ShieldCheck },
    ],
  },
  {
    group: "Validation",
    items: [
      { label: "Detection Evaluation", href: "/eval", icon: FlaskConical },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const { presenterMode, togglePresenterMode, status, incidents } = useEventStore();
  const [isAssetModalOpen, setIsAssetModalOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const activeIncidentsCount = incidents.filter((i) => i.score >= 0.5).length;

  const isLinkActive = (href: string) => {
    if (href === "/") return pathname === "/";
    if (href.includes("?tab=guard")) {
      return pathname === "/deception";
    }
    return pathname.startsWith(href.split("?")[0]);
  };

  return (
    <>
      {/* Mobile top toggle bar */}
      <div className="md:hidden fixed top-0 left-0 right-0 h-14 bg-slate-950 border-b border-slate-800 flex items-center justify-between px-4 z-40">
        <div className="flex items-center gap-2 font-bold text-slate-100 text-sm">
          <Shield className="w-5 h-5 text-blue-400" />
          <span>SentinelX</span>
        </div>
        <button
          type="button"
          onClick={() => setMobileOpen(!mobileOpen)}
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300"
          aria-label="Toggle navigation menu"
        >
          {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </div>

      {/* Backdrop for mobile */}
      {mobileOpen && (
        <div
          className="md:hidden fixed inset-0 z-40 bg-black/60 backdrop-blur-xs"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar container */}
      <aside
        className={cn(
          "w-64 border-r border-slate-800 bg-slate-950/95 flex flex-col shrink-0 min-h-screen transition-transform z-40",
          "fixed md:static inset-y-0 left-0",
          mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        )}
      >
        {/* Brand header */}
        <div className="h-16 flex items-center justify-between px-5 border-b border-slate-800 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shrink-0">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold tracking-tight text-slate-100 flex items-center gap-1.5 leading-none">
                <span>SentinelX</span>
                <span className="text-[9px] font-semibold uppercase px-1 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800/60 font-mono">
                  v1.0
                </span>
              </div>
              <p className="text-[10px] text-slate-400 mt-1">IT/OT Threat & Safety</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setMobileOpen(false)}
            className="md:hidden p-1 text-slate-400 hover:text-slate-200"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Categorized Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-5 overflow-y-auto font-sans">
          {NAV_GROUPS.map((grp) => (
            <div key={grp.group} className="space-y-1">
              <div className="px-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                {grp.group}
              </div>
              <div className="space-y-0.5">
                {grp.items.map((item) => {
                  const Icon = item.icon;
                  const active = isLinkActive(item.href);
                  return (
                    <Link
                      key={item.label}
                      href={item.href}
                      onClick={() => setMobileOpen(false)}
                      className={cn(
                        "flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all group",
                        active
                          ? "bg-slate-800 text-slate-100 shadow-sm border border-slate-700/60"
                          : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
                      )}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <Icon
                          className={cn(
                            "w-4 h-4 shrink-0 transition-colors",
                            active ? "text-blue-400" : "text-slate-500 group-hover:text-slate-300"
                          )}
                        />
                        <span className="truncate">{item.label}</span>
                      </div>
                      {item.label === "Incidents" && activeIncidentsCount > 0 && (
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded-full bg-red-950 text-red-400 border border-red-800/60 animate-pulse">
                          {activeIncidentsCount}
                        </span>
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}

          {/* Asset Inventory Shortcut */}
          <div className="pt-2 border-t border-slate-900">
            <button
              type="button"
              onClick={() => setIsAssetModalOpen(true)}
              className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium text-slate-400 hover:bg-slate-900 hover:text-slate-200 transition-colors cursor-pointer border border-transparent hover:border-slate-800"
            >
              <div className="flex items-center gap-2.5">
                <Server className="w-4 h-4 text-slate-500" />
                <span>Asset Topology</span>
              </div>
              <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                14 Hosts
              </span>
            </button>
          </div>
        </nav>

        {/* Footer controls & status */}
        <div className="p-3.5 border-t border-slate-800 text-xs text-slate-400 space-y-2.5 bg-slate-950 shrink-0 font-mono">
          <button
            type="button"
            onClick={togglePresenterMode}
            className={cn(
              "w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg border text-[11px] font-medium transition-colors cursor-pointer",
              presenterMode
                ? "bg-purple-950/60 border-purple-800/80 text-purple-300"
                : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800"
            )}
          >
            <div className="flex items-center gap-2">
              <Presentation className="w-3.5 h-3.5 text-purple-400" />
              <span>Presenter Mode</span>
            </div>
            <span
              className={cn(
                "text-[10px] uppercase font-mono px-1 py-0.5 rounded",
                presenterMode
                  ? "bg-purple-900 text-purple-200"
                  : "bg-slate-800 text-slate-500"
              )}
            >
              {presenterMode ? "ON" : "OFF"}
            </span>
          </button>

          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-500">Pipeline Stream</span>
            {status === "open" && (
              <span className="text-emerald-400 flex items-center gap-1.5 font-bold">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                ONLINE
              </span>
            )}
            {status === "connecting" && (
              <span className="text-amber-400 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping" />
                CONNECTING
              </span>
            )}
            {status === "closed" && (
              <span className="text-rose-400 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                OFFLINE
              </span>
            )}
          </div>
          <div className="text-[10px] text-slate-600 truncate">
            Autonomous IT/OT Defense
          </div>
        </div>
      </aside>

      {/* Asset Inventory Modal */}
      <AssetInventoryModal
        isOpen={isAssetModalOpen}
        onClose={() => setIsAssetModalOpen(false)}
      />
    </>
  );
}
