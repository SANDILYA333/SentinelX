"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchAssets } from "@/lib/api";
import type { AssetResponse } from "@contracts/index";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Cpu,
  Search,
  Server,
  ShieldAlert,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface AssetInventoryModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function AssetInventoryModal({ isOpen, onClose }: AssetInventoryModalProps) {
  const [filterZone, setFilterZone] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const { data: assets = [], isLoading } = useQuery<AssetResponse[]>({
    queryKey: ["assets"],
    queryFn: fetchAssets,
    enabled: isOpen,
    staleTime: 60000,
  });

  if (!isOpen) return null;

  const filteredAssets = assets.filter((asset) => {
    if (filterZone !== "all" && asset.zone?.toLowerCase() !== filterZone.toLowerCase()) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const ipList = Array.isArray(asset.ips) ? asset.ips : Object.values(asset.ips || {});
      const matchName = asset.name.toLowerCase().includes(q);
      const matchIp = ipList.some((ip) => String(ip).toLowerCase().includes(q));
      const matchRole = (asset.role || "").toLowerCase().includes(q);
      const matchZone = (asset.zone || "").toLowerCase().includes(q);
      if (!matchName && !matchIp && !matchRole && !matchZone) return false;
    }
    return true;
  });

  const getZoneBadge = (zone: string) => {
    const zu = (zone || "unknown").toUpperCase();
    if (zu === "IT") return "bg-sky-950/60 text-sky-400 border-sky-800/60";
    if (zu === "DMZ") return "bg-purple-950/60 text-purple-300 border-purple-800/60";
    if (zu === "OT") return "bg-rose-950/60 text-rose-300 border-rose-800/60";
    if (zu === "MGMT") return "bg-emerald-950/60 text-emerald-400 border-emerald-800/60";
    return "bg-slate-900 text-slate-400 border-slate-700";
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="fixed inset-0" onClick={onClose} aria-hidden="true" />
      <div className="relative z-10 w-full max-w-4xl max-h-[85vh] rounded-2xl bg-slate-950 border border-slate-800 shadow-2xl flex flex-col font-mono text-xs overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100">Cyber-Physical Asset Inventory</h2>
              <p className="text-[11px] text-slate-400 font-sans">
                Authoritative network topology across IT, DMZ, OT, and Management zones.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Filter bar */}
        <div className="p-3 border-b border-slate-800/80 bg-slate-900/40 flex flex-wrap items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 text-[11px]">Zone:</span>
            {["all", "it", "dmz", "ot", "mgmt"].map((z) => (
              <button
                key={z}
                type="button"
                onClick={() => setFilterZone(z)}
                className={cn(
                  "px-2.5 py-1 rounded text-[11px] font-semibold uppercase transition-colors cursor-pointer",
                  filterZone === z
                    ? "bg-blue-600 text-white"
                    : "bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800"
                )}
              >
                {z}
              </button>
            ))}
          </div>

          <div className="relative w-64">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search assets, IPs, roles..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        {/* Asset list */}
        <ScrollArea className="flex-1 p-4">
          {isLoading ? (
            <div className="p-12 text-center text-slate-500">Loading asset catalog...</div>
          ) : filteredAssets.length === 0 ? (
            <div className="p-12 text-center text-slate-500">No assets match criteria.</div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {filteredAssets.map((asset) => {
                const isDecoy = asset.is_decoy;
                const isCritical = asset.process_critical;
                return (
                  <div
                    key={asset.name}
                    className={cn(
                      "p-3.5 rounded-xl border bg-slate-900/50 flex flex-col justify-between space-y-2 transition-colors",
                      isDecoy
                        ? "border-purple-800/60 bg-purple-950/20"
                        : isCritical
                        ? "border-rose-800/60 bg-rose-950/20"
                        : "border-slate-800 hover:border-slate-700"
                    )}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2">
                        {isCritical ? (
                          <Cpu className="w-4 h-4 text-rose-400 shrink-0" />
                        ) : isDecoy ? (
                          <ShieldAlert className="w-4 h-4 text-purple-400 shrink-0" />
                        ) : (
                          <Server className="w-4 h-4 text-blue-400 shrink-0" />
                        )}
                        <span className="font-bold text-slate-200">{asset.name}</span>
                      </div>
                      <Badge variant="outline" className={cn("text-[10px] uppercase font-bold", getZoneBadge(asset.zone))}>
                        {asset.zone}
                      </Badge>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400">
                      <div>
                        IPs: <strong className="text-slate-300">{(Array.isArray(asset.ips) ? asset.ips : Object.values(asset.ips || {})).join(", ") || "N/A"}</strong>
                      </div>
                      <div>
                        Role: <strong className="text-slate-300">{asset.role}</strong>
                      </div>
                      <div>
                        Criticality:{" "}
                        <strong className={isCritical ? "text-rose-400 font-bold" : "text-slate-300"}>
                          {isCritical ? "PROCESS CRITICAL" : String(asset.criticality || "standard")}
                        </strong>
                      </div>
                      <div>
                        Type:{" "}
                        <strong className={isDecoy ? "text-purple-400 font-bold" : "text-slate-300"}>
                          {isDecoy ? "HIGH-INTERACTION DECOY" : "Production Host"}
                        </strong>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </ScrollArea>
      </div>
    </div>
  );
}
