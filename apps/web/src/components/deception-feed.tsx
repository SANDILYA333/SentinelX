"use client";

import { useMemo, useState } from "react";
import type { DeceptionActivity } from "@contracts/index";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  CheckCircle2,
  Cpu,
  Database,
  ExternalLink,
  Radio,
  Search,
  Server,
  ShieldAlert,
  Terminal,
  XCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface DeceptionFeedProps {
  activities: DeceptionActivity[];
  onSelectActivity?: (activity: DeceptionActivity) => void;
  selectedActivityId?: string | null;
}

export function DeceptionFeed({
  activities,
  onSelectActivity,
  selectedActivityId,
}: DeceptionFeedProps) {
  const [filterType, setFilterType] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const filteredActivities = useMemo(() => {
    return activities.filter((act) => {
      if (filterType === "ssh" && !act.decoy_type.includes("ssh") && !act.interaction_type.includes("ssh")) {
        return false;
      }
      if (filterType === "multi" && !act.decoy_type.includes("multi") && !act.interaction_type.includes("mysql") && !act.interaction_type.includes("probe")) {
        return false;
      }
      if (filterType === "ot" && !act.decoy_type.includes("plc") && !act.interaction_type.includes("modbus")) {
        return false;
      }

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesText =
          act.title.toLowerCase().includes(q) ||
          act.description.toLowerCase().includes(q) ||
          act.decoy_hostname?.toLowerCase().includes(q) ||
          act.src_ip?.toLowerCase().includes(q) ||
          String(act.metadata?.user || "").toLowerCase().includes(q) ||
          String(act.metadata?.cmdline || "").toLowerCase().includes(q);
        if (!matchesText) return false;
      }

      return true;
    });
  }, [activities, filterType, searchQuery]);

  const getInteractionIcon = (type: string) => {
    if (type.includes("command")) return Terminal;
    if (type.includes("mysql") || type.includes("db")) return Database;
    if (type.includes("modbus") || type.includes("plc")) return Cpu;
    if (type.includes("probe") || type.includes("discovery")) return Radio;
    return Server;
  };

  const getSeverityBadge = (sev: string) => {
    if (sev === "critical") return "bg-rose-950/80 text-rose-300 border-rose-700";
    if (sev === "high") return "bg-red-950/80 text-red-300 border-red-700";
    if (sev === "medium") return "bg-amber-950/80 text-amber-300 border-amber-700";
    return "bg-blue-950/80 text-blue-300 border-blue-700";
  };

  return (
    <div className="space-y-3 font-mono">
      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5">
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
          <button
            type="button"
            onClick={() => setFilterType("all")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filterType === "all" ? "bg-purple-600 text-white font-bold" : "text-slate-400 hover:text-slate-200"
            )}
          >
            All Canaries ({activities.length})
          </button>
          <button
            type="button"
            onClick={() => setFilterType("ssh")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filterType === "ssh" ? "bg-purple-600 text-white font-bold" : "text-slate-400 hover:text-slate-200"
            )}
          >
            SSH Honeypot
          </button>
          <button
            type="button"
            onClick={() => setFilterType("multi")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filterType === "multi" ? "bg-purple-600 text-white font-bold" : "text-slate-400 hover:text-slate-200"
            )}
          >
            Multi-Service
          </button>
          <button
            type="button"
            onClick={() => setFilterType("ot")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filterType === "ot" ? "bg-purple-600 text-white font-bold" : "text-slate-400 hover:text-slate-200"
            )}
          >
            Decoy PLC
          </button>
        </div>

        <div className="relative flex-1 max-w-xs">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search decoy telemetry..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-hidden focus:border-purple-500"
          />
        </div>
      </div>

      {/* Activity Items List */}
      <Card className="border-slate-800 bg-slate-900/60 shadow-lg">
        <CardContent className="p-0">
          <ScrollArea className="h-[460px]">
            {filteredActivities.length === 0 ? (
              <div className="p-16 text-center text-slate-500 space-y-2">
                <ShieldAlert className="w-8 h-8 mx-auto opacity-40 text-purple-400" />
                <p className="text-xs">No matching deception interactions found.</p>
                <p className="text-[11px] text-slate-600">
                  Deception telemetry triggers when adversary probes or authenticates against configured honeypots.
                </p>
              </div>
            ) : (
              <div className="divide-y divide-slate-800/60">
                {filteredActivities.map((act) => {
                  const Icon = getInteractionIcon(act.interaction_type);
                  const isSelected = selectedActivityId === act.activity_id;

                  return (
                    <div
                      key={act.activity_id}
                      onClick={() => onSelectActivity?.(act)}
                      className={cn(
                        "p-3.5 transition-all cursor-pointer flex flex-col gap-2 hover:bg-slate-800/40",
                        isSelected && "bg-purple-950/40 border-l-4 border-l-purple-500 pl-4",
                        act.outcome === "failure" ? "opacity-90" : ""
                      )}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <div className={cn(
                            "w-7 h-7 rounded-lg flex items-center justify-center border",
                            act.decoy_type.includes("plc")
                              ? "bg-rose-950/60 border-rose-800 text-rose-400"
                              : act.decoy_type.includes("ssh")
                              ? "bg-purple-950/60 border-purple-800 text-purple-400"
                              : "bg-blue-950/60 border-blue-800 text-blue-400"
                          )}>
                            <Icon className="w-3.5 h-3.5" />
                          </div>

                          <div>
                            <span className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                              {act.title}
                              {act.mitre_technique && (
                                <Badge variant="outline" className="text-[9px] px-1 py-0 bg-slate-950 border-slate-700 text-slate-400">
                                  {act.mitre_technique}
                                </Badge>
                              )}
                            </span>
                            <div className="flex items-center gap-2 text-[10px] text-slate-400">
                              <span>Decoy: <strong className="text-purple-300">{act.decoy_hostname}</strong></span>
                              <span>&bull;</span>
                              <span>Zone: <strong className="uppercase text-slate-300">{act.network_zone}</strong></span>
                              {act.src_ip && (
                                <>
                                  <span>&bull;</span>
                                  <span>Source: <strong className="text-red-400">{act.src_ip}</strong></span>
                                </>
                              )}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <Badge variant="outline" className={cn("text-[10px] uppercase font-bold py-0.5", getSeverityBadge(act.severity))}>
                            {act.severity}
                          </Badge>
                          <span className="text-[11px] text-slate-400">
                            {new Date(act.ts).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>

                      <p className="text-[11px] text-slate-300 leading-relaxed pl-9">
                        {act.description}
                      </p>

                      {/* Code / Command line highlight */}
                      {Boolean(act.metadata?.cmdline) && (
                        <div className="ml-9 p-1.5 rounded bg-slate-950/80 border border-slate-800 text-[11px] text-emerald-400 font-mono flex items-center gap-1.5">
                          <Terminal className="w-3 h-3 text-emerald-500 shrink-0" />
                          <span className="truncate">{String(act.metadata?.cmdline)}</span>
                        </div>
                      )}

                      <div className="flex items-center justify-between text-[10px] text-slate-500 pl-9 pt-1 border-t border-slate-800/40">
                        <div className="flex items-center gap-3">
                          <span className="flex items-center gap-1">
                            {act.outcome === "success" ? (
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <XCircle className="w-3 h-3 text-red-400" />
                            )}
                            Outcome: <strong className="text-slate-300 uppercase">{act.outcome}</strong>
                          </span>
                          <span className="text-slate-600">&bull;</span>
                          <span>Sensor: <strong className="text-slate-400">{act.sensor_tool}</strong></span>
                        </div>

                        {act.incident_id && (
                          <span className="text-blue-400 hover:text-blue-300 flex items-center gap-1 font-semibold">
                            Correlated: {act.incident_id} <ExternalLink className="w-2.5 h-2.5" />
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
