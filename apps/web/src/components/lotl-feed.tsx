"use client";

import React, { useMemo, useState } from "react";
import type { LotLInteraction } from "@contracts/index";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SeverityBadge } from "@/components/ui/severity-badge";
import {
  Clock,
  Eye,
  FileCode,
  FileEdit,
  FolderLock,
  Key,
  Network,
  Search,
  Server,
  ShieldAlert,
  Terminal,
  Trash2,
  User,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface LotLFeedProps {
  interactions: LotLInteraction[];
  onSelectInteraction?: (interaction: LotLInteraction) => void;
  selectedInteractionId?: string | null;
}

export function LotLFeed({
  interactions,
  onSelectInteraction,
  selectedInteractionId,
}: LotLFeedProps) {
  const [filterType, setFilterType] = useState<string>("all");
  const [filterHost, setFilterHost] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const hosts = useMemo(() => {
    return Array.from(new Set(interactions.map((i) => i.host).filter(Boolean)));
  }, [interactions]);

  const filteredInteractions = useMemo(() => {
    return interactions.filter((item) => {
      if (filterType !== "all" && item.interaction_type !== filterType) {
        return false;
      }
      if (filterHost !== "all" && item.host !== filterHost) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matches =
          item.interaction_id.toLowerCase().includes(q) ||
          item.lure_id.toLowerCase().includes(q) ||
          item.lure_name.toLowerCase().includes(q) ||
          item.host.toLowerCase().includes(q) ||
          (item.user && item.user.toLowerCase().includes(q)) ||
          (item.process && item.process.toLowerCase().includes(q)) ||
          (item.evidence_source && item.evidence_source.toLowerCase().includes(q)) ||
          (item.command_summary && item.command_summary.toLowerCase().includes(q));
        if (!matches) return false;
      }
      return true;
    });
  }, [interactions, filterType, filterHost, searchQuery]);

  const getInteractionIcon = (type: string) => {
    switch (type) {
      case "shell_history_read":
      case "file_read":
        return <Eye className="w-4 h-4 text-cyan-400" />;
      case "ssh_key_access":
      case "credential_use":
        return <Key className="w-4 h-4 text-rose-400" />;
      case "file_modified":
        return <FileEdit className="w-4 h-4 text-amber-400" />;
      case "file_deleted":
        return <Trash2 className="w-4 h-4 text-red-400" />;
      case "share_enumeration":
        return <FolderLock className="w-4 h-4 text-sky-400" />;
      case "network_pivot":
      case "network_connection":
      case "decoy_authentication":
        return <Network className="w-4 h-4 text-purple-400" />;
      case "discovery":
        return <Search className="w-4 h-4 text-emerald-400" />;
      default:
        return <Terminal className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-3 font-mono">
      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5">
        <div className="flex flex-wrap items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
          <button
            type="button"
            onClick={() => setFilterType("all")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filterType === "all"
                ? "bg-purple-600 text-white font-bold"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            All Touches ({interactions.length})
          </button>
          <button
            type="button"
            onClick={() => setFilterType("file_read")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filterType === "file_read"
                ? "bg-purple-600 text-white font-bold"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            File Reads
          </button>
          <button
            type="button"
            onClick={() => setFilterType("credential_use")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filterType === "credential_use"
                ? "bg-purple-600 text-white font-bold"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            Credential Uses
          </button>
          <button
            type="button"
            onClick={() => setFilterType("file_modified")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filterType === "file_modified"
                ? "bg-purple-600 text-white font-bold"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            Tampering / FIM
          </button>
          <button
            type="button"
            onClick={() => setFilterType("share_enumeration")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filterType === "share_enumeration"
                ? "bg-purple-600 text-white font-bold"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            Share Enum
          </button>
        </div>

        <div className="flex items-center gap-2">
          {hosts.length > 0 && (
            <select
              value={filterHost}
              onChange={(e) => setFilterHost(e.target.value)}
              className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 focus:outline-none focus:border-purple-500"
            >
              <option value="all">All Hosts</option>
              {hosts.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>
          )}

          <div className="relative flex-1 sm:w-60">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search user, cmd, host, lure..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1 bg-slate-900/80 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
            />
          </div>
        </div>
      </div>

      {/* Feed List */}
      <ScrollArea className="h-[520px] rounded-xl border border-slate-800 bg-slate-950/40 p-2">
        {filteredInteractions.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-center text-slate-500">
            <ShieldAlert className="w-8 h-8 mb-2 opacity-40 text-purple-400" />
            <p className="text-xs">No LotL artifact interactions recorded yet.</p>
            <p className="text-[10px] text-slate-600 mt-0.5">
              Simulate attacker actions using native OS commands to trigger lures.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {filteredInteractions.map((item) => {
              const isSelected = selectedInteractionId === item.interaction_id;
              const formattedTime = new Date(item.timestamp).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              });

              return (
                <Card
                  key={item.interaction_id}
                  onClick={() => onSelectInteraction?.(item)}
                  className={cn(
                    "cursor-pointer border transition-all text-xs bg-slate-900/60 hover:bg-slate-900/90",
                    isSelected
                      ? "border-purple-500 bg-purple-950/20 shadow-md shadow-purple-950/50"
                      : "border-slate-800/80 hover:border-slate-700"
                  )}
                >
                  <CardContent className="p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-2.5 min-w-0">
                        <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 shrink-0 mt-0.5">
                          {getInteractionIcon(item.interaction_type)}
                        </div>

                        <div className="space-y-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-bold text-slate-200 text-xs truncate">
                              {item.lure_name}
                            </span>
                            <Badge
                              variant="outline"
                              className="text-[9px] px-1.5 py-0 bg-slate-950 text-purple-300 border-purple-800/50 font-mono"
                            >
                              {item.lure_id}
                            </Badge>
                            <Badge
                              variant="outline"
                              className="text-[9px] px-1.5 py-0 bg-slate-950 text-cyan-400 border-cyan-800/50"
                            >
                              {item.interaction_type.replace(/_/g, " ")}
                            </Badge>
                            {item.severity && (
                              <SeverityBadge
                                severity={item.severity as "low" | "medium" | "high" | "critical"}
                              />
                            )}
                          </div>

                          {/* Command or Detail Summary */}
                          {item.command_summary && (
                            <p className="text-[11px] font-mono text-amber-300/90 bg-slate-950/70 p-1.5 rounded border border-slate-800/60 break-all">
                              $ {item.command_summary}
                            </p>
                          )}

                          {/* Attributed Identity & Host Metadata */}
                          <div className="flex items-center gap-3 text-[10px] text-slate-400 flex-wrap pt-0.5">
                            <span className="flex items-center gap-1 text-slate-300 font-semibold">
                              <Server className="w-3 h-3 text-slate-500" />
                              {item.host}
                            </span>
                            {item.user && (
                              <span className="flex items-center gap-1 text-slate-400">
                                <User className="w-3 h-3 text-slate-500" />
                                {item.user}
                              </span>
                            )}
                            {item.process && (
                              <span className="flex items-center gap-1 text-slate-400">
                                <Terminal className="w-3 h-3 text-slate-500" />
                                {item.process} {item.pid ? `(pid:${item.pid})` : ""}
                              </span>
                            )}
                            {item.evidence_source && (
                              <span className="flex items-center gap-1 text-purple-400/80">
                                <FileCode className="w-3 h-3" />
                                {item.evidence_source}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="shrink-0 flex flex-col items-end gap-1">
                        <span className="text-[10px] text-slate-400 flex items-center gap-1 font-mono">
                          <Clock className="w-3 h-3 text-slate-500" />
                          {formattedTime}
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </ScrollArea>
    </div>
  );
}
