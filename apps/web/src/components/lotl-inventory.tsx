"use client";

import React, { useMemo, useState } from "react";
import type { LotLInteraction, LotLLure } from "@contracts/index";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ConfirmationDialog } from "@/components/ui/confirmation-dialog";
import { StatusBadge } from "@/components/ui/status-badge";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { LotLModal } from "@/components/lotl-modal";
import {
  Clock,
  Eye,
  FileText,
  FolderLock,
  Key,
  RefreshCw,
  Search,
  Server,
  Terminal,
  UploadCloud,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface LotLInventoryProps {
  lures: LotLLure[];
  interactions?: LotLInteraction[];
  onToggleEnabled?: (lureId: string, enabled: boolean) => Promise<void>;
  onDeployAll?: () => Promise<void>;
  onVerifyAll?: () => Promise<void>;
  isDeploying?: boolean;
}

export function LotLInventory({
  lures,
  interactions = [],
  onToggleEnabled,
  onDeployAll,
  onVerifyAll,
  isDeploying = false,
}: LotLInventoryProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedHost, setSelectedHost] = useState("all");
  const [selectedType, setSelectedType] = useState("all");
  const [selectedStatus, setSelectedStatus] = useState("all");
  const [inspectLure, setInspectLure] = useState<LotLLure | null>(null);
  const [showDeployConfirm, setShowDeployConfirm] = useState(false);

  // Collect distinct hosts and types for filter dropdowns
  const hosts = useMemo(() => {
    return Array.from(new Set(lures.map((l) => l.host))).filter((h) => h !== "unsupported");
  }, [lures]);

  const lureTypes = useMemo(() => {
    return Array.from(new Set(lures.map((l) => l.lure_type)));
  }, [lures]);

  const filteredLures = useMemo(() => {
    return lures.filter((l) => {
      if (selectedHost !== "all" && l.host !== selectedHost) return false;
      if (selectedType !== "all" && l.lure_type !== selectedType) return false;
      if (selectedStatus !== "all" && l.status !== selectedStatus) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          l.lure_id.toLowerCase().includes(term) ||
          l.name.toLowerCase().includes(term) ||
          l.path.toLowerCase().includes(term) ||
          l.host.toLowerCase().includes(term)
        );
      }
      return true;
    });
  }, [lures, selectedHost, selectedType, selectedStatus, searchTerm]);

  const getLureIcon = (type: string) => {
    switch (type) {
      case "shell_history":
      case "powershell_history":
        return <Terminal className="w-4 h-4 text-amber-400" />;
      case "ssh_key":
      case "ssh_config":
        return <Key className="w-4 h-4 text-rose-400" />;
      case "decoy_share":
        return <FolderLock className="w-4 h-4 text-sky-400" />;
      case "scheduled_task":
        return <Clock className="w-4 h-4 text-indigo-400" />;
      default:
        return <FileText className="w-4 h-4 text-cyan-400" />;
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Filter and Action Bar */}
      <Card className="bg-slate-900/60 border-slate-800">
        <CardContent className="p-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
            {/* Search */}
            <div className="relative min-w-[220px]">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search lure ID, name, or path..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Host Filter */}
            <select
              value={selectedHost}
              onChange={(e) => setSelectedHost(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-md px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Hosts ({lures.length})</option>
              {hosts.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>

            {/* Type Filter */}
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-md px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Lure Types</option>
              {lureTypes.map((t) => (
                <option key={t} value={t}>
                  {t.replace("_", " ")}
                </option>
              ))}
            </select>

            {/* Status Filter */}
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-md px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Statuses</option>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
              <option value="missing">Missing</option>
              <option value="tampered">Tampered</option>
              <option value="unsupported">Unsupported</option>
            </select>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 self-end md:self-auto">
            {onVerifyAll && (
              <Button
                variant="outline"
                size="sm"
                onClick={onVerifyAll}
                className="text-xs h-8 border-slate-700 hover:bg-slate-800"
              >
                <RefreshCw className="w-3.5 h-3.5 mr-1.5 text-slate-400" />
                Verify Integrity
              </Button>
            )}

            {onDeployAll && (
              <Button
                variant="default"
                size="sm"
                onClick={() => setShowDeployConfirm(true)}
                disabled={isDeploying}
                className="text-xs h-8 bg-cyan-600 hover:bg-cyan-500 text-white"
              >
                <UploadCloud className="w-3.5 h-3.5 mr-1.5" />
                {isDeploying ? "Deploying..." : "Deploy Lures"}
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Lure Inventory Table */}
      <Card className="bg-slate-900/60 border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400 font-mono">
              <tr>
                <th className="py-3 px-4">Lure ID & Name</th>
                <th className="py-3 px-4">Target Host & Path</th>
                <th className="py-3 px-4">Lure Type</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4 text-center">Interactions</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredLures.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 text-sm">
                    No Living-off-the-Land deception artifacts match the current filter.
                  </td>
                </tr>
              ) : (
                filteredLures.map((lure) => (
                  <tr
                    key={lure.lure_id}
                    onClick={() => setInspectLure(lure)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
                  >
                    {/* ID & Name */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2.5">
                        <div className="p-1.5 rounded bg-slate-950 border border-slate-800">
                          {getLureIcon(lure.lure_type)}
                        </div>
                        <div>
                          <div className="font-mono text-xs font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors">
                            {lure.lure_id}
                          </div>
                          <div className="text-xs text-slate-400 line-clamp-1">{lure.name}</div>
                        </div>
                      </div>
                    </td>

                    {/* Host & Path */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 text-xs text-slate-300 font-mono">
                        <Server className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                        <span className="font-semibold text-slate-200">{lure.host}</span>
                      </div>
                      <div className="font-mono text-[11px] text-amber-400/90 truncate max-w-[240px]" title={lure.path}>
                        {lure.path}
                      </div>
                    </td>

                    {/* Type */}
                    <td className="py-3 px-4">
                      <Badge variant="outline" className="font-mono text-[10px] bg-slate-950/60 text-slate-300 border-slate-700 capitalize">
                        {lure.lure_type.replace("_", " ")}
                      </Badge>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4">
                      <StatusBadge status={lure.status} />
                    </td>

                    {/* Severity */}
                    <td className="py-3 px-4">
                      <SeverityBadge severity={lure.severity} />
                    </td>

                    {/* Interactions */}
                    <td className="py-3 px-4 text-center">
                      <span className={cn(
                        "font-mono text-xs font-bold px-2 py-0.5 rounded",
                        lure.total_interactions > 0 ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800/60" : "text-slate-500"
                      )}>
                        {lure.total_interactions}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2 text-xs text-slate-400 hover:text-slate-100"
                          onClick={() => setInspectLure(lure)}
                        >
                          <Eye className="w-3.5 h-3.5 mr-1" />
                          Inspect
                        </Button>
                        {onToggleEnabled && lure.status !== "unsupported" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className={cn(
                              "h-7 px-2 text-xs",
                              lure.enabled ? "text-rose-400 hover:text-rose-300" : "text-emerald-400 hover:text-emerald-300"
                            )}
                            onClick={() => onToggleEnabled(lure.lure_id, !lure.enabled)}
                          >
                            {lure.enabled ? "Disable" : "Enable"}
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Inspect Lure Modal */}
      {inspectLure && (
        <LotLModal
          lure={inspectLure}
          interactions={interactions}
          onClose={() => setInspectLure(null)}
          onToggleEnabled={async (id, en) => {
            if (onToggleEnabled) {
              await onToggleEnabled(id, en);
              setInspectLure((prev) => (prev ? { ...prev, enabled: en, status: en ? "active" : "disabled" } : null));
            }
          }}
        />
      )}

      {/* Safe Deploy Confirmation Dialog */}
      <ConfirmationDialog
        open={showDeployConfirm}
        onOpenChange={setShowDeployConfirm}
        title="Deploy Living-off-the-Land Artifacts"
        description="This will safely and idempotently write synthetic administrative deception artifacts (shell histories, decoy SSH keys, canary configs) across the designated IT/DMZ lab endpoints. Production user accounts will not be overwritten."
        confirmLabel="Deploy Artifacts"
        variant="default"
        onConfirm={async () => {
          if (onDeployAll) {
            await onDeployAll();
          }
        }}
      />
    </div>
  );
}
