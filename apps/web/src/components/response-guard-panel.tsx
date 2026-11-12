"use client";

import { useState } from "react";
import type { GuardDecision, ResponseRecommendation } from "@contracts/index";
import { approveGuardDecision, rejectGuardDecision } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmationDialog } from "@/components/ui/confirmation-dialog";
import { useToast } from "@/components/ui/toast";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Info,
  Lock,
  UserCheck,
  X,
  XCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ResponseGuardPanelProps {
  recommendations: ResponseRecommendation[];
  onDecisionUpdated?: (updatedDecision: GuardDecision) => void;
  className?: string;
}

export function ResponseGuardPanel({
  recommendations,
  onDecisionUpdated,
  className,
}: ResponseGuardPanelProps) {
  const { success, error: toastError } = useToast();
  const [filter, setFilter] = useState<"all" | "allow" | "needs_human" | "deny">("all");
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);
  const [approvalNotes, setApprovalNotes] = useState<Record<string, string>>({});
  const [operatorName] = useState<string>("ot_operator_lead");

  // Confirmation dialog state
  const [pendingConfirmation, setPendingConfirmation] = useState<{
    type: "approve" | "reject";
    rec: ResponseRecommendation;
  } | null>(null);

  const filteredRecs = recommendations.filter((r) => {
    if (filter === "all") return true;
    return r.decision.decision === filter;
  });

  const getActionName = (rec: ResponseRecommendation): string => {
    if (typeof rec.action === "string") return rec.action;
    if (typeof rec.decision.action === "string") return rec.decision.action;
    return "containment_action";
  };

  const getTargetName = (rec: ResponseRecommendation): string => {
    return rec.target || rec.decision.target || "host";
  };

  const confirmApprove = async () => {
    if (!pendingConfirmation) return;
    const { rec } = pendingConfirmation;
    if (rec.decision.decision === "deny") return;

    setActionLoadingId(rec.recommendation_id);
    try {
      const notes = approvalNotes[rec.decision.decision_id] || "Authorized by OT shift supervisor.";
      const updated = await approveGuardDecision(rec.decision.decision_id, operatorName, notes);
      onDecisionUpdated?.(updated);
      success("Human Review Recorded: APPROVED", `Action '${getActionName(rec)}' on ${getTargetName(rec)} authorized by ${operatorName}.`);
    } catch (err) {
      toastError("Approval Failed", err instanceof Error ? err.message : "Backend rejected approval request.");
    } finally {
      setActionLoadingId(null);
      setPendingConfirmation(null);
    }
  };

  const confirmReject = async () => {
    if (!pendingConfirmation) return;
    const { rec } = pendingConfirmation;

    setActionLoadingId(rec.recommendation_id);
    try {
      const notes = approvalNotes[rec.decision.decision_id] || "Rejected during safety verification.";
      const updated = await rejectGuardDecision(rec.decision.decision_id, operatorName, notes);
      onDecisionUpdated?.(updated);
      success("Human Review Recorded: REJECTED", `Action '${getActionName(rec)}' rejected for safety reasons.`);
    } catch (err) {
      toastError("Rejection Failed", err instanceof Error ? err.message : "Backend rejected review submission.");
    } finally {
      setActionLoadingId(null);
      setPendingConfirmation(null);
    }
  };

  const getDecisionCardStyle = (outcome: string) => {
    if (outcome === "deny") {
      return {
        border: "border-red-700/80 bg-red-950/20",
        badge: "bg-red-950 text-red-300 border-red-700",
        icon: XCircle,
        iconColor: "text-red-400",
      };
    }
    if (outcome === "allow") {
      return {
        border: "border-emerald-700/80 bg-emerald-950/20",
        badge: "bg-emerald-950 text-emerald-300 border-emerald-700",
        icon: CheckCircle2,
        iconColor: "text-emerald-400",
      };
    }
    return {
      border: "border-amber-700/80 bg-amber-950/20",
      badge: "bg-amber-950 text-amber-300 border-amber-700",
      icon: AlertTriangle,
      iconColor: "text-amber-400",
    };
  };

  return (
    <div className={cn("space-y-4 font-mono text-xs", className)}>
      {/* Absolute Safety & Execution Boundary Notice */}
      <div className="p-3 rounded-xl bg-blue-950/30 border border-blue-800/60 flex items-start gap-3">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div className="text-[11px] font-sans text-slate-300 leading-relaxed">
          <strong className="text-blue-300 font-semibold font-mono block mb-0.5">
            ADVISORY SAFETY MODE — NO AUTOMATIC EXECUTION
          </strong>
          SentinelX Response Safety Guard evaluates containment actions against authoritative OT process safety policies.
          An <strong className="text-emerald-400 font-mono">ALLOW</strong> decision or human approval does not automatically execute commands against production networks. All real containment must be performed manually by authorized engineers.
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setFilter("all")}
            className={cn(
              "px-2.5 py-1 rounded text-[11px] font-semibold transition cursor-pointer",
              filter === "all"
                ? "bg-slate-800 text-slate-100"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            All ({recommendations.length})
          </button>
          <button
            type="button"
            onClick={() => setFilter("needs_human")}
            className={cn(
              "px-2.5 py-1 rounded text-[11px] font-semibold transition cursor-pointer",
              filter === "needs_human"
                ? "bg-amber-950 text-amber-300 border border-amber-800"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            Needs Human ({recommendations.filter((r) => r.decision.decision === "needs_human").length})
          </button>
          <button
            type="button"
            onClick={() => setFilter("deny")}
            className={cn(
              "px-2.5 py-1 rounded text-[11px] font-semibold transition cursor-pointer",
              filter === "deny"
                ? "bg-red-950 text-red-300 border border-red-800"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            Denied ({recommendations.filter((r) => r.decision.decision === "deny").length})
          </button>
          <button
            type="button"
            onClick={() => setFilter("allow")}
            className={cn(
              "px-2.5 py-1 rounded text-[11px] font-semibold transition cursor-pointer",
              filter === "allow"
                ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                : "text-slate-400 hover:text-slate-200"
            )}
          >
            Allowed ({recommendations.filter((r) => r.decision.decision === "allow").length})
          </button>
        </div>

        <span className="text-[11px] text-slate-500">
          Showing {filteredRecs.length} recommendations
        </span>
      </div>

      {/* Decision Cards List */}
      {filteredRecs.length === 0 ? (
        <div className="p-8 text-center border border-slate-800 rounded-xl bg-slate-900/30 text-slate-500 font-sans">
          No guard recommendations match the selected filter.
        </div>
      ) : (
        <div className="space-y-3">
          {filteredRecs.map((rec) => {
            const dec = rec.decision;
            const style = getDecisionCardStyle(dec.decision);
            const Icon = style.icon;
            const isDeny = dec.decision === "deny";
            const isNeedsHuman = dec.decision === "needs_human";
            const isApproved = dec.approval_status === "approved";
            const isRejected = dec.approval_status === "rejected";
            const reasonsText = Array.isArray(dec.reasons) ? dec.reasons.join(" ") : ((dec as unknown as Record<string, string>).reasoning || rec.description || "Policy evaluated.");
            const ruleIdsText = Array.isArray(dec.rule_ids) ? dec.rule_ids.join(", ") : ((dec as unknown as Record<string, string>).policy_id || "POL-SAFETY");

            return (
              <div
                key={rec.recommendation_id}
                className={cn(
                  "p-4 rounded-xl border transition-all duration-200",
                  style.border
                )}
              >
                {/* Header row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-2 border-b border-slate-800/60">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Icon className={cn("w-4 h-4 shrink-0", style.iconColor)} />
                    <span className="font-bold text-slate-100 text-sm">
                      {getActionName(rec).toUpperCase()} ➔ {getTargetName(rec)}
                    </span>
                    <Badge variant="outline" className={cn("uppercase font-bold text-[10px]", style.badge)}>
                      {dec.decision}
                    </Badge>
                    {(isApproved || isRejected) && (
                      <Badge
                        variant="outline"
                        className={cn(
                          "text-[10px] uppercase font-bold",
                          isApproved
                            ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                            : "bg-red-950 text-red-300 border-red-700"
                        )}
                      >
                        {dec.approval_status} by {dec.approved_by || "supervisor"}
                      </Badge>
                    )}
                  </div>

                  <div className="flex items-center gap-2 text-[11px] text-slate-400">
                    <span>Risk: <strong className="text-slate-200 uppercase">{rec.risk_level}</strong></span>
                    <span className="text-slate-600">|</span>
                    <span>Zone: <strong className="text-slate-200 uppercase">{rec.target_zone || dec.target_zone || "N/A"}</strong></span>
                  </div>
                </div>

                {/* Body details */}
                <div className="mt-3 space-y-2 text-xs">
                  <div className="text-slate-300 font-sans leading-relaxed">
                    <strong>Reasoning:</strong> {reasonsText}
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 text-[11px] text-slate-400">
                    <div>
                      Rule IDs: <strong className="text-slate-200">{ruleIdsText}</strong>
                    </div>
                    <div>
                      Target Zone: <strong className="text-slate-200 uppercase">{rec.target_zone || dec.target_zone || "N/A"}</strong>
                    </div>
                    <div>
                      Criticality:{" "}
                      <strong className={dec.asset_criticality === "process_critical" || dec.asset_criticality === "high" ? "text-rose-400 font-bold" : "text-slate-300"}>
                        {dec.asset_criticality || "standard"}
                      </strong>
                    </div>
                    <div>
                      Status:{" "}
                      <strong className={isDeny ? "text-red-400" : isNeedsHuman ? "text-amber-400" : "text-emerald-400"}>
                        {isDeny ? "BLOCKED BY POLICY" : isNeedsHuman ? "AWAITING HUMAN" : "ALLOWED (ADVISORY)"}
                      </strong>
                    </div>
                  </div>

                  {/* Operational human review controls (Only for non-denied recommendations) */}
                  {isNeedsHuman && dec.approval_status !== "approved" && dec.approval_status !== "rejected" && (
                    <div className="mt-3 p-3 rounded-lg bg-amber-950/20 border border-amber-800/60 space-y-2">
                      <div className="flex items-center justify-between text-amber-300 font-bold text-[11px]">
                        <span className="flex items-center gap-1.5">
                          <UserCheck className="w-3.5 h-3.5" />
                          Dual-Control Safety Authorization Required
                        </span>
                      </div>
                      <div className="flex flex-col sm:flex-row items-center gap-2">
                        <input
                          type="text"
                          placeholder="Supervisor Notes / Ticket Reference..."
                          value={approvalNotes[dec.decision_id] || ""}
                          onChange={(e) =>
                            setApprovalNotes({
                              ...approvalNotes,
                              [dec.decision_id]: e.target.value,
                            })
                          }
                          className="flex-1 w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-amber-500 font-mono"
                        />
                        <div className="flex items-center gap-2 shrink-0">
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => setPendingConfirmation({ type: "reject", rec })}
                            disabled={actionLoadingId === rec.recommendation_id}
                            className="text-xs h-7 gap-1 font-mono cursor-pointer"
                          >
                            <X className="w-3.5 h-3.5" />
                            Reject
                          </Button>
                          <Button
                            size="sm"
                            onClick={() => setPendingConfirmation({ type: "approve", rec })}
                            disabled={actionLoadingId === rec.recommendation_id}
                            className="text-xs h-7 gap-1 bg-amber-600 hover:bg-amber-700 text-white font-mono font-bold cursor-pointer"
                          >
                            <Check className="w-3.5 h-3.5" />
                            Authorize Action
                          </Button>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Non-bypassable DENY notice */}
                  {isDeny && (
                    <div className="mt-2 p-2 rounded bg-red-950/40 border border-red-800/80 text-[11px] text-red-300 font-sans flex items-center gap-2">
                      <Lock className="w-3.5 h-3.5 text-red-400 shrink-0" />
                      <span>
                        <strong>Safety Violation:</strong> This action targets a critical industrial process. Automated and manual execution is strictly prohibited by safety policy <code>{ruleIdsText}</code>.
                      </span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Confirmation Dialog for Human Approvals / Rejections */}
      <ConfirmationDialog
        isOpen={Boolean(pendingConfirmation)}
        title={
          pendingConfirmation?.type === "approve"
            ? "Authorize Containment Action?"
            : "Reject Containment Recommendation?"
        }
        description={
          pendingConfirmation?.type === "approve"
            ? `You are recording formal supervisor authorization for action '${pendingConfirmation ? getActionName(pendingConfirmation.rec) : ""}' on target '${pendingConfirmation ? getTargetName(pendingConfirmation.rec) : ""}'. This audit decision will be logged. Note: Execution must be performed manually outside SentinelX.`
            : `You are recording rejection for action '${pendingConfirmation ? getActionName(pendingConfirmation.rec) : ""}' on target '${pendingConfirmation ? getTargetName(pendingConfirmation.rec) : ""}'.`
        }
        confirmLabel={
          pendingConfirmation?.type === "approve"
            ? "Record Authorization"
            : "Record Rejection"
        }
        variant={pendingConfirmation?.type === "approve" ? "warning" : "danger"}
        isLoading={Boolean(actionLoadingId)}
        onConfirm={
          pendingConfirmation?.type === "approve" ? confirmApprove : confirmReject
        }
        onCancel={() => setPendingConfirmation(null)}
      />
    </div>
  );
}
