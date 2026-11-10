"use client";

import { useState } from "react";
import type { GuardDecision, ResponseRecommendation } from "@contracts/index";
import { approveGuardDecision, rejectGuardDecision } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  FileCheck2,
  Lock,
  Shield,
  ShieldCheck,
  UserCheck,
  X,
  XCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ResponseGuardPanelProps {
  recommendations: ResponseRecommendation[];
  onDecisionUpdated?: (updatedDecision: GuardDecision) => void;
}

export function ResponseGuardPanel({
  recommendations,
  onDecisionUpdated,
}: ResponseGuardPanelProps) {
  const [filter, setFilter] = useState<"all" | "allow" | "needs_human" | "deny">("all");
  const [expandedRecId, setExpandedRecId] = useState<string | null>(null);
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);
  const [approvalNotes, setApprovalNotes] = useState<Record<string, string>>({});
  const [operatorName, setOperatorName] = useState<string>("ot_operator_lead");

  const filteredRecs = recommendations.filter((r) => {
    if (filter === "all") return true;
    return r.decision.decision === filter;
  });

  const handleApprove = async (rec: ResponseRecommendation) => {
    if (rec.decision.decision === "deny") return;
    setActionLoadingId(rec.recommendation_id);
    try {
      const notes = approvalNotes[rec.decision.decision_id] || "Authorized by OT shift supervisor.";
      const updated = await approveGuardDecision(rec.decision.decision_id, operatorName, notes);
      onDecisionUpdated?.(updated);
    } catch (err) {
      console.error("Failed to approve action:", err);
      alert(err instanceof Error ? err.message : "Approval failed");
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleReject = async (rec: ResponseRecommendation) => {
    setActionLoadingId(rec.recommendation_id);
    try {
      const notes = approvalNotes[rec.decision.decision_id] || "Rejected during safety verification.";
      const updated = await rejectGuardDecision(rec.decision.decision_id, operatorName, notes);
      onDecisionUpdated?.(updated);
    } catch (err) {
      console.error("Failed to reject action:", err);
      alert(err instanceof Error ? err.message : "Rejection failed");
    } finally {
      setActionLoadingId(null);
    }
  };

  const getDecisionCardStyle = (outcome: string) => {
    if (outcome === "deny") {
      return {
        border: "border-red-700/80 bg-red-950/30",
        badge: "bg-red-950 text-red-300 border-red-700",
        icon: XCircle,
        iconColor: "text-red-400",
      };
    }
    if (outcome === "allow") {
      return {
        border: "border-emerald-700/80 bg-emerald-950/30",
        badge: "bg-emerald-950 text-emerald-300 border-emerald-700",
        icon: CheckCircle2,
        iconColor: "text-emerald-400",
      };
    }
    return {
      border: "border-amber-700/80 bg-amber-950/30",
      badge: "bg-amber-950 text-amber-300 border-amber-700",
      icon: AlertTriangle,
      iconColor: "text-amber-400",
    };
  };

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* Safety Notice Banner */}
      <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] text-slate-300 flex items-start gap-2.5">
        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5 leading-relaxed">
          <p>
            <strong>Response Safety Guard Active:</strong> Evaluates candidate containment actions against OT physical process interlocks.
          </p>
          <p className="text-slate-400 text-[10px]">
            &bull; <strong className="text-emerald-400">ALLOW:</strong> Permitted by policy. Does not execute automatically.
            &bull; <strong className="text-amber-400">NEEDS_HUMAN:</strong> Requires explicit plant operator review.
            &bull; <strong className="text-red-400">DENY:</strong> Prohibited. Cannot be overridden.
          </p>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
          <button
            type="button"
            onClick={() => setFilter("all")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filter === "all" ? "bg-blue-600 text-white font-bold" : "text-slate-400 hover:text-slate-200"
            )}
          >
            All Recommendations ({recommendations.length})
          </button>
          <button
            type="button"
            onClick={() => setFilter("allow")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filter === "allow" ? "bg-emerald-600 text-white font-bold" : "text-slate-400 hover:text-slate-200"
            )}
          >
            Permitted ({recommendations.filter((r) => r.decision.decision === "allow").length})
          </button>
          <button
            type="button"
            onClick={() => setFilter("needs_human")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filter === "needs_human" ? "bg-amber-600 text-white font-bold" : "text-slate-400 hover:text-slate-200"
            )}
          >
            Review Required ({recommendations.filter((r) => r.decision.decision === "needs_human").length})
          </button>
          <button
            type="button"
            onClick={() => setFilter("deny")}
            className={cn(
              "px-2.5 py-1 rounded transition text-xs",
              filter === "deny" ? "bg-red-600 text-white font-bold" : "text-slate-400 hover:text-slate-200"
            )}
          >
            Prohibited ({recommendations.filter((r) => r.decision.decision === "deny").length})
          </button>
        </div>

        <div className="flex items-center gap-2 text-[11px] text-slate-400">
          <span>Active Reviewer:</span>
          <input
            type="text"
            value={operatorName}
            onChange={(e) => setOperatorName(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-0.5 text-xs text-slate-200 w-36 focus:outline-hidden focus:border-blue-500 font-mono"
            placeholder="operator id"
          />
        </div>
      </div>

      {/* Recommendations Cards List */}
      <div className="space-y-3">
        {filteredRecs.length === 0 ? (
          <div className="p-12 text-center text-slate-500 bg-slate-950/40 rounded-xl border border-slate-800 space-y-1">
            <Shield className="w-8 h-8 mx-auto opacity-30 text-slate-400" />
            <p>No response recommendations matching current filter.</p>
          </div>
        ) : (
          filteredRecs.map((rec) => {
            const dec = rec.decision;
            const style = getDecisionCardStyle(dec.decision);
            const Icon = style.icon;
            const isExpanded = expandedRecId === rec.recommendation_id;
            const isLoading = actionLoadingId === rec.recommendation_id;

            return (
              <Card
                key={rec.recommendation_id}
                className={cn(
                  "border transition-all shadow-md relative overflow-hidden bg-slate-900/70",
                  style.border
                )}
              >
                <CardHeader className="p-4 pb-2">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Icon className={cn("w-5 h-5 shrink-0", style.iconColor)} />
                      <div>
                        <CardTitle className="text-sm font-bold text-slate-100 flex items-center gap-2">
                          {rec.title}
                        </CardTitle>
                        <CardDescription className="text-xs text-slate-400 font-mono mt-0.5">
                          Target: <strong className="text-blue-300">{rec.target}</strong> ({(rec.target_zone || "it").toUpperCase()}) &bull; Risk: <strong className={cn(
                            rec.risk_level === "critical" ? "text-rose-400" : rec.risk_level === "high" ? "text-amber-400" : "text-slate-300"
                          )}>{rec.risk_level.toUpperCase()}</strong>
                        </CardDescription>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <Badge variant="outline" className={cn("text-xs uppercase font-bold py-0.5", style.badge)}>
                        GUARD: {dec.decision.toUpperCase()}
                      </Badge>

                      {dec.approval_status === "approved" && (
                        <Badge variant="outline" className="text-xs uppercase bg-emerald-950 text-emerald-300 border-emerald-600">
                          APPROVED
                        </Badge>
                      )}
                      {dec.approval_status === "rejected" && (
                        <Badge variant="outline" className="text-xs uppercase bg-red-950 text-red-300 border-red-600">
                          REJECTED
                        </Badge>
                      )}
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="p-4 pt-2 space-y-3">
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {rec.description}
                  </p>

                  {/* Primary Policy Decision Reason */}
                  <div className={cn(
                    "p-3 rounded-lg border text-xs space-y-1",
                    dec.decision === "deny"
                      ? "bg-red-950/40 border-red-800/60 text-red-200"
                      : dec.decision === "allow"
                      ? "bg-emerald-950/40 border-emerald-800/60 text-emerald-200"
                      : "bg-amber-950/40 border-amber-800/60 text-amber-200"
                  )}>
                    <div className="flex items-center justify-between font-bold text-[11px] mb-1">
                      <span className="flex items-center gap-1.5">
                        <Lock className="w-3.5 h-3.5" /> Policy Engine Evaluation ({dec.rule_ids[0]})
                      </span>
                      <span>Target Criticality: {dec.asset_criticality?.toUpperCase() || "UNKNOWN"}</span>
                    </div>

                    {dec.reasons.map((r, idx) => (
                      <p key={idx} className="leading-relaxed">
                        &bull; {r}
                      </p>
                    ))}
                  </div>

                  {/* Suggested Safer Alternative for DENIED actions */}
                  {rec.suggested_alternative && (
                    <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-700/60 text-emerald-200 text-xs space-y-1">
                      <span className="font-bold flex items-center gap-1.5 text-emerald-300">
                        <ShieldCheck className="w-4 h-4" /> Recommended Safer Alternative:
                      </span>
                      <p>{rec.suggested_alternative}</p>
                    </div>
                  )}

                  {/* Human Approval Status & Action Workflow */}
                  {dec.decision === "needs_human" && (
                    <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-amber-300 flex items-center gap-1.5">
                          <UserCheck className="w-4 h-4" /> Human Operator Authorization:
                        </span>
                        <span className="text-[11px] text-slate-400">
                          Status: <strong className="uppercase text-slate-200">{dec.approval_status}</strong>
                        </span>
                      </div>

                      {dec.approval_status === "pending_review" ? (
                        <div className="space-y-2 pt-1 border-t border-slate-800/60">
                          <input
                            type="text"
                            placeholder="Operator authorization notes or containment ticket #..."
                            value={approvalNotes[dec.decision_id] || ""}
                            onChange={(e) =>
                              setApprovalNotes({ ...approvalNotes, [dec.decision_id]: e.target.value })
                            }
                            className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-hidden focus:border-amber-500 font-mono"
                          />

                          <div className="flex items-center justify-end gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleReject(rec)}
                              disabled={isLoading}
                              className="text-xs border-red-800 text-red-300 hover:bg-red-950/60"
                            >
                              <X className="w-3.5 h-3.5 mr-1" /> Reject Action
                            </Button>

                            <Button
                              size="sm"
                              onClick={() => handleApprove(rec)}
                              disabled={isLoading}
                              className="text-xs bg-amber-600 hover:bg-amber-500 text-white font-bold"
                            >
                              <Check className="w-3.5 h-3.5 mr-1" /> Authorize Action
                            </Button>
                          </div>
                        </div>
                      ) : (
                        <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
                          <span>
                            Recorded by: <strong className="text-slate-200">{dec.approved_by || "analyst"}</strong>
                          </span>
                          <span>
                            {dec.approved_at ? new Date(dec.approved_at).toLocaleString() : ""}
                          </span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Expand Policy Details Toggle */}
                  <div className="flex items-center justify-between pt-1 text-[11px] text-slate-500 border-t border-slate-800/40">
                    <span className="flex items-center gap-1">
                      <FileCheck2 className="w-3.5 h-3.5 text-blue-400" />
                      Supporting Evidence Events: <strong>{(rec.supporting_evidence_ids || []).length}</strong>
                    </span>

                    <button
                      type="button"
                      onClick={() => setExpandedRecId(isExpanded ? null : rec.recommendation_id)}
                      className="text-slate-400 hover:text-slate-200 flex items-center gap-1 text-[10px]"
                    >
                      {isExpanded ? (
                        <>
                          Hide Policy Matrix <ChevronUp className="w-3 h-3" />
                        </>
                      ) : (
                        <>
                          Inspect Policy Breakdown <ChevronDown className="w-3 h-3" />
                        </>
                      )}
                    </button>
                  </div>

                  {/* Expanded Policy Evaluation Breakdown */}
                  {isExpanded && dec.policy_evaluations && dec.policy_evaluations.length > 0 && (
                    <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2 mt-2">
                      <span className="font-bold text-[10px] text-slate-400 uppercase tracking-wider block">
                        Detailed Safety Policy Evaluation:
                      </span>
                      <div className="divide-y divide-slate-800/60">
                        {dec.policy_evaluations.map((pe) => (
                          <div key={pe.policy_id} className="py-2 flex items-start justify-between gap-2">
                            <div className="space-y-0.5">
                              <span className="font-bold text-slate-200 block text-xs">
                                {pe.policy_name} ({pe.policy_id})
                              </span>
                              <span className="text-[10px] text-slate-400 block leading-relaxed">
                                {pe.explanation}
                              </span>
                            </div>

                            <Badge
                              variant="outline"
                              className={cn(
                                "text-[9px] uppercase font-bold shrink-0 py-0.5",
                                pe.result === "pass"
                                  ? "bg-emerald-950/60 text-emerald-400 border-emerald-800"
                                  : pe.result === "fail"
                                  ? "bg-red-950/60 text-red-400 border-red-800"
                                  : "bg-amber-950/60 text-amber-400 border-amber-800"
                              )}
                            >
                              {pe.result.toUpperCase()}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })
        )}
      </div>
    </div>
  );
}
