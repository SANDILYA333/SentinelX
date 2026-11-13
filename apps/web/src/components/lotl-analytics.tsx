"use client";

import React from "react";
import type { LotLAnalytics, LotLHealthStatus } from "@contracts/index";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Activity,
  HeartPulse,
  Server,
  Shield,
} from "lucide-react";

interface LotLAnalyticsProps {
  analytics: LotLAnalytics | null;
  health: LotLHealthStatus | null;
}

export function LotLAnalyticsView({ analytics, health }: LotLAnalyticsProps) {
  if (!analytics) {
    return (
      <div className="p-8 text-center text-slate-500 font-mono text-xs">
        Loading LotL analytics data...
      </div>
    );
  }

  const interactionDist = Object.entries(analytics.interactions_by_type || {});
  const lureDist = Object.entries(analytics.interactions_by_lure || {});
  const interactingHosts = analytics.interacting_hosts || [];

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Top Level Metric KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card className="bg-slate-900/60 border-slate-800">
          <CardContent className="p-3.5 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Active Lures
            </span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-xl font-bold text-slate-100">
                {analytics.total_active_lures ?? 0}
              </span>
              <span className="text-[10px] text-emerald-400">deployed</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/60 border-slate-800">
          <CardContent className="p-3.5 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Lures Discovered
            </span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-xl font-bold text-purple-400">
                {analytics.total_discovered_lures ?? 0}
              </span>
              <span className="text-[10px] text-slate-500">
                / {analytics.total_active_lures ?? 0}
              </span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/60 border-slate-800">
          <CardContent className="p-3.5 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Total Touches
            </span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-xl font-bold text-cyan-300">
                {analytics.total_interactions ?? 0}
              </span>
              <span className="text-[10px] text-slate-500">recorded</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/60 border-slate-800">
          <CardContent className="p-3.5 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Canary Invocations
            </span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-xl font-bold text-rose-400">
                {analytics.canary_presentations ?? 0}
              </span>
              <span className="text-[10px] text-slate-500">credentials</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/60 border-slate-800">
          <CardContent className="p-3.5 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              Decoy Authentications
            </span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-xl font-bold text-amber-400">
                {analytics.decoy_authentications ?? 0}
              </span>
              <span className="text-[10px] text-slate-500">services</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/60 border-slate-800">
          <CardContent className="p-3.5 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-bold">
              FIM Tampering
            </span>
            <div className="flex items-baseline gap-1.5">
              <span className="text-xl font-bold text-red-400">
                {analytics.file_modifications ?? 0}
              </span>
              <span className="text-[10px] text-slate-500">modifications</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Deployment & Monitoring Health Status Card */}
      {health && (
        <Card className="bg-slate-900/40 border-slate-800">
          <CardHeader className="p-4 pb-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <HeartPulse className="w-4 h-4 text-emerald-400" />
                <CardTitle className="text-sm font-bold text-slate-100">
                  Lure Deployment &amp; Monitoring Health
                </CardTitle>
              </div>
              <Badge
                variant="outline"
                className="bg-emerald-950/60 text-emerald-300 border-emerald-800 text-[10px] font-mono"
              >
                {health.sensors_healthy ? "HEALTHY" : "DEGRADED"}
              </Badge>
            </div>
            <CardDescription className="text-xs text-slate-400 mt-0.5">
              Cross-host verification between registered manifests, container filesystems, and sensor pipelines.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-4 pt-2">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
                <span className="text-[10px] text-slate-500 block">Total Registered</span>
                <span className="text-base font-bold text-slate-200">{health.total_lures ?? 0}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
                <span className="text-[10px] text-slate-500 block">Active Lures</span>
                <span className="text-base font-bold text-emerald-400">{health.active_lures ?? 0}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
                <span className="text-[10px] text-slate-500 block">Missing / Tampered</span>
                <span className="text-base font-bold text-rose-400">
                  {(health.missing_lures ?? 0) + (health.tampered_lures ?? 0)}
                </span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
                <span className="text-[10px] text-slate-500 block">Touches Recorded</span>
                <span className="text-base font-bold text-purple-400">{analytics.total_interactions ?? 0}</span>
              </div>
            </div>

            {interactingHosts.length > 0 && (
              <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex items-center gap-2 text-[11px] text-slate-400 flex-wrap">
                <span className="text-slate-500">Active Sensor Endpoints:</span>
                {interactingHosts.map((host) => (
                  <span
                    key={host}
                    className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 flex items-center gap-1"
                  >
                    <Server className="w-3 h-3 text-emerald-400" />
                    {host}
                  </span>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Breakdowns Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* By Interaction Type */}
        <Card className="bg-slate-900/60 border-slate-800">
          <CardHeader className="p-4 pb-2">
            <CardTitle className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-amber-400" />
              Touches by Interaction Type
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-2 space-y-2">
            {interactionDist.length === 0 ? (
              <span className="text-slate-500 text-[11px]">No interactions recorded</span>
            ) : (
              interactionDist.map(([type, count]) => (
                <div key={type} className="flex items-center justify-between text-xs py-1 border-b border-slate-800/40 last:border-0">
                  <span className="text-slate-300 capitalize">{type.replace(/_/g, " ")}</span>
                  <span className="font-bold text-amber-300">{count}</span>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        {/* By Host */}
        <Card className="bg-slate-900/60 border-slate-800">
          <CardHeader className="p-4 pb-2">
            <CardTitle className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-cyan-400" />
              Interacting Endpoints
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-2 space-y-2">
            {interactingHosts.length === 0 ? (
              <span className="text-slate-500 text-[11px]">No active hosts engaged</span>
            ) : (
              interactingHosts.map((host) => (
                <div key={host} className="flex items-center justify-between text-xs py-1 border-b border-slate-800/40 last:border-0">
                  <span className="text-slate-300">{host}</span>
                  <span className="font-bold text-emerald-400">ACTIVE</span>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        {/* By Lure */}
        <Card className="bg-slate-900/60 border-slate-800">
          <CardHeader className="p-4 pb-2">
            <CardTitle className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-purple-400" />
              Top Touched Lures
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-2 space-y-2">
            {lureDist.length === 0 ? (
              <span className="text-slate-500 text-[11px]">No lures triggered yet</span>
            ) : (
              lureDist.slice(0, 6).map(([lureId, count]) => (
                <div key={lureId} className="flex items-center justify-between text-xs py-1 border-b border-slate-800/40 last:border-0">
                  <span className="text-slate-300 font-mono text-[11px] truncate max-w-[150px]">{lureId}</span>
                  <span className="font-bold text-purple-300">{count}</span>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
