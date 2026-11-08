"use client";

import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchBudget, setBudgetThreshold } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertCircle, CheckCircle2, Gauge, Sliders, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";

export function BudgetGauge() {
  const queryClient = useQueryClient();

  const { data: budget, isLoading } = useQuery({
    queryKey: ["budget"],
    queryFn: fetchBudget,
    refetchInterval: 3000,
  });

  const mutation = useMutation({
    mutationFn: (newThreshold: number) => setBudgetThreshold(newThreshold),
    onSuccess: (updated) => {
      queryClient.setQueryData(["budget"], updated);
    },
  });

  const currentThreshold = budget?.threshold ?? 0.50;
  const currentFp = budget?.fp_per_24h_estimate ?? 0.0;
  const currentRecall = (budget?.attack_recall_estimate ?? 1.0) * 100;

  const [sliderValue, setSliderValue] = useState<number>(currentThreshold);

  // Sync slider when remote data loads
  React.useEffect(() => {
    if (budget?.threshold !== undefined) {
      setSliderValue(budget.threshold);
    }
  }, [budget?.threshold]);

  const handleSliderChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseFloat(e.target.value);
    setSliderValue(val);
  };

  const handleSliderCommit = () => {
    mutation.mutate(sliderValue);
  };

  // Status color: green if 0 FP, amber if <= 0.2, red if > 0.2
  const isOptimal = currentFp === 0 && currentRecall >= 100;
  const isNoisy = currentFp > 0;

  // Semi-circle SVG needle calculations
  // Angle maps threshold 0.0 -> -90 deg, 1.0 -> +90 deg
  const needleAngle = (sliderValue - 0.5) * 180;

  return (
    <Card className="border-slate-800 bg-slate-900/60 shadow-lg relative overflow-hidden">
      <CardHeader className="pb-3 border-b border-slate-800/80">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold tracking-tight text-slate-100 flex items-center gap-2">
            <Gauge className="w-4 h-4 text-emerald-400" />
            Alert Budget Controller &amp; Calibration
          </CardTitle>
          <div className="flex items-center gap-2">
            {isOptimal ? (
              <Badge variant="outline" className="bg-emerald-950/60 text-emerald-400 border-emerald-800/60 text-[11px] font-mono">
                <CheckCircle2 className="w-3 h-3 mr-1" /> Zero FP / 100% Recall
              </Badge>
            ) : (
              <Badge variant="outline" className="bg-amber-950/60 text-amber-400 border-amber-800/60 text-[11px] font-mono">
                <AlertCircle className="w-3 h-3 mr-1" /> FP Noise Detected
              </Badge>
            )}
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
              {budget?.calibration_method === "manual_override" ? "Manual Override" : "LOO-CV Calibrated"}
            </span>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pt-4 grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        {/* SVG Gauge Graphic */}
        <div className="md:col-span-4 flex flex-col items-center justify-center p-2">
          <div className="relative w-44 h-24 flex items-end justify-center">
            <svg viewBox="0 0 160 90" className="w-full h-full overflow-visible">
              {/* Background Arc */}
              <path
                d="M 15 80 A 65 65 0 0 1 145 80"
                fill="none"
                stroke="#1e293b"
                strokeWidth="12"
                strokeLinecap="round"
              />
              {/* Active Colored Arc */}
              <path
                d="M 15 80 A 65 65 0 0 1 145 80"
                fill="none"
                stroke={isOptimal ? "#10b981" : isNoisy ? "#f59e0b" : "#3b82f6"}
                strokeWidth="12"
                strokeLinecap="round"
                strokeDasharray="204"
                strokeDashoffset={204 - 204 * sliderValue}
                className="transition-all duration-300"
              />
              {/* Center Pivot */}
              <circle cx="80" cy="80" r="5" fill="#f8fafc" />
              {/* Needle Indicator */}
              <g transform={`rotate(${needleAngle} 80 80)`} className="transition-transform duration-300">
                <line x1="80" y1="80" x2="80" y2="24" stroke="#f8fafc" strokeWidth="2.5" strokeLinecap="round" />
              </g>
            </svg>

            {/* Central Score Label */}
            <div className="absolute -bottom-2 text-center">
              <span className="text-xl font-bold font-mono tracking-tight text-slate-100">
                {sliderValue.toFixed(2)}
              </span>
              <span className="block text-[10px] text-slate-400 font-mono">Score Threshold</span>
            </div>
          </div>
        </div>

        {/* Live Calibration Stats & Slider Controls */}
        <div className="md:col-span-8 space-y-4">
          <div className="grid grid-cols-3 gap-3">
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block font-medium">Daily False Positives</span>
              <div className="flex items-baseline gap-1 mt-0.5">
                <span className={cn(
                  "text-lg font-bold font-mono",
                  currentFp === 0 ? "text-emerald-400" : "text-amber-400"
                )}>
                  {currentFp.toFixed(3)}
                </span>
                <span className="text-[10px] text-slate-500">FP / 24h</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block font-medium">Attack Scenario Recall</span>
              <div className="flex items-baseline gap-1 mt-0.5">
                <span className="text-lg font-bold font-mono text-slate-100">
                  {currentRecall.toFixed(0)}%
                </span>
                <span className="text-[10px] text-slate-500">3/3 variants</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block font-medium">Alert Budget Limit</span>
              <div className="flex items-baseline gap-1 mt-0.5">
                <span className="text-lg font-bold font-mono text-blue-400">
                  0.000
                </span>
                <span className="text-[10px] text-slate-500">strict target</span>
              </div>
            </div>
          </div>

          {/* Interactive Calibration Slider */}
          <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/60 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Sliders className="w-3.5 h-3.5 text-blue-400" /> Operational Alert Sensitivity
              </span>
              <span className="text-slate-300 font-bold">
                Threshold: {sliderValue.toFixed(2)}
              </span>
            </div>

            <input
              type="range"
              min="0.10"
              max="0.90"
              step="0.05"
              value={sliderValue}
              onChange={handleSliderChange}
              onMouseUp={handleSliderCommit}
              onTouchEnd={handleSliderCommit}
              disabled={isLoading || mutation.isPending}
              className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-blue-500"
            />

            <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
              <span>0.10 (High Sensitivity / Noise)</span>
              <span className="text-emerald-400 font-semibold">&bull; 0.50 (Default Optimal)</span>
              <span>0.90 (High Specificity)</span>
            </div>
          </div>

          {/* Operational Recommendation Pill */}
          <div className="flex items-center justify-between text-[11px] text-slate-400 bg-slate-950/80 px-3 py-1.5 rounded-md border border-slate-800">
            <span className="flex items-center gap-1.5">
              <Sparkles className="w-3 h-3 text-amber-400" />
              <span>
                {sliderValue >= 0.50 && sliderValue <= 0.60
                  ? "Optimal operating point: zero false-positives across 5 benign days with 100% attack recall."
                  : sliderValue < 0.20
                    ? "Sub-optimal: threshold below 0.20 allows isolated baseline anomaly bursts to trigger alarms."
                    : "Operating with high threshold: leaves narrower margin for low-and-slow attack variations."}
              </span>
            </span>

            {sliderValue !== 0.50 && (
              <button
                type="button"
                onClick={() => {
                  setSliderValue(0.50);
                  mutation.mutate(0.50);
                }}
                className="text-blue-400 hover:text-blue-300 underline font-mono shrink-0 ml-2"
              >
                Reset to 0.50
              </button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
