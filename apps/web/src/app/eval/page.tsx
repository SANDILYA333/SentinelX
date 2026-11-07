import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FlaskConical } from "lucide-react";

export default function EvalPage() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <FlaskConical className="w-6 h-6 text-emerald-400" />
            Evaluation & Benchmarks
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Offline PCAP replay, synthetic scenario benchmarks, and detection fidelity scores.
          </p>
        </div>
      </div>

      <Card className="border-slate-800 bg-slate-900/40">
        <CardHeader>
          <CardTitle className="text-slate-200">Platform Evaluation Suite</CardTitle>
          <CardDescription className="text-slate-400">
            Coming in a later phase
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-400">
            Living-off-the-land detection benchmarks, precision/recall verification harnesses, and TTFMA metric dashboards will be integrated in Phase 3.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

