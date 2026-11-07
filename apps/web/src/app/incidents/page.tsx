import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle } from "lucide-react";

export default function IncidentsPage() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-6 h-6 text-amber-400" />
            Security Incidents
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Correlated attack chains, alert budgets, and MITRE kill chain stages.
          </p>
        </div>
      </div>

      <Card className="border-slate-800 bg-slate-900/40">
        <CardHeader>
          <CardTitle className="text-slate-200">Incident Command Center</CardTitle>
          <CardDescription className="text-slate-400">
            Coming in a later phase
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-400">
            Incident clustering, time-to-first-meaningful-alert (TTFMA) metrics, and MITRE ATT&CK kill chain tracking will be connected to the correlation engine in Phase 1.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
