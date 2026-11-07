import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ShieldAlert } from "lucide-react";

export default function DeceptionGuardPage() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-purple-400" />
            Deception & Guard
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Honeypot breadcrumb placement and response safety containment policies.
          </p>
        </div>
      </div>

      <Card className="border-slate-800 bg-slate-900/40">
        <CardHeader>
          <CardTitle className="text-slate-200">Deception Assets & Guard Interlocks</CardTitle>
          <CardDescription className="text-slate-400">
            Coming in a later phase
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-400">
            High-interaction canary traps, OT process-safety gates (human-in-the-loop interlocks for critical Modbus actuators), and automated containment triggers will be introduced in Phase 2.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
