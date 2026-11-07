import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { GitGraph } from "lucide-react";

export default function AttackGraphPage() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <GitGraph className="w-6 h-6 text-blue-400" />
            Attack Graph
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Interactive multi-hop attack chain reconstruction and lateral movement graphs.
          </p>
        </div>
      </div>

      <Card className="border-slate-800 bg-slate-900/40">
        <CardHeader>
          <CardTitle className="text-slate-200">Interactive Entity Graph</CardTitle>
          <CardDescription className="text-slate-400">
            Coming in a later phase
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-400">
            React Flow canvas visualization mapping host-to-PLC traversals, decoy touchpoints, and timeline sequence replay will be activated in Phase 2.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
