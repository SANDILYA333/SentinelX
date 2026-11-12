import type {
  AssetResponse,
  BudgetStatusResponse,
  DeceptionActivity,
  DeceptionAssetSummary,
  DeceptionOverview,
  DetectorEvaluationMetric,
  EvalSummaryResponse,
  EvaluationRunSummary,
  Event,
  GuardDecision,
  Incident,
  IncidentSummaryResponse,
  ResponseRecommendation,
  ScenarioEvaluationResult,
  Signal,
  SourceHealth,
  SystemStatusResponse,
  Technique,
  TelemetryStats,
  TimelineEvent,
} from "@contracts/index";

export function getApiBaseUrl(): string {
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL;
  }
  if (typeof window !== "undefined" && window.location.hostname) {
    return `${window.location.protocol}//${window.location.hostname}:8000`;
  }
  return "http://127.0.0.1:8000";
}

export const API_BASE_URL: string =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export interface HealthResponse {
  status: string;
  schema_version: string;
  env: string;
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${getApiBaseUrl()}/health`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Health check failed: ${res.statusText}`);
  }
  return res.json();
}

export interface EventQueryParams {
  limit?: number;
  before?: string;
  since?: string;
  source_tool?: string;
  domain?: string;
  category?: string;
  host?: string;
  user?: string;
  ip?: string;
}

export async function fetchEvents(params?: number | EventQueryParams): Promise<Event[]> {
  const url = new URL(`${getApiBaseUrl()}/api/v1/events`);
  if (typeof params === "number") {
    url.searchParams.set("limit", params.toString());
  } else if (params) {
    if (params.limit) url.searchParams.set("limit", params.limit.toString());
    if (params.before) url.searchParams.set("before", params.before);
    if (params.since) url.searchParams.set("since", params.since);
    if (params.source_tool) url.searchParams.set("source_tool", params.source_tool);
    if (params.domain) url.searchParams.set("domain", params.domain);
    if (params.category) url.searchParams.set("category", params.category);
    if (params.host) url.searchParams.set("host", params.host);
    if (params.user) url.searchParams.set("user", params.user);
    if (params.ip) url.searchParams.set("ip", params.ip);
  }

  const res = await fetch(url.toString(), {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch events: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEventById(eventId: string): Promise<Event> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/events/${encodeURIComponent(eventId)}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch event ${eventId}: ${res.statusText}`);
  }
  return res.json();
}

export interface SignalQueryParams {
  limit?: number;
  before?: string;
  since?: string;
  detector?: string;
  entity?: string;
  min_confidence?: number;
}

export async function fetchSignals(params?: number | SignalQueryParams): Promise<Signal[]> {
  const url = new URL(`${getApiBaseUrl()}/api/v1/signals`);
  if (typeof params === "number") {
    url.searchParams.set("limit", params.toString());
  } else if (params) {
    if (params.limit) url.searchParams.set("limit", params.limit.toString());
    if (params.before) url.searchParams.set("before", params.before);
    if (params.since) url.searchParams.set("since", params.since);
    if (params.detector) url.searchParams.set("detector", params.detector);
    if (params.entity) url.searchParams.set("entity", params.entity);
    if (params.min_confidence !== undefined) {
      url.searchParams.set("min_confidence", params.min_confidence.toString());
    }
  }

  const res = await fetch(url.toString(), {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch signals: ${res.statusText}`);
  }
  return res.json();
}

export interface SignalWithEvidence extends Signal {
  evidence_events: Event[];
}

export async function fetchSignalById(signalId: string): Promise<SignalWithEvidence> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/signals/${encodeURIComponent(signalId)}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch signal ${signalId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSourcesHealth(): Promise<SourceHealth[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/sources/health`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch sources health: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchStats(windowSeconds: number = 300): Promise<TelemetryStats> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/stats?window_seconds=${windowSeconds}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch telemetry stats: ${res.statusText}`);
  }
  return res.json();
}

export async function emitTestEvent(): Promise<Event> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/dev/emit-test-event`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to emit test event: ${res.statusText}`);
  }
  return res.json();
}

export interface IncidentQueryParams {
  status?: string;
  min_score?: number;
  since?: string;
  limit?: number;
}

export interface IncidentWithEvidence extends Incident {
  signals: Signal[];
  evidence_events: Event[];
}

export async function fetchIncidents(params?: IncidentQueryParams): Promise<Incident[]> {
  const url = new URL(`${getApiBaseUrl()}/api/v1/incidents`);
  if (params) {
    if (params.status) url.searchParams.set("status", params.status);
    if (params.min_score !== undefined) url.searchParams.set("min_score", params.min_score.toString());
    if (params.since) url.searchParams.set("since", params.since);
    if (params.limit) url.searchParams.set("limit", params.limit.toString());
  }

  const res = await fetch(url.toString(), {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch incidents: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchIncidentById(incidentId: string): Promise<IncidentWithEvidence> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/incidents/${encodeURIComponent(incidentId)}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch incident ${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchIncidentTimeline(incidentId: string): Promise<TimelineEvent[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/incidents/${encodeURIComponent(incidentId)}/timeline`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch incident timeline ${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function evaluateGuardAction(
  action: string,
  target: string,
  incidentId?: string,
): Promise<GuardDecision> {
  const url = incidentId
    ? `${getApiBaseUrl()}/api/v1/incidents/${encodeURIComponent(incidentId)}/guard-action`
    : `${getApiBaseUrl()}/api/v1/guard/evaluate`;

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, target, incident_id: incidentId }),
  });
  if (!res.ok) {
    throw new Error(`Failed to evaluate guard action: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchGuardDecisions(limit: number = 20): Promise<GuardDecision[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/guard/decisions?limit=${limit}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch guard decisions: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchGuardDecisionById(decisionId: string): Promise<GuardDecision> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/guard/decisions/${encodeURIComponent(decisionId)}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch guard decision ${decisionId}: ${res.statusText}`);
  }
  return res.json();
}

export async function approveGuardDecision(
  decisionId: string,
  actor: string = "analyst",
  notes?: string
): Promise<GuardDecision> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/guard/decisions/${encodeURIComponent(decisionId)}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ actor, notes }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Failed to approve guard decision: ${res.statusText}`);
  }
  return res.json();
}

export async function rejectGuardDecision(
  decisionId: string,
  actor: string = "analyst",
  notes?: string
): Promise<GuardDecision> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/guard/decisions/${encodeURIComponent(decisionId)}/reject`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ actor, notes }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Failed to reject guard decision: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchGuardRecommendations(incidentId: string): Promise<ResponseRecommendation[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/guard/recommendations/${encodeURIComponent(incidentId)}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch guard recommendations: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchDeceptionOverview(): Promise<DeceptionOverview> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/deception/overview`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch deception overview: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchDeceptionActivities(
  incidentId?: string,
  limit: number = 100
): Promise<DeceptionActivity[]> {
  const url = new URL(`${getApiBaseUrl()}/api/v1/deception/activities`);
  url.searchParams.set("limit", limit.toString());
  if (incidentId) {
    url.searchParams.set("incident_id", incidentId);
  }
  const res = await fetch(url.toString(), {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch deception activities: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchDeceptionActivity(activityId: string): Promise<DeceptionActivity> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/deception/activities/${encodeURIComponent(activityId)}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch deception activity ${activityId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchDeceptionAssets(): Promise<DeceptionAssetSummary[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/deception/assets`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch deception assets: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchBudget(): Promise<BudgetStatusResponse> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/budget`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch budget status: ${res.statusText}`);
  }
  return res.json();
}

export async function setBudgetThreshold(threshold: number): Promise<BudgetStatusResponse> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/budget`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ threshold }),
  });
  if (!res.ok) {
    throw new Error(`Failed to update budget threshold: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAssets(): Promise<AssetResponse[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/assets`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch assets: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchMitreTechniques(): Promise<Technique[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/mitre/techniques`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch MITRE techniques: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSystemStatus(): Promise<SystemStatusResponse> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/status`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch system status: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvalSummary(): Promise<EvalSummaryResponse> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/eval/summary`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evaluation summary: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchIncidentSummary(incidentId: string): Promise<IncidentSummaryResponse> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/incidents/${incidentId}/summary`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch incident summary: ${res.statusText}`);
  }
  return res.json();
}

export async function generateIncidentSummary(
  incidentId: string,
  refresh: boolean = false
): Promise<IncidentSummaryResponse> {
  const res = await fetch(
    `${getApiBaseUrl()}/api/v1/incidents/${incidentId}/summary?refresh=${refresh}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    }
  );
  if (!res.ok) {
    throw new Error(`Failed to generate incident summary: ${res.statusText}`);
  }
  return res.json();
}

export interface EvaluationOverviewResponse {
  latest_run_id: string;
  created_at: string;
  git_commit: string;
  dataset_version: string;
  splits_evaluated: string[];
  headline: {
    tp: number;
    fp: number;
    fn: number;
    tn: number;
    precision: number | null;
    recall: number | null;
    f1_score: number | null;
    accuracy: number | null;
    fpr: number | null;
    fnr: number | null;
  };
  event_level: {
    tp: number;
    fp: number;
    fn: number;
    tn: number;
    precision: number | null;
    recall: number | null;
    f1_score: number | null;
    accuracy: number | null;
    fpr: number | null;
    fnr: number | null;
  };
  scenario_level: {
    tp: number;
    fp: number;
    fn: number;
    tn: number;
    precision: number | null;
    recall: number | null;
    f1_score: number | null;
    accuracy: number | null;
    fpr: number | null;
    fnr: number | null;
  };
  incident_level: {
    tp: number;
    fp: number;
    fn: number;
    tn: number;
    precision: number | null;
    recall: number | null;
    f1_score: number | null;
    accuracy: number | null;
    fpr: number | null;
    fnr: number | null;
  };
  throughput_eps: number;
  p95_latency_ms: number;
  total_historical_runs: number;
}

export interface EvaluationRunListItem {
  run_id: string;
  created_at: string;
  git_commit?: string;
  dataset_version?: string;
  splits_evaluated?: string[];
  splits?: string[];
  headline_precision?: number | null;
  headline_recall?: number | null;
  headline_f1?: number | null;
  headline_accuracy?: number | null;
  p95_latency_ms?: number | null;
  headline: {
    tp?: number;
    fp?: number;
    fn?: number;
    tn?: number;
    precision: number | null;
    recall: number | null;
    f1_score: number | null;
    accuracy: number | null;
  };
  throughput_eps: number;
}

export async function fetchEvaluationOverview(): Promise<EvaluationOverviewResponse> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/evaluation/overview`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evaluation overview: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvaluationRuns(limit: number = 20): Promise<EvaluationRunListItem[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/evaluation/runs?limit=${limit}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evaluation runs: ${res.statusText}`);
  }
  const rawList = await res.json();
  return (rawList || []).map((item: Record<string, unknown>) => {
    const rawHeadline = (item.headline as Record<string, unknown>) || {};
    return {
      ...item,
      run_id: String(item.run_id || ""),
      created_at: String(item.created_at || ""),
      git_commit: String(item.git_commit || ""),
      dataset_version: String(item.dataset_version || ""),
      splits: Array.isArray(item.splits) ? item.splits : Array.isArray(item.splits_evaluated) ? item.splits_evaluated : [],
      splits_evaluated: Array.isArray(item.splits_evaluated) ? item.splits_evaluated : Array.isArray(item.splits) ? item.splits : [],
      throughput_eps: typeof item.throughput_eps === "number" ? item.throughput_eps : 0,
      headline: {
        tp: typeof rawHeadline.tp === "number" ? rawHeadline.tp : 0,
        fp: typeof rawHeadline.fp === "number" ? rawHeadline.fp : 0,
        fn: typeof rawHeadline.fn === "number" ? rawHeadline.fn : 0,
        tn: typeof rawHeadline.tn === "number" ? rawHeadline.tn : 0,
        precision: typeof item.headline_precision === "number" ? item.headline_precision : typeof rawHeadline.precision === "number" ? rawHeadline.precision : null,
        recall: typeof item.headline_recall === "number" ? item.headline_recall : typeof rawHeadline.recall === "number" ? rawHeadline.recall : null,
        f1_score: typeof item.headline_f1 === "number" ? item.headline_f1 : typeof rawHeadline.f1_score === "number" ? rawHeadline.f1_score : null,
        accuracy: typeof item.headline_accuracy === "number" ? item.headline_accuracy : typeof rawHeadline.accuracy === "number" ? rawHeadline.accuracy : null,
      },
    } as EvaluationRunListItem;
  });
}

export async function fetchEvaluationRun(runId: string): Promise<EvaluationRunSummary> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/evaluation/runs/${runId}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evaluation run ${runId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvaluationScenarios(
  runId: string,
  params?: { category?: string; split?: string; classification?: string }
): Promise<ScenarioEvaluationResult[]> {
  const query = new URLSearchParams();
  if (params?.category) query.set("category", params.category);
  if (params?.split) query.set("split", params.split);
  if (params?.classification) query.set("classification", params.classification);

  const qs = query.toString() ? `?${query.toString()}` : "";
  const res = await fetch(`${getApiBaseUrl()}/api/v1/evaluation/runs/${runId}/scenarios${qs}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evaluation scenarios: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvaluationDetectors(runId: string): Promise<DetectorEvaluationMetric[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/evaluation/runs/${runId}/detectors`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evaluation detectors: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvaluationFalsePositives(runId: string): Promise<Record<string, unknown>[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/evaluation/runs/${runId}/false-positives`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evaluation false positives: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvaluationFalseNegatives(runId: string): Promise<Record<string, unknown>[]> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/evaluation/runs/${runId}/false-negatives`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evaluation false negatives: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerEvaluationRun(
  splits: string[] = ["dev", "validation", "test"],
  budgetThreshold: number = 0.50
): Promise<EvaluationRunSummary> {
  const res = await fetch(`${getApiBaseUrl()}/api/v1/evaluation/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ splits, budget_threshold: budgetThreshold }),
  });
  if (!res.ok) {
    throw new Error(`Failed to trigger evaluation run: ${res.statusText}`);
  }
  return res.json();
}
