import type {
  AssetResponse,
  BudgetStatusResponse,
  EvalSummaryResponse,
  Event,
  GuardDecision,
  Incident,
  Signal,
  SourceHealth,
  SystemStatusResponse,
  Technique,
  TelemetryStats,
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
