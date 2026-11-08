import type { Event, Signal, SourceHealth, TelemetryStats } from "@contracts/index";

export const API_BASE_URL: string =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface HealthResponse {
  status: string;
  schema_version: string;
  env: string;
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE_URL}/health`, {
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
  const url = new URL(`${API_BASE_URL}/api/v1/events`);
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
  const res = await fetch(`${API_BASE_URL}/api/v1/events/${encodeURIComponent(eventId)}`, {
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
  const url = new URL(`${API_BASE_URL}/api/v1/signals`);
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
  const res = await fetch(`${API_BASE_URL}/api/v1/signals/${encodeURIComponent(signalId)}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch signal ${signalId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSourcesHealth(): Promise<SourceHealth[]> {
  const res = await fetch(`${API_BASE_URL}/api/v1/sources/health`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch sources health: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchStats(windowSeconds: number = 300): Promise<TelemetryStats> {
  const res = await fetch(`${API_BASE_URL}/api/v1/stats?window_seconds=${windowSeconds}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch telemetry stats: ${res.statusText}`);
  }
  return res.json();
}

export async function emitTestEvent(): Promise<Event> {
  const res = await fetch(`${API_BASE_URL}/api/v1/dev/emit-test-event`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    throw new Error(`Failed to emit test event: ${res.statusText}`);
  }
  return res.json();
}
