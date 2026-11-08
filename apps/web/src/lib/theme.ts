/**
 * Centralized SentinelX Design System & Theme Definitions.
 * Strict semantic consistency across all pages for severities, detectors, domains, and kill-chain stages.
 */

export type SeverityLevel = "low" | "medium" | "high" | "critical";
export type DetectorType = "rule" | "baseline" | "anomaly" | "graph" | "deception";
export type DomainType = "it" | "ot" | "decoy";
export type GuardDecisionType = "allow" | "deny" | "needs_human";

export interface StyleTokens {
  bg: string;
  text: string;
  border: string;
  badge: string;
  dot?: string;
  glow?: string;
  bar?: string;
}

export const SEVERITY_THEME: Record<SeverityLevel, StyleTokens> = {
  low: {
    bg: "bg-blue-950/40",
    text: "text-blue-400",
    border: "border-blue-800/50",
    badge: "bg-blue-950/60 text-blue-400 border-blue-800/60",
    bar: "bg-blue-500",
    glow: "shadow-[0_0_12px_rgba(59,130,246,0.3)]",
  },
  medium: {
    bg: "bg-amber-950/40",
    text: "text-amber-400",
    border: "border-amber-800/50",
    badge: "bg-amber-950/60 text-amber-400 border-amber-800/60",
    bar: "bg-amber-500",
    glow: "shadow-[0_0_12px_rgba(245,158,11,0.3)]",
  },
  high: {
    bg: "bg-orange-950/40",
    text: "text-orange-400",
    border: "border-orange-800/50",
    badge: "bg-orange-950/60 text-orange-400 border-orange-800/60",
    bar: "bg-orange-500",
    glow: "shadow-[0_0_12px_rgba(249,115,22,0.3)]",
  },
  critical: {
    bg: "bg-red-950/40",
    text: "text-red-400",
    border: "border-red-800/50",
    badge: "bg-red-950/60 text-red-400 border-red-800/60",
    bar: "bg-red-500",
    glow: "shadow-[0_0_12px_rgba(239,68,68,0.4)]",
  },
};

export const DETECTOR_THEME: Record<DetectorType, StyleTokens> = {
  rule: {
    bg: "bg-purple-950/40",
    text: "text-purple-300",
    border: "border-purple-800/50",
    badge: "bg-purple-950/60 text-purple-300 border-purple-800/60",
  },
  baseline: {
    bg: "bg-blue-950/40",
    text: "text-blue-300",
    border: "border-blue-800/50",
    badge: "bg-blue-950/60 text-blue-300 border-blue-800/60",
  },
  anomaly: {
    bg: "bg-amber-950/40",
    text: "text-amber-300",
    border: "border-amber-800/50",
    badge: "bg-amber-950/60 text-amber-300 border-amber-800/60",
  },
  graph: {
    bg: "bg-emerald-950/40",
    text: "text-emerald-300",
    border: "border-emerald-800/50",
    badge: "bg-emerald-950/60 text-emerald-300 border-emerald-800/60",
  },
  deception: {
    bg: "bg-rose-950/40",
    text: "text-rose-300",
    border: "border-rose-800/50",
    badge: "bg-rose-950/60 text-rose-300 border-rose-800/60",
  },
};

export const DOMAIN_THEME: Record<DomainType, StyleTokens> = {
  it: {
    bg: "bg-sky-950/40",
    text: "text-sky-400",
    border: "border-sky-800/50",
    badge: "bg-sky-950/60 text-sky-400 border-sky-800/60",
    dot: "bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.7)]",
  },
  ot: {
    bg: "bg-amber-950/40",
    text: "text-amber-400",
    border: "border-amber-800/50",
    badge: "bg-amber-950/60 text-amber-400 border-amber-800/60",
    dot: "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.7)]",
  },
  decoy: {
    bg: "bg-purple-950/40",
    text: "text-purple-400",
    border: "border-purple-800/50",
    badge: "bg-purple-950/60 text-purple-400 border-purple-800/60",
    dot: "bg-purple-400 shadow-[0_0_8px_rgba(192,132,252,0.7)]",
  },
};

export const GUARD_THEME: Record<GuardDecisionType, StyleTokens> = {
  allow: {
    bg: "bg-emerald-950/40",
    text: "text-emerald-400",
    border: "border-emerald-800/50",
    badge: "bg-emerald-950/60 text-emerald-400 border-emerald-800/60",
  },
  deny: {
    bg: "bg-red-950/40",
    text: "text-red-400",
    border: "border-red-800/50",
    badge: "bg-red-950/60 text-red-400 border-red-800/60",
  },
  needs_human: {
    bg: "bg-amber-950/40",
    text: "text-amber-400",
    border: "border-amber-800/50",
    badge: "bg-amber-950/60 text-amber-400 border-amber-800/60",
  },
};

export const STAGE_ORDER: readonly string[] = [
  "initial_access",
  "discovery",
  "credential_access",
  "lateral_movement",
  "ot_impact",
] as const;

export interface StageMeta {
  label: string;
  short: string;
  badge: string;
  index: number;
}

export const STAGE_META: Record<string, StageMeta> = {
  initial_access: {
    label: "Initial Access",
    short: "Access",
    badge: "bg-sky-950/60 text-sky-300 border-sky-800/60",
    index: 0,
  },
  discovery: {
    label: "Discovery",
    short: "Recon",
    badge: "bg-indigo-950/60 text-indigo-300 border-indigo-800/60",
    index: 1,
  },
  credential_access: {
    label: "Credential Access",
    short: "Creds",
    badge: "bg-purple-950/60 text-purple-300 border-purple-800/60",
    index: 2,
  },
  lateral_movement: {
    label: "Lateral Movement",
    short: "Lateral",
    badge: "bg-amber-950/60 text-amber-300 border-amber-800/60",
    index: 3,
  },
  ot_impact: {
    label: "OT Impact",
    short: "OT Impact",
    badge: "bg-rose-950/60 text-rose-300 border-rose-800/60",
    index: 4,
  },
};

export function getSeverityStyle(severity: string | undefined): StyleTokens {
  const clean = (severity || "low").toLowerCase() as SeverityLevel;
  return SEVERITY_THEME[clean] || SEVERITY_THEME.low;
}

export function getDetectorStyle(detector: string | undefined): StyleTokens {
  const clean = (detector || "rule").toLowerCase() as DetectorType;
  return DETECTOR_THEME[clean] || DETECTOR_THEME.rule;
}

export function getDomainStyle(domain: string | undefined): StyleTokens {
  const clean = (domain || "it").toLowerCase() as DomainType;
  return DOMAIN_THEME[clean] || DOMAIN_THEME.it;
}

export function getGuardStyle(decision: string | undefined): StyleTokens {
  const clean = (decision || "needs_human").toLowerCase() as GuardDecisionType;
  return GUARD_THEME[clean] || GUARD_THEME.needs_human;
}

export function sortKillChainStages(stages: string[]): string[] {
  return [...stages].sort((a, b) => {
    const idxA = STAGE_ORDER.indexOf(a);
    const idxB = STAGE_ORDER.indexOf(b);
    const posA = idxA === -1 ? 99 : idxA;
    const posB = idxB === -1 ? 99 : idxB;
    return posA - posB;
  });
}
