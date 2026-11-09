/* eslint-disable */
/**
 * Auto-generated TypeScript data contracts for SentinelX.
 * DO NOT EDIT MANUALLY - Generated from Pydantic schemas via scripts/export_contracts.py
 */

export type EntityType = "user" | "host" | "ip" | "session" | "process" | "device";

export type Value = string;

/**
 * Observable entity instance.
 */

export interface Entity {
  type: EntityType;
  value: Value;
}

export type Framework = "enterprise" | "ics";

export type TechniqueId = string;

export type Name = string;

export type Tactic = string;

/**
 * MITRE ATT&CK technique mapping.
 */

export interface Technique {
  framework: Framework;
  technique_id: TechniqueId;
  name: Name;
  tactic: Tactic;
}

export type Type = "hello" | "event" | "signal" | "incident" | "guard" | "health";

export type Ts = string;

/**
 * Typed WebSocket envelope for real-time messaging.
 */

export interface WSMessage {
  type: Type;
  ts: Ts;
  payload: Payload;
}

export interface Payload {
  [k: string]: unknown;
}

export type EventId = string;

export type IngestedAt = string;
/**
 * Telemetry collection and deception source tools.
 *
 * This interface was referenced by `Event`'s JSON-Schema
 * via the `definition` "SourceTool".
 */

export type SourceTool = "wazuh" | "zeek" | "cowrie" | "opencanary" | "modbus" | "evtx" | "generic";
/**
 * Network and asset operational domain.
 *
 * This interface was referenced by `Event`'s JSON-Schema
 * via the `definition` "Domain".
 */

export type Domain = "it" | "ot" | "decoy";

export type Category =
  | "authentication"
  | "process"
  | "network"
  | "file"
  | "dns"
  | "http"
  | "ot_command"
  | "ot_state"
  | "decoy_interaction"
  | "other";

export type Action = string;
/**
 * Action execution outcome.
 *
 * This interface was referenced by `Event`'s JSON-Schema
 * via the `definition` "Outcome".
 */

export type Outcome = "success" | "failure" | "unknown";

export type Host = string | null;

export type SrcIp = string | null;

export type DstIp = string | null;

export type SrcPort = number | null;

export type DstPort = number | null;

export type Protocol = string | null;

export type User = string | null;

export type Process = string | null;

export type ParentProcess = string | null;

export type Cmdline = string | null;

export type SessionId = string | null;

export type UnitId = number | null;

export type DeviceId = string | null;

export type FunctionCode = number | null;

export type Register = number | null;

export type IsWrite = boolean;

export type Tags = string[];

/**
 * Normalized security event schema produced by all telemetry adapters.
 */

export interface Event {
  event_id: EventId;
  ts: Ts;
  ingested_at: IngestedAt;
  source_tool: SourceTool;
  domain: Domain;
  category: Category;
  action: Action;
  outcome: Outcome;
  host?: Host;
  src_ip?: SrcIp;
  dst_ip?: DstIp;
  src_port?: SrcPort;
  dst_port?: DstPort;
  protocol?: Protocol;
  user?: User;
  process?: Process;
  parent_process?: ParentProcess;
  cmdline?: Cmdline;
  session_id?: SessionId;
  ot?: OTFields | null;
  raw_ref: RawRef;
  raw: Raw;
  tags?: Tags;
}
/**
 * Operational Technology (OT/ICS) specific telemetry attributes.
 *
 * This interface was referenced by `Event`'s JSON-Schema
 * via the `definition` "OTFields".
 */

export interface OTFields {
  unit_id?: UnitId;
  device_id?: DeviceId;
  function_code?: FunctionCode;
  register?: Register;
  value?: unknown;
  is_write: IsWrite;
}

export interface RawRef {
  [k: string]: unknown;
}

export interface Raw {
  [k: string]: unknown;
}

export type SignalId = string;

export type Detector = "rule" | "baseline" | "anomaly" | "graph" | "deception";

export type RuleId = string;

export type Title = string;

export type Score = number;

export type Confidence = number;
/**
 * Observable entity types for graph and correlation analysis.
 *
 * This interface was referenced by `Signal`'s JSON-Schema
 * via the `definition` "EntityType".
 */

export type Entities = Entity[];
/**
 * @minItems 1
 */

export type EvidenceEventIds = [string, ...string[]];

export type Techniques = Technique[];

export type Explanation = string;

/**
 * Detection signal emitted by detectors (detectors emit signals, never raw alerts).
 */

export interface Signal {
  signal_id: SignalId;
  ts: Ts;
  detector: Detector;
  rule_id: RuleId;
  title: Title;
  score: Score;
  confidence: Confidence;
  entities: Entities;
  evidence_event_ids: EvidenceEventIds;
  techniques: Techniques;
  explanation: Explanation;
  metadata?: Metadata;
}
/**
 * Observable entity instance.
 *
 * This interface was referenced by `Signal`'s JSON-Schema
 * via the `definition` "Entity".
 */

export interface Metadata {
  [k: string]: unknown;
}

export type IncidentId = string;

export type Status = "open" | "closed" | "suppressed";

export type CreatedAt = string;

export type UpdatedAt = string;

export type FirstSignalTs = string;

export type FirstMeaningfulAlertTs = string | null;
/**
 * Event-time TTFMA: elapsed event-time seconds from incident start to threshold crossing, NOT processing latency; processing latency not measured in replay; measured live in the demo rehearsal (Phase 8)
 */

export type TtfmaSeconds = number | null;

export type Severity = "low" | "medium" | "high" | "critical";
/**
 * Observable entity types for graph and correlation analysis.
 *
 * This interface was referenced by `Incident`'s JSON-Schema
 * via the `definition` "EntityType".
 */

export type SignalIds = string[];

export type EventIds = string[];

export type KillChainStages = string[];

export type DecoyTouched = boolean;

export type OtTouched = boolean;

export type NoveltyOnly = boolean;

export type Summary = string | null;

export type SummaryCitations = string[];

export type Id = string;

export type Label = string;

export type Nodes = GraphNode[];

export type Source = string;

export type Target = string;

export type Label1 = string;

export type EventIds1 = string[];

export type Edges = GraphEdge[];

/**
 * Correlated attack incident reconstructed across IT/OT domains.
 */

export interface Incident {
  incident_id: IncidentId;
  status: Status;
  created_at: CreatedAt;
  updated_at: UpdatedAt;
  first_signal_ts: FirstSignalTs;
  first_meaningful_alert_ts?: FirstMeaningfulAlertTs;
  ttfma_seconds?: TtfmaSeconds;
  score: Score;
  severity: Severity;
  entities: Entities;
  signal_ids: SignalIds;
  event_ids: EventIds;
  kill_chain_stages: KillChainStages;
  techniques: Techniques;
  decoy_touched: DecoyTouched;
  ot_touched: OtTouched;
  novelty_only?: NoveltyOnly;
  explanation: string[];
  summary?: Summary;
  summary_citations?: SummaryCitations;
  graph?: IncidentGraph | null;
}
/**
 * Observable entity instance.
 *
 * This interface was referenced by `Incident`'s JSON-Schema
 * via the `definition` "Entity".
 */

export interface IncidentGraph {
  nodes: Nodes;
  edges: Edges;
}
/**
 * Node in an incident correlation graph.
 *
 * This interface was referenced by `Incident`'s JSON-Schema
 * via the `definition` "GraphNode".
 */

export interface GraphNode {
  id: Id;
  type: Type;
  label: Label;
}
/**
 * Edge connecting nodes in an incident correlation graph.
 *
 * This interface was referenced by `Incident`'s JSON-Schema
 * via the `definition` "GraphEdge".
 */

export interface GraphEdge {
  source: Source;
  target: Target;
  label: Label1;
  ts: Ts;
  event_ids: EventIds1;
}

export type DecisionId = string;

export type Decision = "allow" | "deny" | "needs_human";

export type Reasons = string[];

export type RuleIds = string[];

export type AssetCriticality = ("low" | "medium" | "high" | "process_critical") | null;

export type RequestedBy = string;

/**
 * Response safety policy decision evaluating proposed containment action.
 */

export interface GuardDecision {
  decision_id: DecisionId;
  ts: Ts;
  incident_id?: IncidentId;
  action: Action;
  target: Target;
  decision: Decision;
  reasons: Reasons;
  rule_ids: RuleIds;
  asset_criticality?: AssetCriticality;
  requested_by: RequestedBy;
}

export type SourceKey = string;

export type RelativePath = string;

export type ExpectedActive = boolean;

export type LinesRead = number;

export type EventsEmitted = number;

export type Unparsed = number;

export type Errors = number;

export type LastEventTs = string | null;

export type LastEventAgeSec = number | null;

export type LastError = string | null;

/**
 * Health status and telemetry volume counters for an ingestion source.
 */

export interface SourceHealth {
  source_key: SourceKey;
  source_tool: SourceTool;
  relative_path: RelativePath;
  status: SourceStatus;
  expected_active: ExpectedActive;
  lines_read: LinesRead;
  events_emitted: EventsEmitted;
  ignored: Ignored;
  unparsed: Unparsed;
  errors: Errors;
  last_event_ts?: LastEventTs;
  last_event_age_sec?: LastEventAgeSec;
  last_error?: LastError;
}

export interface Ignored {
  [k: string]: number;
}

export type WindowSeconds = number;

export type TotalEvents = number;

export type EventsPerSec = number;

/**
 * Aggregate telemetry event metrics computed over a sliding time window.
 */

export interface TelemetryStats {
  window_seconds: WindowSeconds;
  total_events: TotalEvents;
  events_per_sec: EventsPerSec;
  by_source: BySource;
  by_category: ByCategory;
  by_domain: ByDomain;
}

export interface BySource {
  [k: string]: number;
}

export interface ByCategory {
  [k: string]: number;
}

export interface ByDomain {
  [k: string]: number;
}

export type Hostname = string | null;

export type Role = string;

export type Zone = string;

export type IsDecoy = boolean;

export type ProcessCritical = boolean;

export type Criticality = string;

export type AllowedOtWriters = string[];

/**
 * Network, computing, or industrial asset representation.
 */

export interface AssetResponse {
  name: Name;
  hostname?: Hostname;
  role: Role;
  zone: Zone;
  ips?: Ips;
  is_decoy?: IsDecoy;
  process_critical?: ProcessCritical;
  criticality: Criticality;
  allowed_ot_writers?: AllowedOtWriters;
}

export interface Ips {
  [k: string]: string;
}

export type Threshold = number;

export type FpPer24HEstimate = number;

export type AttackRecallEstimate = number;

export type CalibrationMethod = string;

export type Threshold1 = number;

export type FpPer24H = number;

export type Recall = number;

export type Recommendation = string;

export type CalibrationPoints = CalibrationPoint[];

/**
 * Alert budget operational threshold, FP estimates, and calibration matrix.
 */

export interface BudgetStatusResponse {
  threshold: Threshold;
  fp_per_24h_estimate?: FpPer24HEstimate;
  attack_recall_estimate?: AttackRecallEstimate;
  status?: Status;
  calibration_method?: CalibrationMethod;
  calibration_points?: CalibrationPoints;
}
/**
 * Precision/recall calibration operating point from cross-validation.
 *
 * This interface was referenced by `BudgetStatusResponse`'s JSON-Schema
 * via the `definition` "CalibrationPoint".
 */

export interface CalibrationPoint {
  threshold: Threshold1;
  fp_per_24h: FpPer24H;
  recall: Recall;
  recommendation: Recommendation;
}

export type Env = string;

export type IngestMode = string;

export type ReplaySpeed = string;

export type IngestRunning = boolean;

export type DbConnected = boolean;

export type EventsCount = number;

export type SignalsCount = number;

export type IncidentsCount = number;

export type BudgetThreshold = number;

/**
 * Platform system status, telemetry pipeline mode, and live counts.
 */

export interface SystemStatusResponse {
  status: Status;
  env: Env;
  ingest_mode: IngestMode;
  replay_speed: ReplaySpeed;
  ingest_running: IngestRunning;
  db_connected: DbConnected;
  events_count: EventsCount;
  signals_count: SignalsCount;
  incidents_count: IncidentsCount;
  budget_threshold: BudgetThreshold;
}

export type ScenarioType = string;

export type DisplayType = string;

export type Hours = string;

export type Events = number;

export type Signals = number;

export type Incidents = number;

export type TtfmaFromFirstSignalSeconds = number | null;
/**
 * Event-time TTFMA from attack start: difference between event timestamps, NOT processing latency
 */

export type TtfmaFromAttackStartSeconds = number | null;

export type Captures = CaptureEvalRow[];

export type BenignFpPer24H = number;

export type BenignHoursTotal = number;

export type BenignSimulatedDays = number;

export type BenignFpUpperBound95 = number;

export type AttackRecall = number;
/**
 * Mean event-time TTFMA: difference between event timestamps (event.ts), NOT processing latency; processing latency not measured in replay; measured live in the demo rehearsal (Phase 8)
 */

export type MeanTtfmaSeconds = number | null;
/**
 * Mean event-time TTFMA from first signal: difference between event timestamps, NOT processing latency
 */

export type MeanTtfmaFromFirstSignalSeconds = number | null;
/**
 * Mean event-time TTFMA from attack start: difference between event timestamps, NOT processing latency
 */

export type MeanTtfmaFromAttackStartSeconds = number | null;

export type GuardOtInterlock = string;

export type EvaluatedAt = string;

export type Headline = {
  [k: string]: unknown;
} | null;

export type Ablation =
  | {
      [k: string]: unknown;
    }[]
  | null;

export type ThresholdCurve =
  | {
      [k: string]: unknown;
    }[]
  | null;

export type DetectorRanking =
  | {
      [k: string]: unknown;
    }[]
  | null;

export type OrganizerTest = {
  [k: string]: unknown;
} | null;

/**
 * Aggregate benchmark matrix across all 8 verified captures.
 */

export interface EvalSummaryResponse {
  captures: Captures;
  benign_fp_per_24h: BenignFpPer24H;
  benign_hours_total?: BenignHoursTotal;
  benign_simulated_days?: BenignSimulatedDays;
  benign_fp_upper_bound_95?: BenignFpUpperBound95;
  attack_recall: AttackRecall;
  mean_ttfma_seconds?: MeanTtfmaSeconds;
  mean_ttfma_from_first_signal_seconds?: MeanTtfmaFromFirstSignalSeconds;
  mean_ttfma_from_attack_start_seconds?: MeanTtfmaFromAttackStartSeconds;
  guard_ot_interlock?: GuardOtInterlock;
  evaluated_at: EvaluatedAt;
  threshold?: Threshold;
  headline?: Headline;
  ablation?: Ablation;
  threshold_curve?: ThresholdCurve;
  detector_ranking?: DetectorRanking;
  organizer_test?: OrganizerTest;
}
/**
 * Evaluation summary metrics for a single capture dataset.
 *
 * This interface was referenced by `EvalSummaryResponse`'s JSON-Schema
 * via the `definition` "CaptureEvalRow".
 */

export interface CaptureEvalRow {
  name: Name;
  scenario_type: ScenarioType;
  display_type: DisplayType;
  hours: Hours;
  events: Events;
  signals: Signals;
  incidents: Incidents;
  score?: Score;
  severity?: Severity;
  ttfma_seconds?: TtfmaSeconds;
  ttfma_from_first_signal_seconds?: TtfmaFromFirstSignalSeconds;
  ttfma_from_attack_start_seconds?: TtfmaFromAttackStartSeconds;
  status: Status;
  decoy_touched?: DecoyTouched;
  ot_touched?: OtTouched;
  kill_chain_stages?: KillChainStages;
}

export type SourceStatus = "live" | "idle" | "stale" | "error";
