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
  explanation: Explanation;
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
