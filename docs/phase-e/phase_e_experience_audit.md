# SentinelX Phase E — Comprehensive Product Experience Audit

**Document Status:** Final  
**Date:** 2026-11-11  
**Scope:** Frontend Codebase (`apps/web/`), Backend API Contracts (`services/api/`), Navigation, Core Analyst Workflows, and Visual Coherence.

---

## 1. Executive Summary

SentinelX has evolved through Phases A–D into a technically sound, cyber-physical threat detection and response safety engine with verified mathematical precision, kill-chain correlation, and deterministic safety enforcement. However, because features were added across consecutive engineering milestones, the user interface currently exhibits fragmentation:

1. **Information Architecture Fragmentation:** The sidebar presents a flat list of six items without visual grouping, conflating operational telemetry monitoring (`/` Overview), detection signals (`/signals`), incident investigations (`/incidents`), attack graphs (`/graph`), deception and response safety (`/deception`), and offline evaluation (`/eval`).
2. **Visual & Token Inconsistency:** While semantic colors exist in `theme.ts`, individual components re-implement custom Tailwind classes, resulting in varying borders, glow effects, badge styling, and padding.
3. **Investigation Workflow Disconnect:** Analysts investigating an incident in `/incidents` must manually navigate to `/graph?incident_id=...` without a direct return link or preserved view state, and relevant Response Safety Guard decisions for that incident are not visible within the incident detail view itself.
4. **Safety Boundary Communication:** While the Response Safety Guard backend is strictly non-bypassable and advisory-only, the frontend UI must communicate the boundary between an advisory policy verdict (`ALLOW`), human supervisor review (`NEEDS_HUMAN`), and real-world system execution (which SentinelX intentionally never executes automatically).
5. **Evaluation Metric Transparency:** In Phase D, an audit uncovered critical nuances (event recall: 50.00% vs. attack detection: 100.0%, detector coverage gaps for baseline/anomaly, campaign leakage across splits, and technique attribution evaluated capture-wide). The evaluation UI must display these distinctions with total transparency rather than obscuring them.
6. **State Lifecycle & Resilience:** WebSockets are established per-page rather than globally, triggering reconnect cycles and redundant HTTP hydration requests on every page navigation. Disconnected, loading, and empty states vary in design and quality across routes.

---

## 2. Area-by-Area Deep Audit

### 2.1 Main Dashboard (`/` — `apps/web/src/app/page.tsx`)

- **Intended Purpose:** Provide real-time operational situational awareness: environment health, active incidents, telemetry ingress velocity, budget status, and recent threat events.
- **Primary User:** SOC Lead / Shift Supervisor / OT Security Engineer.
- **Main User Action:** Assess current operational status, verify ingest health, inspect highest-severity active incident, and monitor live event velocity.
- **Information Hierarchy:**
  1. Header with WebSocket status, event rate counter, and Dev Emit button.
  2. ReplayStatusBar (Ingest mode, speed, event/signal counts).
  3. Centerpiece grid: Alert Budget Controller gauge & Most Recent Correlated Incident.
  4. Telemetry Sources health cards (13 sources).
  5. Live normalized event stream table with domain/source filters and search.
- **Identified UX Friction & Inconsistencies:**
  - *Layout Density & Visual Competing:* The Budget Controller gauge is placed side-by-side with the Correlated Incident card, giving them equal visual weight even though one is an operational tuning control and the other is an active threat alert.
  - *Excessive Vertical Space for Telemetry Sources:* 13 individual cards take up significant vertical real estate even when all sources are idle or normal. A condensed table or categorized status bar would be significantly easier to scan.
  - *Developer Controls in Production View:* The "Dev Emit" button is displayed unless presenter mode is explicitly activated. In a professional SOC platform, developer test triggers should be placed in a dedicated test or dev menu.
  - *Missing Navigation Bridge:* Clicking an incident in the Recent Incident card navigates to `/incidents`, but does not focus the specific incident ID in the detail view unless explicitly wired.
- **Missing States:**
  - Initial loading skeleton for telemetry stats and source health.
  - Clear zero-state if the event filter matches 0 events.
  - Offline recovery action that automatically polls health without manual page reload.
- **Accessibility & Responsive Issues:**
  - Event table overflows horizontally on tablet/narrow viewports.
  - Contrast on dark blue badges (`bg-blue-950 text-blue-400`) requires verification for WCAG AA compliance.

---

### 2.2 Incident Management List (`/incidents` — `apps/web/src/app/incidents/page.tsx`)

- **Intended Purpose:** Enable analysts to triage, sort, filter, and prioritize correlated attack incidents generated across IT, DMZ, and OT environments.
- **Primary User:** Tier 1 / Tier 2 Incident Responder.
- **Main User Action:** Identify high-priority active incidents, filter by severity or kill-chain stage, and select an incident for detailed investigation.
- **Information Hierarchy:**
  1. Header with summary metrics (Total, Critical, High, Active).
  2. Left Pane: Search bar, status filters, and scrollable list of incident cards.
  3. Right Pane: Selected incident full investigation view.
- **Identified UX Friction & Inconsistencies:**
  - *Fixed Narrow Width for Incident List:* The left column is constrained to a fixed narrow width on large displays, truncating titles and badges while leaving the right pane with excessive white space.
  - *Search Scope:* Search only matches `incident_id`, `category`, and `summary`. Analysts frequently need to search by affected IP address (e.g. `10.10.1.40`), hostname (`eng-ws`), or rule ID (`RULE-OT-001`).
  - *Lack of Sorting:* Incidents are sorted only by score descending. Analysts cannot sort by newest first, last activity, or severity.
  - *Score vs Confidence Confusion:* Incident `score` represents kill-chain progression progression ($0.0 - 1.0$), while individual signal `confidence` represents detector certainty. The UI must clearly label these to prevent analyst misinterpretation.
- **Missing States:**
  - Empty state when no incidents match the search query or selected severity filter.
  - Loading skeleton for the incident list during initial hydration.

---

### 2.3 Incident Details View (`/incidents` Detail Pane)

- **Intended Purpose:** Comprehensive deep-dive investigation into a specific incident: root cause, kill-chain timeline, contributing signals, original evidence provenance, affected entities, MITRE ATT&CK mapping, and advisory intelligence summary.
- **Primary User:** Tier 2 / Tier 3 Senior Security Analyst / Forensic Investigator.
- **Main User Action:** Review evidence, generate/review advisory analyst summary, verify ground-truth telemetry, and launch attack graph visualization.
- **Information Hierarchy:**
  1. Incident header with ID, severity, progression score, status, and Attack Graph launch button.
  2. Executive Summary card (LLM or template fallback with explicit badge).
  3. Kill-Chain Progression visualizer (chronological stage chips).
  4. Contributing Signals list (detector type, rule ID, severity, timestamp, evidence link).
  5. Affected Entities & Assets chip grid.
  6. MITRE ATT&CK technique matrix with descriptions.
- **Identified UX Friction & Inconsistencies:**
  - *Missing Response Safety Guard Decisions:* Although Response Safety Guard evaluates actions relevant to the incident's target assets (e.g. `eng-ws`, `plc-sim`), these decisions are absent from the incident detail page, requiring the analyst to navigate elsewhere to review safety policy.
  - *One-Way Navigation to Graph:* The "Open in Attack Graph" button links to `/graph?incident_id=...`, but the Attack Graph view provides no breadcrumb or link back to `/incidents?id=...`.
  - *Evidence Drawer Context Loss:* Clicking an evidence link opens the drawer, but closing it can lose focus on the currently selected signal.
- **Missing States:**
  - Error state with retry if `/api/v1/incidents/{id}` fails.
  - Explicit indicator when an incident has no MITRE techniques mapped.

---

### 2.4 Attack Graph (`/graph` — `apps/web/src/app/graph/page.tsx`)

- **Intended Purpose:** Visualize cyber-physical attack paths, lateral movement between network zones (External, IT, DMZ, OT, Mgmt), decoy engagements, and targeted industrial control assets.
- **Primary User:** Threat Hunter / Incident Commander.
- **Main User Action:** Trace attacker progression across network zones, inspect node/edge evidence, and correlate structural topology with temporal playback.
- **Information Hierarchy:**
  1. Top bar: Incident selector, timeline playback toggle, Response Guard recommendations drawer toggle.
  2. React Flow canvas with zoned backgrounds and directed edges.
  3. Bottom scrubber: AttackTimeline with step controls.
  4. Right inspector: EvidenceInspector showing selected node/edge/event details.
- **Identified UX Friction & Inconsistencies:**
  - *Fixed Coordinate Layout Overlap:* `getZonedLayout` uses fixed pixel column anchors (`ZONE_X_COORDS`). For complex graphs, nodes can overlap vertically or extend offscreen.
  - *Distinction of Relationship Types:* Edges currently use color coding (Modbus=rose, Pivot=amber, Auth=blue), but the distinction between *Observed Telemetry* (direct communication), *Inferred Kill Chain Edge* (correlated multi-step hop), and *Configured Network Link* is not visually distinct enough without a legend.
  - *Missing Visual Legend:* There is no persistent legend on the canvas explaining node border styles (Decoy=purple, Critical=rose, Attacker=red) or edge colors.
  - *Fit-to-View Accessibility:* While React Flow controls exist in the corner, a prominent "Fit View" button in the canvas toolbar is essential.
- **Missing States:**
  - Empty state when the selected incident has no graph nodes or edges.
  - Loading skeleton while graph data is fetched from the API.

---

### 2.5 Timeline Playback (`apps/web/src/components/attack-timeline.tsx`)

- **Intended Purpose:** Step-by-step or automated chronological reconstruction of the exact sequence of events that formed an incident.
- **Primary User:** Forensic Analyst / Security Auditor.
- **Main User Action:** Play, pause, scrub, step backward/forward, adjust replay speed, and inspect active event.
- **Information Hierarchy:**
  1. Playback controls (Restart, Step Back, Play/Pause, Step Forward, Speed Selector, Event Index).
  2. Horizontally scrollable event card strip.
  3. Active event highlight ring.
- **Identified UX Friction & Inconsistencies:**
  - *No Keyboard Controls:* Forensic analysts expect Spacebar to toggle play/pause and Arrow Left/Right to step backward/forward.
  - *Relative Forensics Timestamps:* Events display local wall-clock time (`HH:MM:SS`), but lack delta-time from incident inception (`+00:00`, `+01:24`, etc.), which is critical for understanding attack velocity.
  - *Empty Timeline Behavior:* If an incident has no events, the timeline renders an empty container without user guidance.

---

### 2.6 Deception Intelligence (`/deception` — `apps/web/src/app/deception/page.tsx`)

- **Intended Purpose:** Track hostile interactions with high-interaction decoys (Cowrie SSH, OpenCanary services, Decoy Modbus PLC), classify attacker intent, and monitor canary containment.
- **Primary User:** Deception Operator / Threat Intelligence Analyst.
- **Main User Action:** Review decoy interaction stream, inspect full interaction telemetry in modal, and verify that attacker engagement is contained within decoys.
- **Information Hierarchy:**
  1. Deception overview metrics (Total interactions, unique attacker IPs, decoys touched, containment rate).
  2. Tab bar ("Deception Intelligence" vs "Response Safety Guard").
  3. Left column: Interaction feed with severity and attacker details.
  4. Right column: Deception asset inventory table.
- **Identified UX Friction & Inconsistencies:**
  - *Conflated Route:* Housing both Deception Intelligence and Response Safety Guard under `/deception` with tab switching causes confusion. Guard is an enterprise safety system that deserves prominent first-class navigation.
  - *Observed vs Inferred Distinction:* Attacker intent classifications (e.g., "Reconnaissance", "Credential Brute Force") are not explicitly demarcated as *Inferred Intent* vs *Directly Observed Telemetry* (e.g., "SSH Authentication Failure").
  - *Missing Incident Linkage:* If a decoy interaction contributed to an active incident, there is no direct link to view that incident in `/incidents` or `/graph`.

---

### 2.7 Response Safety Guard (`apps/web/src/components/response-guard-panel.tsx` & `/deception`)

- **Intended Purpose:** Evaluate containment actions against safety policies before execution, preventing automated or human mistakes that could trip safety instrumented systems or cause industrial damage.
- **Primary User:** OT Safety Lead / Incident Commander.
- **Main User Action:** Review recommended response actions, verify safety policy reasoning, approve or reject `NEEDS_HUMAN` recommendations, and confirm that `DENY` is enforced.
- **Information Hierarchy:**
  1. Advisory mode banner: SentinelX operates in advisory-only mode.
  2. Interactive action evaluation tester.
  3. Decision cards: Action, Target, Decision badge (`ALLOW`, `DENY`, `NEEDS_HUMAN`), Policy Rule ID, Safety Reasoning, Target Criticality & Zone.
  4. Human supervisor review form (for `NEEDS_HUMAN` decisions).
- **Identified UX Friction & Inconsistencies:**
  - *Execution Boundary Ambiguity:* The distinction between a policy decision (`ALLOW`), human supervisor approval, and real-world system execution must be unmistakable. `ALLOW` must never be misconstrued as "action has been executed on the host/firewall/PLC".
  - *Native Browser Alerts:* Approval and rejection handlers use JavaScript `alert()` for errors. This must be replaced with professional toast notifications.
  - *Confirmation Dialog Missing:* Approving or rejecting a high-impact safety decision should require an explicit confirmation modal.

---

### 2.8 Detection Evaluation Dashboard (`/eval` — `apps/web/src/app/eval/page.tsx`)

- **Intended Purpose:** Present quantitative detection effectiveness metrics, benchmark results, latency distributions, and detector coverage across ground-truth dataset splits.
- **Primary User:** Detection Engineer / Evaluation Auditor / Platform Evaluator.
- **Main User Action:** Audit event-level vs scenario-level metrics, review detector coverage, inspect attribution discrepancies, compare evaluation runs, and trigger new benchmark runs.
- **Information Hierarchy:**
  1. Header with dataset version, git commit, and Run Evaluation trigger.
  2. Mode Selector: Phase D Formal Framework vs Legacy Phase 7.
  3. Sub-tabs: Overview, Detectors, Scenarios, Attribution & Gaps, Performance, History.
  4. Metric scorecards: Headline, Event-Level, Scenario-Level, Incident-Level, Attack Detection, Rule Attribution, Technique Attribution.
- **Identified Discrepancies & UX Requirements:**
  - *Technique Attribution Reconciliation:* In ground truth v1.0.0, `SCEN-DEC-001` expected `T1078` and `SCEN-DEC-002` expected `T1046`, while the decoy rule emitted `T1021.004` and `T0846`. The evaluation engine previously reported 100% technique attribution because it checked if *any* signal in the multi-stage capture emitted the technique. The UI must clearly disclose this evaluation nuance in the Attribution & Gaps tab.
  - *Dataset Limitation Disclosure:* All 9 malicious scenarios across Dev, Validation, and Test derive from slices of the same capture replay (`demo_baseline`). The dashboard must feature a permanent Dataset Limitation note explaining that the test split does not represent an independent attack campaign.
  - *Detector Status (Baseline & Anomaly):* The dashboard must visibly explain why `baseline` and `anomaly` are labeled `NOT EVALUATED` in ground truth v1.0.0 (0 benchmark scenarios assigned, despite being active in pipeline).
  - *Event Recall (50.00%) vs Attack Detection (100.0%):* Contrast SIEM event-level recall against multi-stage incident detection so users understand that 50% event recall is normal SIEM fan-out, not missed attacks.

---

### 2.9 Asset & System Information Views

- **Intended Purpose:** Allow operators to inspect protected cyber-physical assets, sensors, network topologies, and decoy placements.
- **Current State:** Assets are returned by `/api/v1/assets`, but only exposed as nodes in the attack graph or rows in the deception inventory.
- **Improvement:** Introduce a clean, accessible Asset Inventory modal or drawer accessible globally from the sidebar and header.

---

### 2.10 Navigation, Application Shell & State Management

- **Navigation:** Sidebar has 6 items in a flat structure. Grouping into logical sections (*Overview*, *Investigation*, *Threat Intelligence*, *Validation*) improves cognitive clarity.
- **WebSocket Connection Lifecycle:** Currently, `useEventStream()` is invoked in every page component, causing WebSocket teardown and reconnection on route changes. Moving the connection to the application provider level ensures a single, persistent real-time stream.
- **Responsive Layout:** On viewports under 1024px, the sidebar collapsibility, split panes, and graph controls require fluid CSS and responsive drawer patterns.

---

## 3. Prioritized Defect & Enhancement Backlog

| Priority | ID | Area | Description | Resolution Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **P0** | SEC-01 | Response Guard | Ensure execution boundary is unmistakable: `ALLOW` is advisory-only; SentinelX never executes automated commands. | Add prominent Safety Boundary banners, advisory disclaimers, and eliminate any ambiguity regarding execution. |
| **P0** | EVAL-01 | Evaluation UI | Disclose technique attribution evaluation nuance (`SCEN-DEC-001/002`), campaign leakage across splits, and uncalibrated detector status. | Add detailed Methodology & Limitations callout cards to `/eval` and reconcile metrics. |
| **P1** | ARCH-01 | Application Shell | Global WebSocket stream lifecycle in `Providers` to prevent connection thrashing and redundant re-hydration on navigation. | Lift `useEventStream` connection logic to `Providers`, keeping Zustand store synchronized globally. |
| **P1** | NAV-01 | Sidebar & Nav | Restructure navigation into logical sections (Overview, Investigation, Threat Intelligence, Validation) with mobile drawer. | Update `Sidebar` with categorized hierarchy, active route indicators, mobile hamburger toggle, and environment pill. |
| **P1** | WORK-01 | Incident Detail | Add Response Safety Guard decisions to Incident Detail view and provide bidirectional navigation between Incidents and Attack Graph. | Embed relevant Guard decisions inside Incident Detail; add back-link from `/graph` to `/incidents`. |
| **P1** | GRAPH-01 | Attack Graph | Distinguish observed vs inferred vs configured edges with visual styling, add canvas legend and Fit-to-View button. | Update React Flow edge styling (solid, dashed, dotted), add persistent on-canvas legend, and toolbar controls. |
| **P1** | TIME-01 | Attack Timeline | Add keyboard shortcuts (Space=play/pause, Left/Right=step), relative timestamps (`+MM:SS`), and robust empty state. | Implement keydown listeners, delta timestamp formatter, and empty state component in `AttackTimeline`. |
| **P2** | DS-01 | Design System | Consolidate design tokens, unified badges, metric cards, detail panels, and replace native `alert()` with toasts. | Create `design-system.md`, build reusable UI components (`MetricCard`, `StatusBadge`, `Toast`, `EmptyState`). |
| **P2** | DEC-01 | Deception UI | Add direct incident navigation links from deception activities and clearly label inferred attacker intent vs observed action. | Add Incident Link pill to `DeceptionFeed` and explicit "Observed vs Inferred" chip to `DeceptionModal`. |
| **P2** | DASH-01 | Dashboard | Optimize telemetry sources layout (compact collapsible grid/table), remove "Dev Emit" from default view, improve hierarchy. | Redesign telemetry source cards into compact status table; move dev tools behind a clean dropdown/flag. |
| **P2** | A11Y-01 | Accessibility | Ensure WCAG AA contrast, visible focus rings, ARIA roles, and responsive layouts down to 768px. | Audit Tailwind color tokens, add focus-visible styles, and test responsive layouts. |
| **P3** | ASSET-01 | Asset Inventory | Provide global Asset Topology modal/drawer from the sidebar to inspect all 14 cyber-physical assets and sensors. | Implement `AssetInventoryModal` using existing `/api/v1/assets` contract. |

---

## 4. Verification & Testing Strategy

Each workstream will be verified according to:
1. **Functional Verification:** Verify all routes render correctly with live backend data and simulated edge cases.
2. **Safety & Correctness Verification:** Verify Response Safety Guard decisions remain non-bypassable and advisory-only.
3. **Evaluation Integrity:** Confirm all evaluation metrics reflect actual persisted benchmark results without distortion.
4. **Automated Quality:** Full pass on `uv run pytest`, `pnpm run lint`, `pnpm run build`, and browser-based validation.
5. **Visual Documentation:** Headless browser screenshots of all major views stored in `docs/phase-e/screenshots/`.
