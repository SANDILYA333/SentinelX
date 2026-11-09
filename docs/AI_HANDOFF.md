# SentinelX: Definitive AI Assistant & Technical Engineering Handoff

> **Document Purpose:** Self-contained operational handoff enabling a new AI assistant, principal engineer, or hackathon evaluator to immediately understand, navigate, reproduce, test, and continue developing the SentinelX platform without requiring access to prior conversation context.  
> **Repository Commit Baseline:** Commit [`664e6bb`](https://github.com/innovasia/SentinelX/commit/664e6bb) on branch `main`  
> **Status:** All core phases (Phase 0 through Phase 8.2) implemented, integrated, and verified by passing test suites and empirical scorecards.

---

## A. Project Identity & Hackathon Context

- **Project Name:** SentinelX
- **Hackathon Challenge:** Problem Statement PS-06: "IT/OT Threat Hunter"
- **Domain:** Converged Enterprise Information Technology (IT) and Industrial Operational Technology (OT / SCADA / ICS) threat detection, deception, and response safety.
- **Core Objective:** Provide automated, multi-engine detection of Living-off-the-Land (LotL) cyber-physical attack campaigns across IT/OT boundaries, correlate discrete signals into kill-chain incidents, gate alerts against an operational budget threshold ($\theta = 0.50$), enforce state-dependent response safety interlocks on physical industrial controllers, and synthesize grounded AI forensic briefings with prompt injection defenses.
- **Intended Users:**
  1. *SOC Tier-2/3 Security Analysts & Incident Responders:* Investigating converged enterprise-to-SCADA intrusions with graph-linked telemetry evidence.
  2. *OT Control Systems Engineers:* Protecting physical actuators and programmable logic controllers from dangerous automated cyber containment actions.
  3. *Hackathon Judges & Technical Evaluators:* Auditing detection recall, false positive rates, architecture modularity, and demo reproducibility.
- **Final Product Vision:** A unified cyber-physical defense platform bridging enterprise SIEMs (Wazuh, Windows Event Logs) and industrial control networks (Modbus, DNP3, CIP), combining zero-false-positive deception tripwires with safety-governed automated response.

---

## B. Current Project State

- **Current Git Branch:** `main`
- **Current HEAD Commit:** [`664e6bb0bcf097f666b20baa5f61828744387df3`](https://github.com/innovasia/SentinelX/commit/664e6bb)
- **Latest Commit Message:** `fix(llm): complete Phase 8.2 V5 regex guard, headline verification, and evidence ranking`
- **Working-Tree Status:** Documentation and verification scripts added; zero modifications to engine, services, apps, or evaluation source code.
- **Latest Completed Phase:** **Phase 8.2** (Grounding verifier hardening, Rule V5 non-verdict regex guard with entity masking, headline verification fallback, and slow-burn evidence relevance ranking).
- **What Works:**
  - 14 Docker container lab across 4 isolated subnets (`it`, `dmz`, `ot`, `mgmt`), all with `internal: true`.
  - Asynchronous file tailer with inode and offset checkpointing in SQLite.
  - 6 telemetry normalization adapters (`wazuh`, `zeek`, `cowrie`, `opencanary`, `plc`, `generic` YAML).
  - 5 independent detection engines (`rule`, `baseline`, `anomaly`, `graph`, `deception`).
  - 15-minute sliding temporal window correlator with 5-stage progression scoring and session-aware OT boost.
  - Alert budget controller gating alerts at $\theta = 0.50$ (0.000 FP/24h on 25.0h simulated benign data; 95% UB: 2.876 FP/24h).
  - Response Safety Guard inspecting real-time PLC physics state, deterministically denying controller isolation mid-manipulation.
  - Next.js 15 web application with real-time WebSocket streaming, interactive `@xyflow/react` attack graph, and Presenter Mode.
  - LLM analyst summary layer using Google Gemini with structured output, V1–V6 Python grounding verification, and zero-downtime template fallback.
  - Master evaluation harness (`make eval-full`) reproducing LOO cross-validation, 4-tier ablation, and Windows DC benchmarks.
- **What Remains Unfinished / Deferred:**
  - Automated containment execution is advisory only (returns binding safety verdicts, but does not push live switch port shutdowns).
  - OT protocol support currently limited to Modbus TCP.
  - SQLite single-node persistence (sufficient for local replay $> 160$ eps, but not distributed across clusters).
  - API endpoints lack authentication and RBAC.

---

## C. System Architecture & Tech Stack

```text
+---------------------------------------------------------------------------------------------------+
|                        PHYSICAL & NETWORK TESTBED (14 DOCKER CONTAINERS)                          |
|  Attacker (10.10.1.5) | IT Subnet (jump, file, db, eng) | DMZ (cowrie, canary) | OT (plc-sim, decoy)|
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                        SENSOR & TELEMETRY COLLECTION LAYER                                        |
|  Wazuh archives.json  | audit-shell cmd.jsonl | Zeek conn/modbus logs | Honey/PLC JSONL logs      |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                        INGESTION & NORMALIZATION SUBSYSTEM                                        |
|  Async Inode Tailer ---> 6 Normalization Adapters ---> Canonical Event Stream (Strict Schema)     |
+---------------------------------------------------------------------------------------------------+
                                                  |
               +----------------------------------+----------------------------------+
               |                  |               |                  |               |
               v                  v               v                  v               v
        [ Rules Engine ]   [ Baselines ]   [ Isolation ]      [ Interaction ]   [ Deception ]
        Context Policies   User Profiles   Forest Anomaly     Graph Edges/Scans  Honeytokens
               |                  |               |                  |               |
               +----------------------------------+----------------------------------+
                                                  | Emitted Signals
                                                  v
+---------------------------------------------------------------------------------------------------+
|                        CORRELATION, SCORING & SAFETY SUBSYSTEM                                    |
|  1. Sliding Window & Entity Clustering (15-min window across IP, host, user)                      |
|  2. Kill-Chain Progression Scoring (Stages: Initial Access -> Discovery -> Creds -> Move -> OT)   |
|  3. Context Multipliers: Honeytoken Boost (+0.35) | Session-Aware OT (+0.35) | Novelty Cap (0.40) |
|  4. Alert Budget Controller (Threshold theta = 0.50 gates uncorroborated noise)                   |
|  5. Response Safety Guard (Inspects live PLC physics: DENIES controller isolation mid-attack)    |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                        PERSISTENCE & SERVICE BACKEND                                              |
|  SQLite WAL Database (idempotent primary keys) <---> FastAPI Backend & WebSocket Stream (port 8000)|
+---------------------------------------------------------------------------------------------------+
                                    |                               |
                                    v                               v
+---------------------------------------+       +---------------------------------------------------+
|   ADVISORY LLM SUMMARY SUBSYSTEM      |       |             ANALYST WEB DASHBOARD                 |
|  Bounded Evidence & Secret Redaction  |       |  Next.js 15, Tailwind v4, React Flow Graph        |
|  Gemini 3.5/3.8 Flash (Structured)    |       |  Live WebSocket Feed (capped at 20 events/sec)    |
|  Python Grounding Verifier (V1 - V6)  | ----> |  State-Dependent Guard Action Dialogs             |
|  Deterministic Template Fallback      |       |  Presenter Mode (Clean Demo Presentation)        |
+---------------------------------------+       +---------------------------------------------------+
```

### Technology Stack & Versions
- **Backend Core:** Python `3.12.13`, Pydantic `2.7.0+`, Scikit-Learn `1.9.1+`, NetworkX `3.7+`, PyYAML `6.0+`.
- **API & WebSockets:** FastAPI `0.110.0+`, Uvicorn `0.28.0+`, WebSockets `12.0+`.
- **Generative AI:** Google GenAI SDK `google-genai>=3.0.0` (Gemini 3.5 Flash / Gemini 3.8 Flash).
- **Frontend Dashboard:** Next.js `15.5.29`, React `19.1.0`, `@xyflow/react` `12.12.1`, Dagre `0.8.5`, Tailwind CSS `4.0`, Zustand `5.0.16`.
- **Package & Runtime Management:** `uv` (`>=0.4.0`) workspace managing `engine` and `services/api`; `pnpm` (`>=9.0.0`) managing `apps/web`.

---

## D. Repository Structure & Key Entry Points

```text
SentinelX/
├── apps/
│   └── web/                     # Next.js 15 frontend application
│       └── src/
│           ├── app/             # App Router pages (Overview, Incidents, Graph, Deception, Eval, Signals)
│           ├── components/      # UI components (evidence-drawer, budget-gauge, graph-nodes, sidebar)
│           └── lib/             # API client, store (Zustand), WebSocket client
├── content/                     # Declarative configuration & detection policies
│   ├── assets.yaml              # Single source of truth for lab asset topology, criticality, & honeytokens
│   ├── detectors.yaml           # Ablation study toggles and engine thresholds
│   ├── guard/                   # Response safety actions catalog and safety policies
│   ├── mappings/                # Generic YAML adapters (windows_security.yaml, modbus_csv.yaml)
│   ├── mitre/                   # MITRE ATT&CK Enterprise and ICS mapping catalogs
│   ├── rules/                   # Declarative YAML condition trees (RULE-AUTH, NET, CRED, SHELL, OT, DECOY)
│   └── scenarios/               # Attack scenario definitions (baseline.yaml, reordered.yaml, slow_burn.yaml)
├── docs/                        # Authoritative documentation suite
│   ├── AI_HANDOFF.md            # This document: definitive technical handoff for AI assistants & engineers
│   ├── PROJECT_OVERVIEW.md      # Master architecture, verification, reality audit, and quantitative facts
│   ├── PHASE_HISTORY.md         # Phase-by-phase development history, defect fixes, and commit references
│   ├── QA_FOR_JUDGES.md         # Hard questions and evidence-grounded answers for judges & evaluators
│   └── REPO_MAP.md              # Programmatically generated repository inventory and route/schema tables
├── engine/                      # Core headless Python detection, correlation, and safety engine
│   ├── sentinelx/
│   │   ├── budget/              # Alert Budget Controller (threshold calibration and gating)
│   │   ├── correlate/           # Multi-stage kill-chain correlator, scoring, and stage taxonomy
│   │   ├── detect/              # 5 independent detectors (rules, baseline, anomaly, graph, runtime)
│   │   ├── enrich/              # MITRE ATT&CK catalog enricher
│   │   ├── guard/               # Response Safety Guard evaluator and physical PLC interlocks
│   │   ├── ingest/              # Asynchronous file tailer and 6 normalization adapters
│   │   ├── llm/                 # Gemini client, evidence packet builder, verifier (V1-V6), template fallback
│   │   ├── normalize/           # Asset inventory resolver and zone boundary enricher
│   │   ├── schemas/             # Frozen core data contracts (Event, Signal, Incident, Guard) and API models
│   │   └── store/               # SQLite WAL persistence layer
│   └── tests/                   # Engine pytest suite (test_detectors, test_correlator, test_llm_summary, etc.)
├── eval/                        # Evaluation harnesses, datasets, and benchmark reports
│   ├── captures/                # 8 telemetry captures (5 benign days, 3 attack variants) with SHA-256 manifests
│   ├── fixtures/                # Third-party Windows EVTX enterprise control fixtures
│   ├── reports/                 # Authoritative scorecard.md and incident_eval_summary.json
│   ├── ablation.py              # 4-tier detector ablation harness
│   ├── eval_full.py             # Master evaluation runner (make eval-full)
│   ├── metrics.py               # Leave-One-Out CV, hours-based FP, and Poisson confidence bounds
│   └── organizer_test.py        # Third-party enterprise log evaluation harness
├── lab/                         # Reproducible Docker cyber-physical lab testbed
│   ├── compose.yml              # 14 containers, 4 isolated networks (all internal: true)
│   ├── benign/                  # Poisson-paced diurnal enterprise traffic generator
│   ├── decoys/                  # Cowrie SSH, OpenCanary multi-service, and Decoy PLC definitions
│   ├── hosts/                   # Debian endpoint Dockerfiles, audit-shell.sh, and attack runners
│   ├── plc-sim/                 # Operational Modbus PLC simulator with hydraulic water tank physics
│   ├── wazuh/                   # Storage-capped Wazuh manager ossec.conf (no indexer, logall_json)
│   └── zeek/                    # Zeek promiscuous sensor scripts sniffing container bridges
├── packages/
│   └── contracts/               # Exported JSON schemas and generated TypeScript contract interfaces
├── scripts/                     # Automation, verification, and demo execution scripts
│   ├── gen_repo_map.py          # Programmatic generator for docs/REPO_MAP.md
│   ├── verify_docs.py           # Comprehensive cross-document consistency and reference verification script
│   ├── demo_preflight.py        # Live demo readiness and container health audit
│   ├── demo_reset.py            # Restores SQLite database and resets PLC physics to 55% normal
│   ├── guard_eval.py            # Executes live guard evaluation table with PLC state column
│   └── measure_latency.py       # Replay throughput and live end-to-end latency benchmark
├── services/
│   └── api/                     # FastAPI backend application service
│       ├── app/                 # Routes (events, signals, incidents, guard, budget, eval, status), main.py, ws.py
│       └── tests/               # API endpoint unit tests (test_api.py)
└── Makefile                     # Project workflow command interface
```

### Critical Execution Entry Points
- **API Server:** `uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --app-dir services/api` (`make api`).
- **Frontend Dashboard:** `cd apps/web && pnpm dev --port 3000` (`make web`).
- **Unit & Integration Tests:** `uv run pytest` (`make test`).
- **Master Evaluation Runner:** `uv run python eval/eval_full.py` (`make eval-full`).
- **Capture Ingestion & Replay:** `uv run python scripts/detect_correlate_replay.py --dir eval/captures/attack/demo_baseline --speed 50`.
- **Contract Exporter:** `uv run python scripts/export_contracts.py` (`make contracts`).
- **Documentation Verification:** `uv run python scripts/verify_docs.py`.

---

## E. Development History & Key Milestones

- **Phase 0 (Scaffold & Contracts):** Defined frozen Pydantic contracts (`Event`, `Signal`, `Incident`, `GuardDecision`, `WSMessage`). Exported TypeScript types.
- **Phase 1 & 1.1 (Docker Lab & Hardening):** Built 14-container lab across 4 subnets. Fixed critical storage exhaustion in Wazuh manager by disabling vulnerability detection feeds, mounting a 64M tmpfs on `/var/ossec/tmp`, enforcing 10m log rotation, and tuning PLC water tank physics. Substituted `audit-shell.sh` for Auditd.
- **Phase 2 & 2.1 (Ingestion & Normalization):** Implemented async file tailer with inode/offset checkpointing, 6 normalization adapters, and SQLite event persistence.
- **Phase 3 (Benign & Attack Scenarios):** Modeled diurnal Poisson benign activity across 5 days (25.0 simulated hours) with staggered start hours; implemented 3 attack scenarios (`baseline`, `reordered`, `slow_burn`); documented container startup burst artifact.
- **Phase 4 & 4.1–4.3 (Threat Detectors):** Built 5 independent engines. Rewrote brittle IP/register signatures in `RULE-AUTH-001` and `RULE-OT-001` into context-aware asset/zone policies with verified 3-case proofs.
- **Phase 5 & 5.1 (Correlator, Budget & Safety Guard):** Implemented 15-minute sliding window entity linking, progression scoring with session-aware OT boost, budget controller ($\theta = 0.50$), and state-dependent Response Safety Guard. Added PLC state column to guard evaluation table.
- **Phase 6 & 6.1 (Analyst Dashboard):** Built Next.js 15 UI with `@xyflow/react` attack graph, Presenter Mode, and live WebSocket streaming. Connected Eval UI page to live `/api/v1/eval/summary` endpoint.
- **Phase 7 & 7.1–7.4 (Evaluation Suite):** Implemented Leave-One-Out CV, 4-tier ablation study, and third-party Windows EVTX benchmark. Implemented **Novelty Corroboration Requirement** (capping novelty-only incidents at `0.4000` via additive `novelty_only: bool = False` schema field); calculated exact 95% Poisson upper confidence bound (`2.876 FP / 24h`); restated TTFMA as event-time timestamp delta.
- **Phase 8, 8.1 & 8.2 (LLM Briefing & Verifier Hardening):** Built advisory AI summary layer using Google Gemini with structured JSON output, secret redaction, and deterministic Python verifier (V1–V6). Added Rule V5 non-verdict phrase guard blocking adversary prompt injection attempts to declare attacks benign; added entity masking, headline verification fallback, and slow-burn evidence relevance ranking.

---

## F. Current Functionality: Verified vs Simulated

| Platform Capability | Implementation Reality | Supporting Evidence |
| :--- | :--- | :--- |
| **Telemetry Ingestion** | **VERIFIED:** Async tailer tracks inodes and byte offsets; reads 6 distinct log formats without duplication. | `engine/tests/test_tailer.py`, `test_samples_adapters.py` |
| **Threat Detection** | **VERIFIED:** 5 independent engines emit standardized Signals; covers 7/7 attack steps in evaluation suite. | `engine/tests/test_detectors.py`, `eval/reports/scorecard.md` |
| **Autonomous Deception** | **VERIFIED:** Honeypot interactions elevate score/confidence to 0.99 with `confirmed_honeytoken=True`. | `engine/tests/test_assets.py`, `content/rules/decoy_touch.yaml` |
| **Kill-Chain Correlation**| **VERIFIED:** 15-min window clusters entities; scores 5 stages; applies session-aware OT boost (+0.35). | `engine/tests/test_correlator_and_scoring.py` |
| **Alert Budgeting** | **VERIFIED:** Threshold $\theta = 0.50$ gates noise; 0.000 FP/24h over 25h simulated (exact 95% UB: 2.876). | `engine/tests/test_budget.py`, `eval/reports/scorecard.md` |
| **Response Safety Guard** | **VERIFIED (Advisory):** State-dependent interlocks DENY controller isolation while PLC flag is manipulated. | `engine/tests/test_guard.py`, `scripts/guard_eval.py` table output |
| **Industrial Control** | **SIMULATED:** Software PLC simulator running Modbus TCP and hydraulic water tank physics in Docker. | `lab/plc-sim/sim.py` |
| **Advisory AI Briefings**| **VERIFIED:** Gemini structured summaries audited by Python verifier (V1-V6); injection blocked by V5. | `engine/tests/test_llm_summary.py` (13 passed) |
| **Analyst Web Dashboard**| **VERIFIED:** Next.js 15 UI renders attack graphs, budget gauges, evidence drawers, and Presenter Mode. | `apps/web/src/app/`, `pnpm lint` |

---

## G. How to Work with the Project

### Environment Setup
1. Ensure Python 3.12, Node.js 20+, `pnpm`, and Docker are installed.
2. Install dependencies:
   ```bash
   make setup
   ```
3. Run verification tests:
   ```bash
   make lint
   make test
   ```

### Running the System
- **Option 1: Full Live Lab Demo (Docker Running):**
  ```bash
  # 1. Start lab containers
  make lab-up
  # 2. Reset state to pristine baseline
  make demo-reset
  # 3. Verify health
  make demo-preflight
  # 4. Start backend (Terminal 1)
  make api
  # 5. Start frontend (Terminal 2)
  make web
  # 6. Trigger live paced baseline attack (Terminal 3)
  make demo-attack
  ```
- **Option 2: Headless Recorded Capture Replay (Zero Containers Needed):**
  ```bash
  # Replay baseline attack capture at 50x speed
  make detect-correlate-replay DIR=eval/captures/attack/demo_baseline SPEED=50
  ```
- **Option 3: Run Master Evaluation Suite:**
  ```bash
  make eval-full
  ```

### Secrets and Environment Configuration
- The Google Gemini API key is configured in `services/api/.env.local`:
  ```bash
  GEMINI_API_KEY=<configured-in-env-local>
  GEMINI_MODEL=gemini-3.5-flash
  ```
- **Safety Rule:** `services/api/.env.local` is ignored by git and mode `0600`. Never commit API keys. The system operates 100% offline without an API key using the deterministic template engine.

---

## H. Known Issues & Architectural Blockers

1. **Living-off-the-Land Novelty Cap Blind Spot:**  
   Because novelty-only incidents are capped at `0.4000` to prevent false alarms on un-baselined hosts, a pure LotL campaign that avoids touching decoy assets, utilizes unmapped hosts, and evades all five deterministic rules will be capped below the alert threshold ($\theta = 0.50$) by design.
2. **Advisory Containment Execution:**  
   Response Safety Guard decisions are returned via REST API to the analyst UI; SentinelX does not execute active firewall changes or network interface shutdowns.
3. **In-Memory Correlator State:**  
   The sliding correlation window is evaluated in-process memory. Campaigns that pause for longer than 15 wall-clock minutes without active events will split across distinct incident IDs.
4. **Unauthenticated REST API:**  
   Endpoints and WebSocket feeds have no authentication tokens or user session validation.

---

## I. Prioritized Next Development Steps

### P0: Must Fix Before Production Deployment
- **Task P0-1: Implement API Authentication & RBAC:**  
  - *Outcome:* Secure REST routes and WebSocket streams with JWT bearer authentication and role-based permissions (`analyst`, `admin`, `auditor`).  
  - *Files (planned):* `services/api/app/main.py`, `services/api/app/config.py`, planned `auth.py`.  
  - *Dependencies:* `python-jose`, `passlib`.  
  - *Acceptance Criteria:* Unauthenticated API requests receive HTTP 401; unauthorized role actions receive HTTP 403.
- **Task P0-2: Safe Active Containment Connectors:**  
  - *Outcome:* Implement modular active response drivers (e.g. Linux iptables/nftables, pfSense REST API) that execute approved perimeter IP blocks.  
  - *Files (planned):* Planned connectors module under `engine/sentinelx/guard/`, `engine/sentinelx/guard/evaluator.py`.  
  - *Acceptance Criteria:* When Guard verdict is `ALLOW`, connector applies firewall drop rule; provides automatic rollback after configurable timeout.

### P1: Important Polish Before Final Hackathon Submission
- **Task P1-1: Browser End-to-End Automated Test:**  
  - *Outcome:* Add Playwright test verifying that triggering an attack renders red attack graph nodes and displays the Guard DENY dialog in the browser.  
  - *Files (planned):* Planned end-to-end test spec `apps/web/e2e/demo.spec.ts`.  
  - *Dependencies:* `@playwright/test`.  
  - *Acceptance Criteria:* Headless browser launches, connects to API WebSocket, and asserts DOM element visibility.
- **Task P1-2: Export Incident Forensic PDF Report:**  
  - *Outcome:* Add a button to the Incidents page exporting verified LLM claims, cited events, and graph images as a PDF.  
  - *Files (planned):* `apps/web/src/app/incidents/page.tsx`, planned export component.  
  - *Acceptance Criteria:* Clicking export downloads formatted incident brief.

### P2: Valuable Architectural Improvements
- **Task P2-1: PostgreSQL / TimescaleDB Storage Migration:**  
  - *Outcome:* Replace SQLite WAL persistence with TimescaleDB hyper-tables for events and incidents.  
  - *Files (planned):* `engine/sentinelx/store/sqlite.py` $\rightarrow$ planned `postgres.py` store adapter.  
  - *Acceptance Criteria:* Parallel worker replay achieves $> 500$ events/s with zero database lock contention.
- **Task P2-2: Extended Industrial Protocol Adapters:**  
  - *Outcome:* Add Zeek parsers and normalization adapters for DNP3 and Ethernet/IP CIP protocols.  
  - *Files:* `engine/sentinelx/ingest/adapters/zeek.py`, `engine/sentinelx/schemas/event.py`.  
  - *Acceptance Criteria:* Ingests DNP3 function codes and extracts outstation addresses into `OTFields`.

### P3: Future Enhancements
- **Task P3-1: On-Premises Quantized SLM Deployment:**  
  - *Outcome:* Integrate local vLLM runner hosting quantized Gemma 2 9B for completely offline, air-gapped forensic summarization.  
  - *Files:* `engine/sentinelx/llm/client.py`.  
  - *Acceptance Criteria:* Generates verified summaries with $< 3.0\text{s}$ latency without outbound Internet connectivity.

---

## J. Explicit Instructions for the Next AI Assistant

1. **Read Core Documents First:**  
   - Read this document (`docs/AI_HANDOFF.md`) to establish baseline context and boundaries.  
   - Read `docs/PROJECT_OVERVIEW.md` for the definitive architectural specification, reality audit, and quantitative facts table.  
   - Read `docs/PHASE_HISTORY.md` to understand why specific historical designs were implemented or rejected.  
   - Read `docs/REPO_MAP.md` for exact file paths, line counts, and route definitions.  
   - Read `docs/QA_FOR_JUDGES.md` before answering evaluator questions.
2. **Inspect Actual Code Before Proposing Changes:**  
   - Never assume an implementation is unchanged from an earlier phase. Read the file near the target line.  
   - Always copy code excerpts directly by command (`sed -n 'A,Bp' file`); never retype or paraphrase from memory.
3. **Respect Established Architectural Constraints:**  
   - **Constraint 1:** `engine/sentinelx/` must NEVER import `fastapi`, `starlette`, or application service logic.  
   - **Constraint 2:** Detectors must run independently; never introduce cross-detector imports.  
   - **Constraint 3:** Core schemas in `engine/sentinelx/schemas/` are frozen (except the additive `novelty_only: bool = False` flag). Extended response models belong in `api_models.py`.  
   - **Constraint 4:** LLM output is strictly read-only advisory text. It must **NEVER** mutate incident scores, severity, budget thresholds, or Response Safety Guard verdicts.
4. **Never Fabricate Numbers:**  
   - Every quantitative metric must cite an exact source file and commit in `eval/reports/` or live command output.  
   - If an evaluation result cannot be verified, state that it is UNVERIFIED or NOT RUN.
5. **No Prohibited Superlatives:**  
   - Do NOT use ungrounded marketing superlatives (the five prohibited terms specified in project instructions). State evaluation caveats whenever metrics appear.
6. **Secrets & Path Hygiene:**  
   - Never print or commit values from `.env.local`. Decoy credentials in `content/assets.yaml` are fake tripwires.  
   - Never use user-specific filesystem paths (such as user home directories or system temporary directories); use repo-relative paths exclusively.
7. **Verify Everything:**  
   - Run `uv run python scripts/verify_docs.py` before completing any documentation task to ensure all line references, Makefile targets, commit hashes, and numbers are fully valid.
