# SentinelX Phase F: Living-off-the-Land (LotL) Deception Engine
## Master Implementation Plan

**Status:** APPROVED FOR EXECUTION  
**Version:** 1.0.0  
**Phase:** Phase F  
**Date:** November 2026  

---

## 1. Implementation Sequence

The implementation is executed in 7 disciplined stages following Section 18 of the Phase F specification:

1. **Step 1: Core Data Models & Schema Contracts**
   - Extend `engine/sentinelx/schemas/deception.py` with typed models: `LotLLure`, `LotLInteraction`, `LotLHealthStatus`, `LotLAnalytics`, and updated `DeceptionInteractionType`.
   - Update `packages/contracts` and export TypeScript types.
2. **Step 2: Lure Registry, Manifest & Database Tables**
   - Implement `engine/sentinelx/deception/lotl/registry.py` and SQLite migration in `engine/sentinelx/store/sqlite.py`.
   - Implement default catalog of supported Linux lures and explicit Windows stub.
3. **Step 3: Lure Manager & Artifact Implementations**
   - Implement `engine/sentinelx/deception/lotl/manager.py` with idempotent deployment, verification, and manifest tracking.
   - Implement lure generator modules (`shell_history.py`, `ssh_keys.py`, `env_vars.py`, `config_files.py`, `shares.py`, `scheduled_tasks.py`).
4. **Step 4: Interaction Monitoring, Normalization & Telemetry Fusion**
   - Implement `engine/sentinelx/deception/lotl/monitor.py` and `normalizer.py`.
   - Integrate with `engine/sentinelx/ingest/adapters/wazuh.py` and `engine/sentinelx/deception/classifier.py`.
   - Add LotL detection rules (`RULE-LOTL-001` through `RULE-LOTL-006`) in `content/rules/`.
5. **Step 5: Backend API Routes & WebSocket Distribution**
   - Implement `services/api/app/routes/lotl.py` exposing REST endpoints for lures, interactions, health, analytics, enable, and disable.
   - Wire route into `services/api/app/main.py` and `services/api/app/ws.py`.
6. **Step 6: Frontend Dashboard Extension**
   - Extend `apps/web/src/app/deception/page.tsx` with dedicated "Living-off-the-Land" views:
     - Lure Inventory table with status badges and quick actions.
     - Real-time Interaction Feed with provenance indicators.
     - Lure Details Modal with inspection drawer.
     - Analytics KPI cards and distribution charts.
     - Multi-criteria filtering.
7. **Step 7: Verification, Lab Attack Simulation & Final Audit**
   - Unit tests (`engine/tests/test_lotl_deception.py`, `services/api/tests/test_lotl_api.py`).
   - Lab runtime attack simulation testing actual lure discovery, reading, and pivot.
   - Benign traffic validation.
   - Final audit documentation: `docs/phase-f/final_acceptance_audit.md` and `docs/phase-f/known_limitations.md`.

---

## 2. File Modification & Creation Inventory

### 2.1 Files to Create

| File Path | Description |
| :--- | :--- |
| `engine/sentinelx/deception/lotl/__init__.py` | Package init exposing registry, manager, monitor, and health modules |
| `engine/sentinelx/deception/lotl/models.py` | Typed Pydantic models for LotL lures, interactions, health, and analytics |
| `engine/sentinelx/deception/lotl/registry.py` | Lure Registry with SQLite persistence and thread-safe querying |
| `engine/sentinelx/deception/lotl/manager.py` | Lure Manager handling safe deployment, verification, checksums, and manifests |
| `engine/sentinelx/deception/lotl/monitor.py` | Interaction Monitor tracking command execution, FIM events, and network pivots |
| `engine/sentinelx/deception/lotl/normalizer.py` | Canonical event normalizer generating structured LotL events |
| `engine/sentinelx/deception/lotl/health.py` | Lure and sensor health monitor |
| `engine/sentinelx/deception/lotl/lures/shell_history.py` | Generator for synthetic `.bash_history` and `.zsh_history` |
| `engine/sentinelx/deception/lotl/lures/ssh_keys.py` | Generator for synthetic SSH keys and `.ssh/config` stanzas |
| `engine/sentinelx/deception/lotl/lures/env_vars.py` | Generator for canary environment variables with unique tokens |
| `engine/sentinelx/deception/lotl/lures/config_files.py` | Generator for synthetic Docker, Ansible, Kube, and SCADA configs |
| `engine/sentinelx/deception/lotl/lures/shares.py` | Decoy share directory structure and files |
| `engine/sentinelx/deception/lotl/lures/scheduled_tasks.py` | Generator for inert decoy scheduled tasks / cron |
| `content/rules/lotl_shell_history_read.yaml` | Detection rule for shell history access |
| `content/rules/lotl_ssh_key_harvest.yaml` | Detection rule for decoy SSH key read |
| `content/rules/lotl_config_file_read.yaml` | Detection rule for decoy infrastructure configuration discovery |
| `content/rules/lotl_share_enumeration.yaml` | Detection rule for decoy share access |
| `content/rules/lotl_canary_token_use.yaml` | Detection rule for canary token presentation |
| `content/rules/lotl_decoy_tampering.yaml` | Detection rule for decoy file modification/deletion |
| `services/api/app/routes/lotl.py` | REST endpoints for LotL lures, interactions, health, and analytics |
| `apps/web/src/components/lotl-inventory.tsx` | UI component for Lure Inventory and details modal |
| `apps/web/src/components/lotl-feed.tsx` | UI component for real-time LotL interaction feed |
| `apps/web/src/components/lotl-analytics.tsx` | UI component for LotL metrics, charts, and distribution |
| `engine/tests/test_lotl_deception.py` | Unit and integration tests for LotL engine |
| `services/api/tests/test_lotl_api.py` | API endpoint integration tests |
| `scripts/deploy_lotl_lures.py` | CLI tool to deploy or verify lures in the lab environment |
| `scripts/simulate_lotl_attack.py` | End-to-end attack simulation validating LotL telemetry |
| `docs/phase-f/architecture.md` | Phase F Master Architecture Specification |
| `docs/phase-f/implementation_plan.md` | Phase F Master Implementation Plan |
| `docs/phase-f/final_acceptance_audit.md` | Final acceptance audit report |
| `docs/phase-f/known_limitations.md` | Honest disclosures and known limitations |

### 2.2 Files to Modify

| File Path | Modification Purpose |
| :--- | :--- |
| `engine/sentinelx/schemas/deception.py` | Add LotL interaction types and export LotL data structures |
| `engine/sentinelx/store/sqlite.py` | Add `lotl_lures` and `lotl_interactions` tables and indexes |
| `engine/sentinelx/deception/classifier.py` | Extend classification rules to recognize LotL events and generate interpretations |
| `engine/sentinelx/deception/service.py` | Integrate LotL overview and metrics into deception service |
| `services/api/app/main.py` | Mount `lotl.py` router |
| `apps/web/src/lib/api.ts` | Add typed fetch client methods for LotL endpoints |
| `apps/web/src/app/deception/page.tsx` | Add LotL Deception tab, inventory, interaction feed, and analytics |
| `apps/web/src/components/sidebar.tsx` | Update navigation / tooltip indicators if necessary |
| `scripts/export_contracts.py` | Include new LotL models in contract export |

---

## 3. Risk Assessment & Safety Mitigations

| Risk | Impact | Mitigation |
| :--- | :--- | :--- |
| Overwriting legitimate user files | Data loss on lab endpoints | Lure Manager checks destination and refuses to overwrite unmanaged files. |
| Exposing valid secrets or real keys | Credential exposure | Keys are generated with distinct test metadata; passwords/tokens are canary strings. Secret redaction in API. |
| Accidental automated containment | Operational disruption | Response Safety Guard remains advisory only. Explicit `"ADVISORY SAFETY MODE"` badge. |
| High-volume noise from shell audit | Performance degradation | Specific filtering for target decoy paths; UI rate-limiting at 20 events/sec. |
| Sensor blindness on file reads | Missed detection | Combined command execution auditing (`audit-shell` / `prompt-command.sh`) with Wazuh FIM. |

---

## 4. Acceptance Criteria Checklist

- [ ] Lure Registry with metadata and SQLite persistence
- [ ] Safe, idempotent Lure Manager with deployment manifest
- [ ] 7 supported lure implementations (Linux Shell History, Decoy SSH Keys/Config, Canary Env Vars, Config Files, Shares, Scheduled Tasks, Windows stub)
- [ ] Multi-layer interaction monitoring (read, modify, delete, network pivot, auth attempt)
- [ ] Canonical event normalization with lure attribution tags
- [ ] 6 LotL detection rules and deception classification integration
- [ ] Multi-stage incident correlation linking lure discovery to network pivot
- [ ] REST API endpoints under `/api/v1/deception/lotl/`
- [ ] Next.js 15 UI with Lure Inventory, Interaction Feed, Analytics, Filtering, and Modals
- [ ] Real-time WebSocket updates
- [ ] Unit, API, and end-to-end attack simulation tests passing
- [ ] All 187 existing tests passing without regression
- [ ] Clean lint (`ruff`, `eslint`) and TypeScript compilation

