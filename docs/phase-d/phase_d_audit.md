# SentinelX Phase D — Detection Evaluation & System Performance Audit

## 1. Executive Summary

SentinelX has successfully achieved core incident correlation, scoring, persistence, and alert filtering (Phase A), an evidence-backed attack graph with chronological timeline playback (Phase B), and deception intelligence with response safety guards (Phase C).

The primary objective of **Phase D** is to establish a rigorous, reproducible, deterministic, and evidence-backed evaluation framework. This framework measures how effectively SentinelX detects malicious activity across IT, DMZ, and OT environments, quantifies false positives and false negatives, benchmarks detection and correlation latency, evaluates the alert budget controller, and provides transparent visibility via evaluation APIs and an interactive evaluation dashboard.

This audit assesses the current state of detection, correlation, and evaluation in the SentinelX codebase and details the design for Phase D workstreams (D0 through D7).

---

## 2. Existing Detection & Correlation Architecture

### 2.1 Detection Engine Portfolio
The detection pipeline (`engine/sentinelx/detect/runtime.py`) orchestrates five detection mechanisms:
1. **Rule Engine (`engine/sentinelx/detect/rules/engine.py`):**
   - Matches incoming canonical `Event` objects against declarative YAML rules in `content/rules/`.
   - Generates typed `Signal` objects containing severity, confidence, MITRE ATT&CK techniques, and rule metadata.
2. **Baseline Detector (`engine/sentinelx/detect/baseline/detector.py`):**
   - Maintains statistical z-score baselines over moving windows of normal telemetry.
   - Identifies volumetric deviations in network and event flow rates.
3. **Anomaly Detector (`engine/sentinelx/detect/anomaly/detector.py`):**
   - Employs Scikit-learn's Isolation Forest on numerical and categorical feature vectors.
   - Flags out-of-distribution event patterns.
4. **Interaction Graph Detector (`engine/sentinelx/detect/graph/detector.py`):**
   - Tracks dynamic asset interaction topologies and degree anomalies across network zones.
   - Flags novel communication paths or sudden hub formations.
5. **Deception Intelligence (`engine/sentinelx/deception/`):**
   - Classifies interactions with Cowrie SSH/telnet honeypots, OpenCanary services, and Decoy PLCs.
   - Produces high-fidelity deception signals indicating targeted adversary reconnaissance or lateral movement.

### 2.2 Correlation & Alert Budgeting
- **Graph Correlator (`engine/sentinelx/correlate/engine.py`):**
  - Clusters signals by shared entities (IPs, hostnames, user accounts) and temporal proximity into `Incident` objects.
  - Computes composite risk scores using multi-stage kill-chain progression and asset criticality.
- **Alert Budget Controller (`engine/sentinelx/correlate/budget.py`):**
  - Manages signal ingestion budgets to prevent analyst alert fatigue while preserving high-severity threat detections.

---

## 3. Existing Evaluation Capabilities & Limitations

### 3.1 Existing Evaluation Artifacts
- **Telemetry Captures (`eval/captures/`):**
  - 3 attack captures: `demo_baseline`, `reordered`, `slow_burn`.
  - 5 benign captures: `day_101`, `day_102`, `day_103`, `day_104`, `day_105`.
- **Existing Evaluation Scripts:**
  - `eval/metrics.py`: Computes incident-level precision, recall, and F1 across the 8 captures with Leave-One-Out (LOO) cross-validation for benign folds.
  - `eval/ablation.py`: Executes "Drop-One" detector ablations to measure single-detector dependencies.
  - `eval/eval_full.py`: Unified harness for ablation, LOO, organizer test, and scorecard generation (`eval/reports/scorecard.md`, `eval/reports/incident_eval_summary.json`).
  - `scripts/measure_latency.py`: Basic processing latency script measuring elapsed times for batch runs.

### 3.2 Key Limitations Identified
1. **Coarse Binary Granularity:** Current evaluation primarily measures capture-level binary outcomes (incident present vs absent). It lacks granular **scenario-level** and **event-level** ground truth.
2. **Missing Formal Scenario Ground-Truth Schemas:** The repository lacks a standardized Pydantic schema for scenarios (`EvaluationScenario`) specifying expected signals, expected MITRE tactics, target assets, ground-truth classification (malicious vs benign), and expected detection rules.
3. **No Per-Rule Performance Breakdown:** The existing system evaluates detectors as monolithic blocks without isolating which specific YAML rules generate true positives versus false positives.
4. **Coarse Latency Tracking:** Ingest latency ($L_{ingest}$), detector latency ($L_{detect}$), correlation latency ($L_{corr}$), and end-to-end latency ($L_{e2e}$) are not recorded on individual items or aggregated into percentiles (P50, P90, P95, P99).
5. **No Alert Budget Suppression Evaluation:** The Alert Budget Controller has not been empirically verified to ensure that noise reduction does not suppress critical attacks.
6. **No Historical Persistence or Evaluation API:** Evaluation results are saved only to static markdown and JSON files. There is no SQLite storage for evaluation runs and no full REST API under `/api/v1/evaluation/*` supporting background runs and historical run diffing.
7. **Frontend `/eval` Page Gaps:** The current UI displays static cards and ablation summaries without interactive drill-downs into false positives, false negatives, detector comparisons, scenario inspection, or latency distributions.

---

## 4. Phase D Target Architecture

```
+-----------------------------------------------------------------------------------+
|                           Ground Truth Dataset (D1)                              |
|  - Pydantic Schemas: EvaluationScenario, ExpectedDetection, GroundTruthDataset    |
|  - Curated Scenarios across IT, DMZ, OT, Deception, and Benign Environments       |
|  - Dataset Splitting: dev, validation, held-out test                              |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                        Detection Evaluation Engine (D2)                           |
|  - Multi-level metrics: Event-Level, Scenario-Level, Incident-Level               |
|  - Metrics: TP, FP, FN, TN, Precision, Recall, F1, FPR, FNR, TTD                 |
|  - Per-Detector & Per-Rule Granular Performance Breakdown                         |
|  - False Positive & False Negative Extraction with Root-Cause Evidence Linkages   |
+-----------------------------------------------------------------------------------+
             |                                                  |
             v                                                  v
+-----------------------------+                    +--------------------------------+
| Latency & Performance (D3)  |                    | Alert Budget Evaluation (D4)   |
| - L_ingest, L_detect        |                    | - Admitted vs Suppressed Alert |
| - L_corr, L_e2e, TTD        |                    | - High-Severity Preservation   |
| - Quantiles: P50..P99       |                    | - Noise Reduction Verification |
| - Throughput (EPS)          |                    +--------------------------------+
+-----------------------------+                                 |
             \                                                 /
              v                                               v
+-----------------------------------------------------------------------------------+
|                       Evaluation API & Persistence (D5)                           |
|  - SQLite Tables: evaluation_runs, evaluation_scenario_results                    |
|  - Endpoints: /api/v1/evaluation/runs, /detectors, /scenarios, /performance, etc. |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                       Evaluation Dashboard & Analyst UX (D6)                      |
|  - Next.js /eval page with KPI Cards, Detector Matrix, Drill-Down Modal           |
|  - Latency & Throughput Quantile Charts, Historical Run Comparison                |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                       Regression & Automation Suite (D7)                          |
|  - `make eval` target, 100% Phase A/B/C regression preservation                   |
|  - Comprehensive pytest suite & final implementation report                       |
+-----------------------------------------------------------------------------------+
```

---

## 5. Workstream Breakdown & Deliverables

- **Workstream D0:** Repository Audit & Evaluation Design (`docs/phase-d/phase_d_audit.md`).
- **Workstream D1:** Ground Truth & Evaluation Dataset:
  - `engine/sentinelx/schemas/eval.py`: Pydantic data models.
  - `eval/scenarios/`: Ground truth scenario definitions spanning IT, DMZ, OT, and Deception.
  - `scripts/validate_evaluation_dataset.py`: Validation script for dataset integrity.
- **Workstream D2:** Detection Evaluation Engine:
  - `engine/sentinelx/eval/engine.py`: Multi-level evaluation engine calculating metrics with rigorous zero-division protection.
  - `docs/phase-d/evaluation_methodology.md` & `docs/phase-d/metric_definitions.md`.
- **Workstream D3:** Detection Latency & System Performance:
  - Latency metric collector measuring $L_{ingest}, L_{detect}, L_{corr}, L_{e2e}$, and TTD across percentiles (P50, P90, P95, P99).
  - Throughput (events/sec, signals/sec) and SQLite database performance under load.
  - `scripts/eval_load_benchmark.py` and `docs/phase-d/performance_methodology.md`.
- **Workstream D4:** Alert Quality & Alert Budget Evaluation:
  - Verification that Alert Budget Controller reduces alert volume without suppressing critical OT or high-risk incidents.
- **Workstream D5:** Evaluation API & Persistence:
  - Schema migration in `engine/sentinelx/store/sqlite.py` for evaluation runs and scenario results.
  - FastAPI endpoints in `services/api/app/routes/evaluation.py`.
- **Workstream D6:** Evaluation Dashboard & Analyst UX:
  - Enhanced `/eval` page in `apps/web/src/app/eval/page.tsx` with KPI overview, detector comparisons, scenario inspector, and latency graphs.
- **Workstream D7:** Regression & Final Implementation Report:
  - CLI harness and Makefile integration (`make eval`).
  - Unit and integration tests covering all new evaluation components.
  - `docs/phase-d/phase_d_implementation_report.md`.

---

## 6. Safety & Integrity Invariants

1. **Absolute Truth in Metrics:** Metrics will never be artificially inflated or computed over manipulated data. If an attack is missed, it must be recorded as a False Negative ($FN$). If benign activity triggers an alert, it must be recorded as a False Positive ($FP$).
2. **Zero Automated Execution:** Evaluation runs will not execute response actions on any industrial system. All Guard decisions and simulated response actions remain strictly advisory and non-destructive.
3. **No Simulated Overrides:** Ground-truth labels are immutable specifications. Detection engines must be evaluated against ground truth as-is without modifying rules or thresholds post-hoc to fit test cases.
4. **Architectural Backward Compatibility:** All existing Phase A, B, and C capabilities (APIs, incident correlation, attack graph generation, timeline playback, deception feeds, Guard evaluation) must remain fully intact and operational.

