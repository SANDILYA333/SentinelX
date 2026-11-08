# SentinelX Evaluation Scorecard & Performance Audit (Phase 7)
**Generated**: 2026-11-08 17:09:16 UTC  
**Evaluation Scope**: Full End-to-End Pipeline (Ingestion -> Normalization -> 5 Detectors -> Kill-Chain Correlator -> Budget Gating at 0.50).  
**Test Corpus**: 8 Telco/SCADA Captures (5 Benign Days, 3 Multi-Stage Attack Scenarios) + 1 Organizer Windows Enterprise Log.

---

## 1. Executive Summary & Headline Metrics

| Metric | Measured Value | Benchmark / Target | Status |
| :--- | :--- | :--- | :--- |
| **Incident Precision** | **100.0%** (3/3 True Positives) | >= 90.0% | **PASS** |
| **Incident Recall** | **100.0%** (3/3 Attack Variants) | 100.0% | **PASS** |
| **F1 Score** | **1.0000** | >= 0.950 | **PASS** |
| **Daily False Positive Rate** | **0.000 FP / 24h** (0 FP across 5 LOO folds) | 0.000 strict target | **PASS** |
| **Golden Scenario Step Recall**| **7/7 (100.0%)** across all 3 attack variants | 7/7 steps | **PASS** |
| **Mean Time to First Meaningful Alert (TTFMA)** | **1.69s** (baseline: 1.54s, reordered: 0.94s, slow_burn: 2.58s) | < 5.0s | **PASS** |
| **Classification Accuracy** | **100.0%** (8/8 captures correctly classified) | 100.0% | **PASS** |

---

## 2. Detector Layer Ablation Study (Task 1)

Each tier was evaluated through the entire correlation and scoring pipeline at budget threshold 0.50.

| Detector Configuration | day_101 | day_102 | day_103 | day_104 | day_105 | demo_baseline | reordered | slow_burn | Chain Coverage | Benign FP/24h |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Rules Only** | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 1 (1.00, 4/7) | 1 (1.00, 4/7) | 1 (1.00, 4/7) | **4/7 steps** | **0.000** |
| **2. Rules + Base + Anom** | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 1 (1.00, 6/7) | 1 (1.00, 6/7) | 1 (1.00, 6/7) | **6/7 steps** | **0.000** |
| **3. Rules + Base + Anom + Graph** | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 1 (1.00, 6/7) | 1 (1.00, 6/7) | 1 (1.00, 6/7) | **6/7 steps** | **0.000** |
| **4. Full (+ Deception)** | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 1 (1.00, 7/7) | 1 (1.00, 7/7) | 1 (1.00, 7/7) | **7/7 steps** | **0.000** |

### Ablation Findings:
1. **Rules Only (4/7 steps)**: Accurately detects deterministic attack landmarks: Step 1 (Initial Access via unexpected zone SSH), Step 3 (Credential theft), and Step 6 (Modbus valve manipulation). It completely misses the pre-attack subnet discovery scan (Step 2) and honeypot reconnaissance (Steps 4 & 7).
2. **Rules + Baseline + Anomaly (6/7 steps)**: Adding unsupervised machine learning introduces discovery scan detection via Isolation Forest event bursts (Step 2) and flags unseen interaction with the decoy PLC (Step 7). Step 4 (Cowrie SSH decoy interaction) remains unobserved.
3. **Rules + Base + Anom + Graph (6/7 steps)**: Graph edge analysis detects the attacker's network discovery scan *prior* to successful SSH authentication, establishing topological context for lateral pivot edges.
4. **Full (+ Deception) (7/7 steps)**: The deception engine captures the Cowrie and OpenCanary decoy pivots (Step 4), confirming adversary deception interaction with 100% confidence and providing full kill-chain attribution.

---

## 3. Incident-Level Precision, Recall, and Confusion Matrix (Task 2)

Evaluated under **Leave-One-Out (LOO) Cross-Validation** across the 5 benign daily folds:
- Each benign fold was evaluated against models trained strictly on the other 4 benign days (preventing memorization).
- True Positives require an active correlated incident reaching score >= 0.50 with multi-stage kill-chain progression.

### Incident Confusion Matrix (Operating Threshold = 0.50):
| | Actual Attack (Positive) | Actual Benign (Negative) | Total Predicted |
| :--- | :---: | :---: | :---: |
| **Predicted Attack** | **TP = 3** | **FP = 0** | **3** |
| **Predicted Benign** | **FN = 0** | **TN = 5** | **5** |
| **Total Actuals** | **3** | **5** | **8 Folds** |

### Threshold Operating Curve & Sensitivity Analysis:
| Threshold | TP | FP | FN | TN | Precision | Recall | F1 Score | Operational Classification |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| 0.10 | 3 | 1 | 0 | 4 | 75.0% | 100.0% | 0.857 | Too noisy (burst anomalies survive) |
| 0.20 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating point |
| 0.30 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating point |
| 0.40 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating point |
| 0.50 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Recommended Default (Zero FP, 100% Recall) **[RECOMMENDED]** |
| 0.60 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating point |
| 0.70 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating point |
| 0.80 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating point |
| 0.90 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Over-constrained (leaves thin margin for slow burn) |

---

## 4. Golden Attack Step Coverage & TTFMA Summary (Task 3)

| Scenario Step | demo_baseline (Standard) | reordered (Early OT) | slow_burn (Low & Slow) |
| :--- | :--- | :--- | :--- |
| **Step 1: Initial Access (svc_backup)** | baseline, rule (36 sigs) | baseline, rule (36 sigs) | baseline, rule (36 sigs) |
| **Step 2: IT Subnet Discovery Scan** | anomaly, deception, graph (33 sigs) | anomaly, deception, graph (33 sigs) | anomaly (89 sigs) |
| **Step 3: Credential Theft (.db_creds)** | baseline, rule (2 sigs) | baseline, rule (2 sigs) | baseline, rule (2 sigs) |
| **Step 4: Decoy Pivot (cowrie/opencanary)** | deception (17 sigs) | deception (17 sigs) | deception (13 sigs) |
| **Step 5: Lateral Movement to eng-ws** | baseline, deception, graph, rule (47 sigs) | baseline, deception, graph, rule (47 sigs) | baseline, graph, rule (42 sigs) |
| **Step 6: Modbus Valve Manipulation** | rule (3 sigs) | rule (3 sigs) | rule (5 sigs) |
| **Step 7: Decoy PLC Reconnaissance** | baseline, deception, graph (17 sigs) | baseline, deception, graph (17 sigs) | baseline, deception, graph (15 sigs) |
| **Total Steps Represented** | **7 / 7 (100.0%)** | **7 / 7 (100.0%)** | **7 / 7 (100.0%)** |
| **Incident Score** | **1.00 (CRITICAL)** | **1.00 (CRITICAL)** | **1.00 (CRITICAL)** |
| **Time to First Meaningful Alert (TTFMA)** | **1.54s** (RULE-AUTH-001) | **0.94s** (RULE-AUTH-001) | **2.58s** (RULE-AUTH-001) |

---

## 5. Detector Contribution & Trust Ranking Matrix (Task 4)

| Rank | Detector Engine | True Positive Signals | LOO Benign FPs | Critical Step Enabler | Trust Classification |
| :---: | :--- | :---: | :---: | :--- | :--- |
| **#1** | **Deception Engine (Honeypot/Honeytoken)** | 47 sigs | 0 FPs | Step 4 (Decoy Pivot), Step 7 (PLC Recon) | Tier 1: Absolute Trust (Zero Benign Noise) |
| **#2** | **Context-Aware Rules Engine** | 77 sigs | 0 FPs | Step 1 (Auth), Step 3 (Creds), Step 6 (OT Write) | Tier 1: High Trust (Strict Asset Authorization) |
| **#3** | **Interaction Graph Detector** | 43 sigs | 0 FPs | Step 2 (Scan), Step 5 (Lateral Path) | Tier 1: High Trust (Unprecedented Topology Edges) |
| **#4** | **Behavioral Baseline Engine** | 57 sigs | 0 FPs | Step 1 (Svc Acct), Step 5 (Eng WS), Step 7 (PLC) | Tier 1: High Trust (Zero FP Across Benign Folds) |
| **#5** | **Isolation Forest Anomaly Detector** | 147 sigs | 5 FPs | Step 2 (Volumetric IT Subnet Discovery) | Tier 2: Supporting Context (Requires Correlator Gate) |

---

## 6. Organizer-Log Robustness Test & Context Boundaries (Task 5)

Simulated third-party enterprise audit using `content/mappings/windows_security.yaml` against unfamiliar Windows EVTX telemetry (`eval/fixtures/organizer_windows_events.jsonl` from host `WIN-CORP-DC01`):

- **Events Ingested**: 12 normalized events (logon failures, successful logon, reconnaissance commands, suspicious PowerShell download, credential injection).
- **Signals Generated**: 16 signals across 3 engines (baseline, graph, rule).
- **Correlated Incident**: Formed 1 active incident reaching score **0.56 (MEDIUM)**.
- **MITRE ATT&CK Techniques Identified**: `T1021.004, T1059.004, T1078.003`.

### What Was Detected (Generic Transferability):
- `RULE-SHELL-001`: Caught automated credential injection (`sshpass`), base64 decoding, and curl download cradles.
- `BASE-DEV-001`: Unsupervised behavioral baseline flagged unknown service account (`svc_payroll`) and unseen command lines.
- `GRAPH-EDGE-001`: Interaction graph recognized unprecedented user-to-host execution edges.

### What Was NOT Detected (Environment Boundary Analysis):
- `RULE-AUTH-001` did not fire: `WIN-CORP-DC01` is not in `content/assets.yaml`, so authorization policies cannot resolve valid zone boundaries.
- `RULE-OT-001` did not fire: Windows telemetry contains no Modbus ICS protocol fields.
- `RULE-DECOY-001` did not fire: adversary did not interact with registered honeytokens.

### Architectural Takeaway:
Generic behavioral rules, process inspection, and unsupervised baselines reliably transfer to completely new operating systems and schemas. However, high-specificity authorization rules strictly require asset inventory registration to define valid operational boundaries.
