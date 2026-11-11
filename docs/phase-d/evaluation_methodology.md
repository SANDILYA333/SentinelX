# SentinelX Detection Evaluation Methodology

## 1. Principles of Evaluation

SentinelX evaluation is grounded in four non-negotiable principles:
1. **Empirical Truth:** Detection metrics must reflect actual detector behavior against ground truth telemetry. No synthetic score inflation, no altered labels to hide misses, and no suppression of false positives.
2. **Multi-Level Granularity:** Evaluating detection solely at the incident level obscures whether individual rules fire or whether benign events trigger noise. Therefore, evaluation is performed across three independent tiers:
   - **Event-Level:** Measures raw event classification accuracy.
   - **Scenario-Level:** Measures attack-step and tactical execution detection.
   - **Incident-Level:** Measures multi-stage incident aggregation and risk scoring.
3. **Partitioned Cross-Validation:** The evaluation suite utilizes `dev`, `validation`, and `test` dataset splits to verify generalizability and prevent overfitting detection heuristics to training captures.
4. **Zero-Division Rigor:** When true and false positives are zero, precision is strictly undefined (`None` / `null`) rather than assumed to be 1.0 or 0.0.

---

## 2. Evaluation Tiers

### 2.1 Tier 1: Event-Level Evaluation
- **Objective:** Quantify how individual telemetry records (Sysmon, Zeek, Modbus, Honeypot) are classified.
- **True Positive ($TP_{event}$):** A malicious event that generates at least one detection signal.
- **False Negative ($FN_{event}$):** A malicious event that passes unnoticed through all detectors.
- **False Positive ($FP_{event}$):** A benign operational event that generates an alert signal.
- **True Negative ($TN_{event}$):** A benign event correctly ignored by the detection pipeline.

### 2.2 Tier 2: Scenario-Level Evaluation
- **Objective:** Evaluate whether specific attacker techniques (e.g. credential access, cross-zone pivot, Modbus register write) or benign workflows (e.g. routine backup, maintenance shift) are correctly handled.
- **True Positive ($TP_{scenario}$):** An attack scenario where expected rules or techniques fire.
- **False Negative ($FN_{scenario}$):** An attack scenario where no expected detection occurs.
- **False Positive ($FP_{scenario}$):** A benign scenario that triggers unwarranted active incidents or excessive alerts.
- **True Negative ($TN_{scenario}$):** A benign scenario that runs without triggering false alarms.

### 2.3 Tier 3: Incident-Level Evaluation
- **Objective:** Evaluate the correlation engine's ability to cluster disparate signals into an actionable security incident.
- **True Positive ($TP_{incident}$):** An attack campaign that results in an active incident exceeding the operational risk threshold ($\ge 0.50$).
- **False Positive ($FP_{incident}$):** A benign capture that produces an active incident exceeding the threshold.

---

## 3. Per-Engine & Per-Rule Granularity

Every evaluation run isolates:
- **Detector Performance:** Independent metrics for `rule`, `baseline`, `anomaly`, `graph`, and `deception`.
- **Rule Performance:** Individual evaluation for every YAML detection rule in `content/rules/`.
- **False Positive Extraction:** Full evidence linkages (event IDs, timestamps, rule explanations) for any benign event that fired.
- **False Negative Extraction:** Explicit identification of missed attacker actions with target assets and MITRE techniques.

