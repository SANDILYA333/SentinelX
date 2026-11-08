# SentinelX Demo Playbook & Operator Guide

This playbook provides the end-to-end execution script, preflight checklist, terminal orchestration commands, and verbal narration script for demonstrating SentinelX to stakeholders, analysts, and evaluation committees.

---

## 1. Demo Architecture Overview

SentinelX is a context-aware cyber-physical detection and response automation platform. During the live demonstration, the system showcases:
1. **Multi-Domain Telemetry**: Real-time event streaming across IT (Wazuh, Zeek), Decoy canaries (Cowrie SSH, OpenCanary), and OT/ICS process control (Modbus, physical PLC simulator).
2. **Five Independent Detectors**: Rules, Baselines, Isolation Forest Anomaly Detection, Topology Graph Deviation, and Deception Canary Triplines.
3. **Progressive Correlation & Scoring**: Dynamic kill-chain advancement scoring with Time-to-First-Meaningful-Alert (TTFMA) tracking.
4. **Alert Budget Controller**: Calibrated score thresholds preventing analyst alert fatigue (0 false positives on 5 benign days).
5. **Response Safety Guard**: Safety-constrained autonomous response policy preventing destructive actions against critical physical infrastructure.
6. **Information-Dense Analyst UI**: Live event stream, incident narrative timelines, interactive Dagre-layout attack graphs, honeypot telemetry, and guard action tester.

---

## 2. Preflight Checklist

Before commencing any live demonstration, verify that all prerequisites are satisfied:

```bash
make demo-preflight
```

The preflight tool validates 7 critical health gates:
1. **Host Free Disk Space**: At least 15 GB free disk space (preventing Docker telemetry volume exhaustion).
2. **Docker Lab Containers (9/9)**: `jump-host`, `file-srv`, `db-srv`, `eng-ws`, `plc-sim`, `cowrie`, `opencanary`, `decoy-plc`, `wazuh-manager` are UP and healthy.
3. **SentinelX API Reachability**: `GET http://localhost:8000/health` returns status `ok`.
4. **Telemetry Sources Health (5/5)**: Live log tailers actively tracking Wazuh, Zeek IT/DMZ/OT, Cowrie, OpenCanary, and PLC logs.
5. **OT PLC Physics & Registers**: Tank level ~55%, status `normal`, emergency stop `false`.
6. **Clean Incident Store**: 0 active incidents in SQLite database.
7. **Budget Controller Calibration**: Score threshold calibrated to `0.50` (or operational setpoint).

If any check fails, run the quick-fix recommendations indicated by the preflight tool.

---

## 3. Terminal Orchestration

Open three terminal windows arranged side-by-side:

### Terminal 1: Backend API & Ingestor
```bash
make ingest-live
```
*Listens on `http://localhost:8000`, tails logs in real-time from `data/logs/`, runs detectors and correlator, and broadcasts updates over WebSocket.*

### Terminal 2: Analyst Web Dashboard
```bash
make web
```
*Serves the Next.js dashboard at `http://localhost:3000`.*

### Terminal 3: Demonstration Controller
```bash
# Step 1: Ensure clean baseline state
make demo-reset

# Step 2: Validate preflight health
make demo-preflight

# Step 3: Trigger live paced attack (when ready)
make demo-attack
```

---

## 4. Live Demonstration Script & Narration

| Elapsed Time | Attack Action | UI Screen & Expected Reaction | Speaker Script / Narration |
| :--- | :--- | :--- | :--- |
| **00:00 - 00:20** | *Pre-Attack Baseline* | **Overview (`/`)**<br>- 5 telemetry sources healthy<br>- Ingest rate normal<br>- 0 incidents active<br>- Budget gauge set to 0.50 | *"Notice our baseline posture: 5 telemetry sources streaming from IT hosts, network taps, decoys, and OT networks. The alert budget is calibrated to suppress routine anomalies, ensuring zero alert fatigue."* |
| **00:20 - 00:35** | **Step 1: Initial Access**<br>Attacker compromises `jump-host` via stolen SSH credentials (`svc_backup`) from external IP `10.10.1.5`. | **Overview & Signals (`/signals`)**<br>- Ingest ticker spikes<br>- `RULE-AUTH-001` fires (SSH from unexpected zone)<br>- Score begins accumulating | *"In Terminal 3, we trigger `make demo-attack`. Notice our rule detector immediately flags an anomalous SSH login from an unexpected source zone. Rather than blasting the analyst with an unverified alert, SentinelX tracks this as the first signal."* |
| **00:35 - 00:55** | **Steps 2-4: Recon & Decoys**<br>Attacker scans IT subnet and touches Cowrie SSH decoy (`10.10.2.20`) and OpenCanary (`10.10.2.30`). | **Deception Tab (`/deception`)**<br>- Decoy touch counter increments<br>- `RULE-DECOY-001` & `GRAPH-EDGE-001` fire<br>- Honeypot session payload captured | *"The attacker attempts lateral reconnaissance and trips our Cowrie and OpenCanary traps. Decoy touches carry high deception fidelity. Graph topology detects an unprecedented network interaction edge, advancing kill-chain correlation."* |
| **00:55 - 01:15** | **Step 5: Lateral Pivot**<br>Attacker moves to Engineering Workstation (`eng-ws`). | **Incidents Tab (`/incidents`)**<br>- Incident score rises (>0.70)<br>- Narrative timeline links initial access to pivot<br>- ATT&CK tags update (T1021.004) | *"As the adversary pivots into the OT staging subnet via `eng-ws`, our correlator unifies these disparate logs across Wazuh, Zeek, and Cowrie into a single incident entity. The progression score passes the budget threshold."* |
| **01:15 - 01:35** | **Step 6: OT Tampering**<br>Attacker issues unauthorized Modbus write to close valve (reg 1, val 0) on `plc-sim`. | **Attack Graph (`/graph`) & Incidents**<br>- `RULE-OT-001` fires<br>- Incident score saturates at 1.00 (Critical)<br>- TTFMA recorded (~15-20s)<br>- Attack Graph lights up `plc-sim` in red | *"Here is the physical impact: the attacker manipulates Modbus register 1 on the water treatment PLC. Our OT rule fires immediately. The incident score saturates at 100%, TTFMA is recorded, and the Attack Graph reveals the exact traversal path to the physical asset."* |
| **01:35 - 02:00** | **Response Evaluation** | **Deception & Guard Tab (`/deception`)**<br>- Guard Action Tester<br>- Test `isolate_host(jump-host)`<br>- Test `block_ip(10.10.3.20)`<br>- Test `modify_ot_register(valve)` | *"Now we evaluate automated containment. Let's test three response actions against our Response Safety Guard:*<br>• *`isolate_host(jump-host)` -> **ALLOWED** (non-critical asset).*<br>• *`block_ip(10.10.3.20)` -> **DENIED** (PLC is process-critical; autonomous isolation would blind operators).*<br>• *`modify_ot_register` -> **NEEDS_HUMAN** (physical state changes mandate human verification)."* |
| **02:00 - 02:30** | **Ground Truth & Benchmarks** | **Evaluation Tab (`/eval`)**<br>- 8-capture benchmark matrix<br>- 5 benign days (0 FP)<br>- 3 attack scenarios (100% recall) | *"Finally, on the Eval tab, we see the empirical evidence: 5 continuous benign days evaluated with zero false positives under the calibrated budget, and 100% kill-chain recall across baseline, reordered, and slow-burn attacks."* |

---

## 5. Presenter Mode

During live stage presentations or boardroom projections:
- Click the **Presenter Mode** toggle in the left sidebar or the top navigation pill.
- **Presenter Mode Changes**:
  - Increases base font sizing and data badge contrast.
  - Expands table row padding and metric gauges for projector legibility.
  - Collapses secondary chrome to maximize forensic visualization real estate.

---

## 6. Fallback Ladder (Emergency Contingencies)

If unexpected lab or environmental issues occur during a live presentation, use this graded fallback ladder:

### Level 1: Telemetry Tailer Stalls or Docker Logs Pause
*Symptom*: Events are not streaming on `/signals` after triggering the attack.
*Remedy*:
```bash
# Restart API with live ingestion
make ingest-live
```

### Level 2: Live Attack Execution Fails or Containers De-sync
*Symptom*: Attack runner throws a connection error or container status shows degraded.
*Remedy*:
```bash
# Fallback to deterministic replay of the validated golden capture at 5x speed
make ingest-replay DIR=eval/captures/attack/demo_baseline SPEED=5
```
*The UI will stream the exact verified capture with identical detector firings, incident scoring, and graph topology.*

### Level 3: Full Lab Reset Needed
*Symptom*: Docker container port conflict or corrupt volume.
*Remedy*:
```bash
make lab-reset
make demo-preflight
```

### Level 4: Fully Offline Standalone Mode
*Symptom*: Complete lack of Docker runtime on presentation laptop.
*Remedy*:
- Navigate to `http://localhost:3000/eval` to inspect the frozen capture benchmark matrix and detection results.
- Demonstrate the **Guard Action Tester** on `/deception`, which operates standalone against safety policy rules.

