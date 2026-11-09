# SentinelX Evaluation Plan & Performance Verification Methodology (Phase 7)

This document establishes the scientific evaluation protocol, cross-validation methodology, ablation matrix design, and generalization benchmarks implemented in the SentinelX master evaluation suite.

---

## 1. Evaluation Corpus & Dataset Design

The evaluation framework rigorously tests detection and correlation capabilities across **8 verified lab captures** (~12 MB total raw telemetry, 44.6 simulated hours) plus **1 third-party enterprise audit fixture**:

### 1.1 Capture Corpus Breakdown
| Capture Name | Classification | Simulated Span | Events | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `benign/day_101` | Benign Negative | 5.0h (00:00–05:00) | 55 | Night baseline: low activity, periodic backups |
| `benign/day_102` | Benign Negative | 5.0h (05:00–10:00) | 77 | Morning ramp: user logins, shift change |
| `benign/day_103` | Benign Negative | 5.0h (10:00–15:00) | 75 | Mid-day peak: high volume administrative traffic |
| `benign/day_104` | Benign Negative | 5.0h (15:00–20:00) | 67 | Afternoon peak & evening wind-down |
| `benign/day_105` | Benign Negative | 5.0h (20:00–01:00) | 48 | Night operations: automated maintenance windows |
| `attack/demo_baseline` | Attack Positive | 3.2h (01:15–04:30) | 275 | Standard 7-step multi-stage attack scenario |
| `attack/reordered` | Attack Positive | 3.2h (01:15–04:30) | 277 | Out-of-order execution (early looting before scan) |
| `attack/slow_burn` | Attack Positive | 26.6h (00:00–02:35) | 831 | Low-and-slow execution (dilated dwell intervals) |
| `organizer_windows` | Robustness Test | Audit Replay | 12 | Unfamiliar Windows EVTX security telemetry |

---

## 2. Leave-One-Out (LOO) Cross-Validation Protocol

To guarantee that anomaly detection and behavioral baseline profiling do not suffer from data leakage or memorization:
1. **5-Fold Cross-Validation**:
   - For each fold $k \in \{101, 102, 103, 104, 105\}$, the baseline profile and isolation forest models are trained exclusively on the **remaining 4 benign days**.
   - Fold $k$ is then evaluated as unseen test telemetry through the entire ingestion, detection, and correlation pipeline.
2. **Evaluation Metric Criteria**:
   - **True Positive (TP)**: An attack capture producing $\ge 1$ correlated incident reaching score $\ge \theta$ ($\theta = 0.50$).
   - **False Positive (FP)**: A benign capture fold producing $\ge 1$ incident reaching score $\ge \theta$.
   - **False Negative (FN)**: An attack capture failing to produce an incident reaching score $\ge \theta$.
   - **True Negative (TN)**: A benign capture producing zero incidents reaching score $\ge \theta$.

---

## 3. Four-Tier Detector Layer Ablation Matrix

The evaluation suite executes a systematic 4-tier ablation study (`eval/ablation.py`) to quantify the exact marginal value of each detection paradigm:

```
[ Tier 1: Rules Only ]
        |
        v  (+ Behavioral Baselines + Isolation Forest)
[ Tier 2: Rules + Baseline + Anomaly ]
        |
        v  (+ Interaction Graph Topology)
[ Tier 3: Rules + Baseline + Anomaly + Graph ]
        |
        v  (+ Honeypots & Honeytokens)
[ Tier 4: Full Multi-Paradigm (+ Deception) ]
```

Each tier is gated through the full correlation pipeline at budget threshold $0.50$ across all 8 datasets to measure:
- Active incidents per capture.
- Peak incident progression score.
- Kill-chain scenario step coverage ($X / 7$ steps).
- Daily benign false positive rate ($\text{FP} / 24\text{h}$).

---

## 4. Threshold Sensitivity & Operating Curve

The budget controller threshold $\theta$ governs incident escalation. The evaluation suite assesses sensitivity across the full spectrum $\theta \in [0.10, 0.90]$:
- $\theta = 0.10$: Overly sensitive; single-event anomaly bursts in `day_103` survive correlation, producing 1 FP (Precision drops to 75.0%).
- $\theta \in [0.20, 0.80]$: Optimal operating window; multi-stage kill-chain progression elevates attacks to $\ge 0.90$, while isolated anomalies fail to compound, yielding **100% Precision and 100% Recall**.
- $\theta = 0.50$ is selected as the recommended default, providing the widest robustness margin against both benign jitter and patient adversaries.

---

## 5. Organizer-Log Robustness Benchmark

To verify generalization beyond the lab's simulated Linux and Modbus schemas:
- **Telemetry**: Windows EVTX event logs (`eval/fixtures/organizer_windows_events.jsonl`) generated on an unmapped Active Directory Domain Controller (`WIN-CORP-DC01`).
- **Mapping**: Transformed via generic mapping definition (`content/mappings/windows_security.yaml`).
- **Audit Objective**: Verify that command-line and process execution detectors (`RULE-SHELL-001`, `BASE-DEV-001`, `GRAPH-EDGE-001`) detect adversarial behavior after rule-content extension to support Windows-native execution keywords (`-EncodedCommand`, `certutil`, `wmic`, `schtasks`, `Invoke-WebRequest`) and generic technique mappings (`T1059`, `T1021`), while documenting why asset-dependent rules (`RULE-AUTH-001`, `RULE-OT-001`) intentionally do not fire on uncatalogued foreign hosts.
- **Novelty Corroboration Requirement**: Unsupervised baseline, graph, and anomaly signals without corroboration from deterministic rules or deception assets are capped below the budget threshold ($\text{score} \le 0.40$, flagged `novelty_only=true`). Configured via `IncidentConfig.novelty_cap: float = 0.40` in `engine/sentinelx/config.py`.
  - *Trade-off*: Prevents false alarms on un-baselined hosts in unfamiliar enterprise environments. By design, a pure living-off-the-land or novel zero-day attack that eludes all deterministic rules and canary lures is capped below the alert threshold ($\theta = 0.50$). Note that the cap is only restrictive below threshold when $\theta > \text{novelty\_cap}$; operating at $\theta \le 0.40$ allows novelty-only incidents to escalate.
