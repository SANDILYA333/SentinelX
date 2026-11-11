# SentinelX Ground Truth Evaluation Dataset Documentation

## 1. Overview

The SentinelX Ground Truth Evaluation Dataset (`eval/scenarios/ground_truth.json`) provides a deterministic, version-controlled ground truth specification for quantifying detection efficacy across industrial OT and enterprise IT cyber environments.

It establishes explicit expectations for:
- **Scenario Intent:** Whether activity is malicious (attack scenario) or benign (operational background).
- **Domain Categories:** Authentication, Lateral Movement, Endpoint, Deception, Industrial OT, and Benign Baselines.
- **Dataset Partitioning:** Rigid division across `dev`, `validation`, and `test` splits to prevent benchmark overfitting and data leakage.
- **Expected Detections:** Ground truth mapping to expected detection rules (`rule_id`), detector types (`detector`), MITRE ATT&CK techniques, and target assets.

---

## 2. Dataset Schema & Invariants

The dataset strictly validates against the Pydantic schema `GroundTruthDataset` defined in `engine/sentinelx/schemas/eval.py`:

```python
class EvaluationScenario(BaseModel):
    scenario_id: str
    name: str
    description: str
    category: ScenarioCategory
    split: DatasetSplit
    is_malicious: bool
    capture_name: str | None = None
    target_assets: list[str] = Field(default_factory=list)
    expected_detections: list[ExpectedDetection] = Field(default_factory=list)
    expected_attack_stages: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
```

### Key Schema Invariants:
1. **Benign Invariant:** Scenarios marked `is_malicious = False` must never declare `expected_detections` or `expected_attack_stages`. Any detection triggered during a benign scenario is strictly classified as a **False Positive (FP)**.
2. **Malicious Invariant:** Scenarios marked `is_malicious = True` must declare explicit expected detections or attack stages. If no detector or rule fires during the scenario, it is classified as a **False Negative (FN)**.
3. **Partition Isolation:** Scenarios are partitioned into three non-overlapping splits:
   - `dev`: Exploratory development and rule iteration.
   - `validation`: Model hyperparameter calibration, Leave-One-Out cross-validation, and dynamic threshold tuning.
   - `test`: Held-out final verification suite.

---

## 3. Scenario Portfolio & Distribution

| Scenario ID | Name | Category | Split | Malicious? | Target Assets |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `SCEN-AUTH-001` | External SSH Login Unexpected Zone | authentication | dev | Yes | `jump-host`, `srv-backup` |
| `SCEN-AUTH-002` | Admin SSH Session During Business Hours | authentication | dev | No | `jump-host` |
| `SCEN-NET-001` | IT Subnet Discovery and Port Sweep | lateral_movement | validation | Yes | `jump-host`, `corp-dc-01`, `db-prod-01` |
| `SCEN-NET-002` | Cross-Zone Pivot to OT Eng Workstation | lateral_movement | dev | Yes | `eng-ws` |
| `SCEN-NET-003` | Routine NTP & DNS Infrastructure Traffic | lateral_movement | validation | No | `corp-dc-01` |
| `SCEN-EP-001` | Suspicious Encoded Shell Execution | endpoint | test | Yes | `jump-host` |
| `SCEN-EP-002` | Scheduled Backup Archive Script | endpoint | test | No | `srv-backup` |
| `SCEN-DEC-001` | Cowrie SSH Decoy Interaction | deception | dev | Yes | `backup-srv-02` |
| `SCEN-DEC-002` | OpenCanary DB Decoy Port Probe | deception | validation | Yes | `db-prod-02` |
| `SCEN-DEC-003` | Decoy PLC Modbus Protocol Probe | deception | test | Yes | `decoy-plc` |
| `SCEN-OT-001` | Unauthorized Modbus Write to PLC | industrial_ot | dev | Yes | `plc-primary` |
| `SCEN-OT-002` | Authorized Modbus Periodic Telemetry | industrial_ot | dev | No | `plc-primary` |
| `SCEN-OT-003` | Eng WS Maintenance Setpoint Update | industrial_ot | validation | No | `plc-secondary` |
| `SCEN-BENIGN-101`| Day 101 Benign Baseline Capture | benign | dev | No | `jump-host`, `eng-ws`, `plc-primary` |
| `SCEN-BENIGN-103`| Day 103 Benign Capture with Transient Noise | benign | validation | No | `jump-host`, `eng-ws`, `plc-primary` |
| `SCEN-BENIGN-105`| Day 105 Quiet Baseline Capture | benign | test | No | `jump-host`, `eng-ws`, `plc-primary` |
| `SCEN-ATK-BASE` | Full Multi-Stage Attack: Demo Baseline | industrial_ot | dev | Yes | Multiple assets |

---

## 4. Verification and Automation

The dataset is verified using:
```bash
python scripts/validate_evaluation_dataset.py
```
And tested continuously via `engine/tests/test_eval_dataset.py`.

