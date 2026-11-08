# SentinelX Response Safety Guard & Industrial Safety Policy

In converged IT/OT environments, automated security responses cannot follow conventional enterprise playbooks. Terminating a process, cutting network connections, or rebooting a server in an enterprise setting may cause minor service downtime; in an industrial operational technology (OT) network, abruptly disconnecting a Programmable Logic Controller (PLC) or closing a control valve can cause catastrophic physical damage, hydraulic water hammer, chemical spills, or human casualty.

The SentinelX Response Safety Guard (`sentinelx/guard/`) enforces deterministic, state-dependent safety interlocks on all automated and analyst-initiated response actions before execution.

```
+---------------------------------------------------------------------------------------------------+
|                                  Requested Mitigation Action                                      |
|            {action: CONTAIN_HOST, target: 10.10.3.20, reason: "Mitigate Modbus Attack"}           |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                          SentinelX Response Safety Guard Engine                                   |
|   1. Query Target Asset Metadata (`content/assets.yaml`: zone, process_critical, criticality)     |
|   2. Inspect Real-Time Physical Controller State (PLC: RUNNING / MAINTENANCE / SAFE_STANDBY)      |
|   3. Match Policy Constraints & Fail-Safe Defaults                                                |
+---------------------------------------------------------------------------------------------------+
                                                  |
                        +-------------------------+-------------------------+
                        |                                                   |
                        v                                                   v
           [ IT Asset / Non-Critical ]                           [ OT Asset / Process-Critical ]
                        |                                                   |
                        v                                                   v
           Decision: PERMIT                                      Decision: DENY / NEEDS_HUMAN
           Action executed safely                                Interlock prevents physical harm
```

---

## 1. Response Action Catalog & Authorization Rules

| Action Type | Permitted Scopes | Safety Classification | Default Guard Decision |
| :--- | :--- | :--- | :--- |
| `BLOCK_IP` | Perimeters, DMZ, IT Subnets | Low Risk | **PERMIT** (if IP is non-critical infrastructure) |
| `CONTAIN_HOST` | IT Workstations (`eng-ws`, `file-srv`, `jump-host`) | Medium Risk | **PERMIT** (in IT); **DENY** (if process-critical OT) |
| `ISOLATE_SUBNET` | Enterprise IT Subnets (`10.10.1.0/24`) | High Risk | **NEEDS_HUMAN** (Requires human analyst sign-off) |
| `SHUTDOWN_VALVE` | Industrial Modbus Actuators | Critical Physical Impact | **NEEDS_HUMAN** / **DENY** (Automated closure forbidden) |

---

## 2. PLC State-Dependent Safety Interlocks

The guard queries live controller operational telemetry (`plc-sim`) before permitting any action targeting the industrial cell:

1. **State: `RUNNING` (Active Chemical/Pumping Process)**:
   - **Policy**: Absolute interlock.
   - **Guard Decision**: **`DENY`**.
   - **Rationale**: Abrupt network disconnection or process termination prevents the safety loop and engineer workstation from reading sensor values, blinding operators to dangerous pressure or flow imbalances.
2. **State: `MAINTENANCE` (Scheduled Maintenance Window)**:
   - **Policy**: Elevated review.
   - **Guard Decision**: **`NEEDS_HUMAN`**.
   - **Rationale**: Technicians are actively performing calibrations. Isolation requires operator radio confirmation.
3. **State: `SAFE_STANDBY` (Process Idle / Offline)**:
   - **Policy**: Automated containment permissible.
   - **Guard Decision**: **`PERMIT`**.
   - **Rationale**: No physical flow or pressure is active; containment can safely isolate compromised network interfaces.

---

## 3. Fail-Safe Defaults & Evaluation Contract

The guard operates on a **zero-trust, fail-safe default**:
- If an asset is unlisted in `content/assets.yaml`, the guard treats it as potentially critical and defaults to **`NEEDS_HUMAN`**.
- If a PLC state cannot be verified over telemetry, the guard defaults to **`DENY`**.
- All decisions produce an immutable, schema-validated `GuardDecision` object (`packages/contracts/schemas/GuardDecision.json`):

```json
{
  "decision_id": "guard-dec-20261108-0042",
  "action": "CONTAIN_HOST",
  "target_asset": "plc-sim",
  "target_ip": "10.10.3.20",
  "decision": "DENY",
  "safety_score": 0.05,
  "rationale": "Safety Interlock Violation: plc-sim is actively RUNNING physical pump cycles. Automated network isolation or termination is strictly forbidden to prevent overpressure physical hazards.",
  "required_approvers": ["chief_plant_engineer", "lead_ot_operator"],
  "created_at": "2026-11-08T01:16:32.418Z"
}
```

This ensures that SentinelX's automated detection and response loop remains 100% deterministic and physically safe under all operational scenarios.
