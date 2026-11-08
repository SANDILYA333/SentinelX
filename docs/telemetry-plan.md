# SentinelX Telemetry Generation & Capture Plan (Phase 3)

This document specifies the telemetry generation architecture, the diurnal benign activity model, the data-driven attack scenarios, and the capture tooling and validation pipeline.

---

## 1. Benign Activity Model

### 1.1 Diurnal Pattern & Time Compression
Benign enterprise activity naturally varies across the 24-hour day. In SentinelX, benign generation models realistic diurnal rhythms compressed via a configurable `SIM_SPEED` factor (default: `96x`, compressing 24 simulated hours into 15 real wall-clock minutes).

A weighted-hour table modulates inter-action pacing dynamically across simulated hours:
- **Night (00:00–06:00)**: Low activity (weight: `0.15–0.25`).
- **Morning Ramp & Peak (07:00–11:00)**: High activity (weight: `0.70–1.00`).
- **Lunch Dip (12:00–13:00)**: Reduced activity (weight: `0.50–0.60`).
- **Afternoon Peak (14:00–17:00)**: High activity (weight: `0.75–1.00`).
- **Evening Wind-down (18:00–23:00)**: Moderate/low activity (weight: `0.20–0.50`).

### 1.2 Legitimate Actors & Real Operations
All operations are executed via genuine SSH sessions with real keys and credentials against non-decoy assets:
- **`alice` (Sysadmin)**:
  - Connects to `file-srv` (`10.10.1.20`) and `jump-host` (`10.10.1.10`).
  - Executes administrative commands: `ls -la /srv/share`, `df -h`, `cat /etc/hosts`, `uptime`, `systemctl status wazuh-agent`.
  - Performs occasional patch-level checks: `apt list --upgradable`.
  - Logs in and out realistically rather than holding continuous open connections.
- **`bob` (Database Administrator)**:
  - Connects to `db-srv` (`10.10.1.30`).
  - Executes SQL queries: `SELECT count(*) FROM customers;`, `SELECT MAX(id), count(*) FROM customers;`.
  - Performs occasional database backups: `pg_dump -t customers -f /tmp/cust_dump.sql` (small table, file deleted immediately).
- **`eng1` (Plant Engineer)**:
  - Connects from `eng-ws` (`10.10.1.40`) to `plc-sim` (`10.10.3.20`).
  - Performs continuous periodic Modbus reads (`/usr/local/bin/read_plc.py 10.10.3.20 502`) every ~10s.
  - **OT Change-Control Maintenance Window**: Modbus writes to pump speed (`register 0`, values `48–62%`) are strictly confined to simulated maintenance hours (`02:00–04:00`). Outside this window, zero writes are permitted.
- **`svc_backup` (Service Account)**:
  - Low-frequency cron-style password-authenticated SSH logins (`Backup2024!`) to `jump-host` (`10.10.1.10`) executing `uptime` to establish a legitimate password-auth baseline.

### 1.3 Light Realistic Noise & Decoy Protection Guarantees
- **Noise Injection**:
  - `alice` occasionally mistypes password on `jump-host` (`alice_failed_login_prob = 0.05`), generating realistic `Failed password for alice` records in `auth.log`.
  - Occasional quick disconnects and aborted probes.
  - **NEVER** mistypes `svc_backup` password; **NEVER** touches honey user `svc_dbadmin`.
- **Hard-Negative Guarantee (Zero Decoy Touches)**:
  - The benign runner enforces strict runtime assertions: any command referencing `10.10.2.20` (Cowrie), `10.10.2.30` (OpenCanary), `10.10.3.60` (Decoy PLC), `svc_dbadmin`, or `Winter2026!` immediately raises a fatal exception.

---

## 2. Attack Scenario Catalog

All attack scenarios are expressed declaratively in `content/scenarios/` and executed uniformly by [`engine/sentinelx/attack/runner.py`](file:///home/kafka/innovasia/SentinelX/engine/sentinelx/attack/runner.py).

### 2.1 `baseline.yaml` (Live Demo Scenario, ~90s)
| Step | Name | ATT&CK ID | Actor / Host | Action | Target | Delay |
|---|---|---|---|---|---|---|
| 1 | Initial Access | T1078.003 | attacker -> jump-host | `ssh_jump_login` | 10.10.1.10 | 2–4s |
| 2 | Network Discovery | T1046 | attacker -> jump-host | `network_discovery` | 10.10.1.0/24 | 4–6s |
| 3 | Credential Theft | T1552.001 | attacker -> file-srv | `credential_theft` | 10.10.1.20 | 3–5s |
| 4 | Decoy Pivot | T1021.004 | attacker -> cowrie, opencanary | `decoy_pivot` | 10.10.2.20, 10.10.2.30 | 5–8s |
| 5 | Lateral Movement | T1021.004 | attacker -> eng-ws | `lateral_movement` | 10.10.1.40 | 4–6s |
| 6 | OT Manipulation | T0855 | attacker -> plc-sim | `ot_manipulation` | 10.10.3.20 | 15–20s |
| 7 | OT Recon & Restore | T0846 | attacker -> decoy-plc, plc-sim | `ot_discovery_and_restore` | 10.10.3.60, 10.10.3.20 | 20–25s |

### 2.2 `reordered.yaml` (Split-Discovery Variant, ~95s)
Materially alters the step ordering by executing immediate credential looting upon landing, followed by split network discovery bursts around the decoy pivot.
- Steps: Initial Access -> Credential Theft -> Discovery Phase 1 -> Decoy Pivot -> Discovery Phase 2 -> Lateral Move -> OT Manipulation -> OT Recon & Restore.

### 2.3 `slow_burn.yaml` (Patient Living-Off-The-Land Variant, ~240s)
Uses identical underlying attack actions but dilates inter-step intervals (15–35s dwell times) to stress-test correlation engines against patient adversaries.

---

## 3. Capture Tooling & Validation

- [`eval/capture.py`](file:///home/kafka/innovasia/SentinelX/eval/capture.py): Orchestrates preflight disk checks (>= 15 GB free), clean lab reset (`make lab-reset`), background benign generation, attack scenario execution, log snapshotting, SHA-256 integrity calculation, and `manifest.json` generation.
- [`eval/validate_captures.py`](file:///home/kafka/innovasia/SentinelX/eval/validate_captures.py): Replays capture directories into isolated scratch databases and enforces strict semantic contracts:
  - **Benign**: Exactly 0 decoy domain events, 0 `honey_user` tags, 0 `honey_file` tags.
  - **Attack**: >= 1 `honey_user`, >= 1 `ot.is_write=true`, >= 1 `cross_zone` tag, and verifiable log evidence for all scenario steps.

### 3.1 Capture Inventory

| Name | Category | Wall Duration | Sim Span | Size | Raw Lines | Events | Hard-Neg / Steps |
|---|---|---|---|---|---|---|---|
| `benign/day_101` | Benign | 60.0s | 1.6h | 1.165 MB | 525 | 56 | 0 Decoy / 0 Honey (**PASS**) |
| `benign/day_102` | Benign | 60.0s | 1.6h | 1.167 MB | 543 | 54 | 0 Decoy / 0 Honey (**PASS**) |
| `benign/day_103` | Benign | 60.0s | 1.6h | 1.170 MB | 543 | 58 | 0 Decoy / 0 Honey (**PASS**) |
| `benign/day_104` | Benign | 60.0s | 1.6h | 1.164 MB | 532 | 55 | 0 Decoy / 0 Honey (**PASS**) |
| `benign/day_105` | Benign | 60.0s | 1.6h | 1.167 MB | 532 | 56 | 0 Decoy / 0 Honey (**PASS**) |
| `attack/demo_baseline` | Attack | 118.8s | 3.2h | 1.324 MB | 1011 | 275 | All 7 Steps Proven (**PASS**) |
| `attack/reordered` | Attack | 120.0s | 3.2h | 1.337 MB | 1046 | 277 | All 7 Steps Proven (**PASS**) |
| `attack/slow_burn` | Attack | 234.3s | 6.2h | 1.510 MB | 1587 | 442 | All 7 Steps Proven (**PASS**) |

*Note: Raw captures are local data assets (~11 MB total) and gitignored per security and repository footprint requirements (`eval/captures/*/*/*`). Only reproducible `manifest.json` metadata files are tracked in version control.*

