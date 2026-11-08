# SentinelX Deception Placement & Honeytoken Architecture

Deception in SentinelX is designed as a **deterministic, zero-false-positive early warning system**. Unlike signature-based detection, which relies on known patterns of adversary behavior, deception turns the attacker's own reconnaissance and lateral movement against them. Because legitimate enterprise actors and automated workflows have no operational reason to interact with decoy assets or honeytokens, any interaction represents high-confidence malicious intent.

---

## 1. Deception Topology & Placement Matrix

SentinelX strategically embeds trap assets across all three operational network zones (IT Enterprise, DMZ, and ICS/OT):

```
+---------------------------------------------------------------------------------------------------+
|                                      OPERATIONAL ARCHITECTURE                                     |
+---------------------------------------------------------------------------------------------------+

     [ IT ENTERPRISE: 10.10.1.0/24 ]
     +-----------------------------------------------------------------------------------+
     | Production:   jump-host (10.10.1.10)   file-srv (10.10.1.20)   eng-ws (10.10.1.40) |
     |                                               |                                   |
     | Deception:                             [.db_creds Honeytoken]                     |
     |                                        [OpenCanary: 10.10.1.30]                   |
     +-----------------------------------------------------------------------------------+
                                               |
                                               v
     [ DMZ PERIMETER: 10.10.2.0/24 ]
     +-----------------------------------------------------------------------------------+
     | Deception:    Cowrie Medium-Interaction SSH Honeypot (10.10.2.20)                 |
     +-----------------------------------------------------------------------------------+
                                               |
                                               v
     [ ICS / OT CELL: 10.10.3.0/24 ]
     +-----------------------------------------------------------------------------------+
     | Production:   plc-sim (10.10.3.20 - Modbus Port 502)                              |
     |                                                                                   |
     | Deception:    decoy-plc (10.10.3.60 - Modbus Emulation)                           |
     +-----------------------------------------------------------------------------------+
```

### 1.1 Trap Asset Inventory

| Asset Name | Zone / Subnet | IP Address | Emulated Services | Deception Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Cowrie Honeypot** | DMZ (`10.10.2.0/24`) | `10.10.2.20` | SSH (Port 2222 -> 22) | Logs credential brute-force, interactive shell commands, and malware payload uploads. |
| **OpenCanary Daemon** | IT (`10.10.1.0/24`) | `10.10.1.30` | FTP, Telnet, HTTP, SMB | Emulates vulnerable enterprise services; triggers immediate alert on syn-packet or banner probe. |
| **Honeytoken Credential**| IT (`file-srv`) | `/srv/share/.db_creds` | Static File Bait | Contains bogus credentials: `user: svc_dbadmin`, `pass: Winter2026!`, host: `db-srv`. |
| **Decoy PLC** | OT (`10.10.3.0/24`) | `10.10.3.60` | Modbus TCP (Port 502) | Mimics an industrial controller; responds to Modbus FC03 (read) and FC06/FC16 (write) probes. |

---

## 2. Honeytoken Bait Design & Breadcrumbing

Adversaries navigating an enterprise network prioritize credential harvesting. To intercept lateral movement early:
1. **Lootable Bait Placement**:
   - A hidden credential file `/srv/share/.db_creds` is staged on `file-srv` (`10.10.1.20`) alongside legitimate engineering shares.
   - Permissions are readable by domain users, simulating poor administrative hygiene.
2. **Honey Identity (`svc_dbadmin`)**:
   - The credential file references user `svc_dbadmin` with password `Winter2026!`.
   - This identity does not correspond to any active human user or valid operational service account.
3. **Tripwire Monitoring**:
   - Any authentication attempt in Wazuh/Syslog referencing `svc_dbadmin` immediately tags the event with `honey_user: svc_dbadmin`.
   - Any process accessing `/srv/share/.db_creds` is flagged with `honey_file_touched: true`.

---

## 3. Incident Correlation & Escalation Multiplier

Deception signals play a decisive role in the kill-chain correlation engine (`sentinelx/correlate/`):

1. **Instant Confirmation**:
   - Ordinary anomaly signals carry modest individual confidence ($0.40–0.60$) due to potential environmental noise.
   - A deception trip emits `DECEP-TRIP-001` with confidence **0.99**.
2. **The `confirmed_honeytoken` Boost**:
   - When the correlator observes an entity using credentials acquired from a honeytoken, the incident sets `confirmed_honeytoken = True`.
   - Scoring applies a $+0.25$ base bump and sets a progression multiplier of $1.5\times$.
   - This guarantees that an intrusion attempting to pivot using decoy credentials immediately crosses the operational alert budget threshold ($0.50$) into **HIGH / CRITICAL** severity, eliminating alert dwell time.

---

## 4. Hard-Negative Verification Guarantees

To ensure deception assets produce strictly **0.000 false positives**, SentinelX enforces rigorous verification gates:
- **Benign Pipeline Assertion**: The benign telemetry generation runner (`eval/generator.py`) programmatically asserts that benign actors (`alice`, `bob`, `eng1`) never target decoy IP ranges (`10.10.2.20`, `10.10.2.30`, `10.10.3.60`) or reference `svc_dbadmin`.
- **Offline Validation Gate**: `eval/validate_captures.py` scans every benign capture (day_101 through day_105) and enforces that total decoy events and honey tags equal exactly `0`.
