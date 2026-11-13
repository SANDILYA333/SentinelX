# SentinelX Phase F: Living-off-the-Land (LotL) Deception Engine
## Master Architecture Specification

**Status:** APPROVED FOR IMPLEMENTATION  
**Version:** 1.0.0  
**Phase:** Phase F (Advanced Living-off-the-Land Deception)  
**Date:** November 2026  

---

## 1. Executive Overview & Problem Statement

Living-off-the-Land (LotL) tradecraft involves adversaries using legitimate administrative binaries, configurations, and environment resources (`bash`, `ssh`, `cat`, `env`, `find`, `net`, `crontab`) to explore systems, harvest credentials, and pivot across network boundaries without introducing signatured malware. 

Traditional signature-based and honeypot-only detection models suffer from two blind spots:
1. **Network-edge Honeypots** only catch adversaries who attempt external or brute-force connections to dedicated honey-daemons (e.g., Cowrie, OpenCanary). They remain completely blind while an adversary is enumerating internal endpoints (`eng-ws`, `jump-host`, `file-srv`).
2. **Filesystem Change Monitors (FIM)** catch file writes and modifications, but operating system FIM agents (including standard Wazuh syscheck) do not detect read operations (`cat`, `grep`, `source`, `view`).

The **SentinelX Living-off-the-Land Deception Engine** bridges this gap. It plants high-fidelity, believable administrative lures throughout the IT, DMZ, and OT environments, and implements multi-layer telemetry fusion to detect when lures are:
1. Discovered via native directory listing or search commands
2. Read or extracted (`cat .bash_history`, `ssh -i id_rsa`, `env`)
3. Modified or tampered with
4. Used to initiate internal network connections
5. Presented as credentials against canary or honeypot endpoints (Cowrie SSH, OpenCanary MySQL/HTTP, Decoy PLC)

Interactions are normalized into SentinelX canonical `Event`s, enriched with precise lure attribution, fed into the multi-engine detector pipeline, and correlated into evidence-backed attack graph incidents.

---

## 2. System Architecture & Component Responsibilities

The LotL Deception Engine integrates cleanly into SentinelX without altering the canonical event contract, introducing parallel pipelines, or disrupting existing detectors.

```text
                     +-------------------------------------------------------+
                     |             Laboratory Host Infrastructure            |
                     |  (eng-ws, jump-host, file-srv, db-srv, benign)        |
                     +-------------------------------------------------------+
                           |                          |                   |
            [Shell & Process Audit]            [Wazuh FIM]        [Decoy Daemons]
             /var/log/sentinelx/cmd.jsonl       syscheck           Cowrie, OpenCanary,
                           |                          |            Decoy PLC
                           v                          v                   |
                     +---------------------------------------+            |
                     |          Wazuh Manager / Zeek         |            |
                     |  archives.json, conn.log, etc.        |            |
                     +---------------------------------------+            |
                                      |                                   |
                                      +-----------------+-----------------+
                                                        |
                                                        v
                                         +------------------------------+
                                         |   SentinelX Ingest Runtime   |
                                         |    (Tailers & Adapters)      |
                                         +------------------------------+
                                                        |
                                                        v Canonical Events
+---------------------------------------------------------------------------------------------------+
| SentinelX LotL Deception Subsystem                                                                 |
|                                                                                                   |
|  +--------------------+    +--------------------+    +--------------------+    +---------------+  |
|  |   Lure Registry    |<-->|    Lure Manager    |<-->| Interaction Monitor|<-->| Health Monitor|  |
|  | (Metadata, State,  |    | (Deployment, Revert|    | (Correlation, Event|    | (Verification,|  |
|  |  Manifest, Policies|    |  Manifest Control) |    |  Attribution, Tags)|    |  Audit Checks)|  |
|  +--------------------+    +--------------------+    +--------------------+    +---------------+  |
+---------------------------------------------------------------------------------------------------+
                                                        | Canonical Lure Events & Tags
                                                        v
                                         +------------------------------+
                                         |    Detector Pipeline         |
                                         |  - Rules Engine (RULE-LOTL-*) |
                                         |  - Behavioral Baselines      |
                                         |  - Isolation Forest Anomaly  |
                                         |  - Interaction Graph         |
                                         |  - Deception Classifier      |
                                         +------------------------------+
                                                        | Signals
                                                        v
                                         +------------------------------+
                                         |    Correlation Pipeline      |
                                         |  - Graph Entity Correlator   |
                                         |  - Stage Progression         |
                                         |  - Alert Budget Controller   |
                                         |  - Response Safety Guard     |
                                         +------------------------------+
                                                        | Incidents & Guard Decisions
                                                        v
                                         +------------------------------+
                                         |    FastAPI REST & WebSockets |
                                         |    Next.js 15 Analyst UI     |
                                         +------------------------------+
```

### 2.1 Core Components

1. **Lure Registry (`engine/sentinelx/deception/lotl/registry.py`)**:
   - Single source of truth for all deception artifacts.
   - Maintains lure IDs, filenames, hosts, absolute paths, expected interactions, MITRE ATT&CK technique IDs, severity ratings, and enabled/disabled status.
   - Manages persistence in SQLite (`lotl_lures` and `lotl_interactions` tables) with in-memory caching.
   - Enforces secret redaction: canary tokens are hashed or uniquely tagged; actual secret tokens are never exposed in API responses or plain logs.

2. **Lure Manager (`engine/sentinelx/deception/lotl/manager.py`)**:
   - Manages idempotent deployment and cleanup of physical decoy artifacts.
   - Maintains an explicit **Managed Artifact Manifest** tracking file ownership, sha256 checksums, and deployment targets.
   - Safety constraints:
     - Never overwrites real user files (`.bashrc`, real `.bash_history` of active employees).
     - Only deploys into dedicated managed directories or decoy accounts (`svc_backup`, `decoy_admin`).
     - Never performs arbitrary deletion: only files present in the engine's internal deployment manifest can be removed.

3. **Interaction Monitor (`engine/sentinelx/deception/lotl/monitor.py`)**:
   - Multi-layer observation engine fusing telemetry from:
     - **Process & Command Telemetry:** `cmd.jsonl` from `audit-shell` and `prompt-command.sh` on endpoints, detecting file reads (`cat`, `less`, `grep`, `strings`, `nano`, `vim`), environment dumping (`env`, `printenv`), and directory search (`find`, `ls`).
     - **Filesystem Integrity Monitoring (FIM):** Wazuh `syscheck` for file modifications, creations, and deletions.
     - **Decoy Services:** Cowrie SSH session commands and logins, OpenCanary database/web/port probes, and Decoy PLC Modbus commands.
     - **Network Telemetry:** Zeek connection logs (`conn.log`) matching outbound connection requests to decoy IP addresses or ports referenced in lures.
   - Distinguishes directly observed telemetry (`observed`) from inferred attacker intent (`inferred`) and configured topology (`configured`).

4. **Event Normalizer (`engine/sentinelx/deception/lotl/normalizer.py`)**:
   - Translates raw interactions into canonical SentinelX `Event`s conforming strictly to `schemas/event.py`.
   - Populates event metadata with `tags=["decoy", "lotl", f"lure_id:{lure.lure_id}", f"lure_type:{lure.lure_type}"]`.
   - Preserves source context, process IDs, parent process, session IDs, and evidence references.

5. **Lure Health Monitor (`engine/sentinelx/deception/lotl/health.py`)**:
   - Continuously evaluates the operational status of deployed lures and telemetry feeds.
   - Distinguishes three states:
     - `Lure Deployed`: The file exists on the target host with matching checksum.
     - `Lure Monitored`: The telemetry sensor responsible for the host is healthy and streaming events.
     - `Interaction Observed`: Actual interaction events have been received and verified.
   - Detects missing files, unexpected modifications (tampering), disabled lures, and disconnected sensors.

---

## 3. Data Flow & Event Processing Lifecycle

```text
[Attacker Action on eng-ws]
        |
        +---> Attacker executes: `cat /home/svc_backup/.bash_history`
        |
        v
[Endpoint Telemetry Capture]
        |
        +---> audit-shell / prompt-command.sh writes JSON to /var/log/sentinelx/cmd.jsonl
        |
        v
[Wazuh Agent & Manager]
        |
        +---> Wazuh Agent streams log line to Wazuh Manager
        +---> Wazuh Manager appends to /var/ossec/logs/archives/archives.json
        |
        v
[SentinelX Telemetry Ingestion]
        |
        +---> Ingest Tailer reads line from archives.json
        +---> WazuhArchivesAdapter normalizes record into canonical Event:
        |       - category: "process"
        |       - action: "exec"
        |       - host: "eng-ws"
        |       - user: "svc_backup"
        |       - cmdline: "cat /home/svc_backup/.bash_history"
        |
        v
[LotL Interaction Monitor & Classifier]
        |
        +---> Matches cmdline against Lure Registry manifest (/home/svc_backup/.bash_history)
        +---> Enriches Event with tags: ["decoy", "lotl", "lure_id:LURE-HIST-001", "history_discovery"]
        +---> Classifies as DeceptionActivity:
        |       - interaction_type: "shell_history_read"
        |       - mitre_technique: "T1552.001"
        |       - severity: "high"
        |       - provenance: "observed"
        |
        v
[Detector Pipeline]
        |
        +---> RulesEngine fires RULE-LOTL-001 (Shell History Discovery) -> Signal emitted
        +---> Deception Classifier creates DeceptionActivity record
        |
        v
[Incident Correlator]
        |
        +---> Correlates Signal with subsequent SSH key read or Cowrie decoy authentication
        +---> Updates Incident with multi-stage attack progression:
        |       Discovery -> Credential Access -> Lateral Movement
        +---> Updates Attack Graph with provenance edges (observed solid, inferred dashed)
        |
        v
[Analyst Notification]
        +---> Broadcasts to WebSocket stream (/ws/stream)
        +---> Refreshes Next.js Deception & Incident Dashboards in real time
```

---

## 4. Deception Artifact Catalog (Supported Lure Implementations)

All deception artifacts deployed in the lab follow strict design standards:
- **Zero Real Credentials:** All usernames, passwords, API tokens, and SSH keys are synthetic and invalid against production infrastructure.
- **Controlled Decoy Destinations:** Decoy connection targets resolve exclusively to isolated internal lab decoys (`cowrie` at `10.10.2.20`, `opencanary` at `10.10.2.30`, `decoy-plc` at `10.10.3.60`).
- **Plausible Context:** Artifacts look like legitimate operational resources used by systems engineers, backup operators, or database administrators.

| Lure ID | Name | Type | Target Host | Path / Location | Target Decoy | ATT&CK Technique |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `LURE-HIST-001` | Legacy Shell History (Bash) | `shell_history` | `eng-ws` | `/home/svc_backup/.bash_history` | `10.10.2.20:22` (Cowrie) | T1552.001, T1059.004 |
| `LURE-HIST-002` | Maintenance Shell History | `shell_history` | `jump-host` | `/home/svc_backup/.bash_history` | `10.10.2.30:3306` (OpenCanary) | T1552.001, T1059.004 |
| `LURE-SSH-001` | Decoy SSH Private Key | `ssh_key` | `eng-ws` | `/home/svc_backup/.ssh/id_ed25519_backup` | `backup-srv-02` (Cowrie) | T1552.004, T1021.004 |
| `LURE-SSH-002` | Decoy SSH Config Stanza | `ssh_config` | `eng-ws` | `/home/svc_backup/.ssh/config` | `10.10.2.20` (`backup-srv-02`) | T1552.004, T1021.004 |
| `LURE-ENV-001` | Canary Environment Credentials | `canary_env` | `eng-ws` | `/etc/profile.d/backup_env.sh` | Synthetic Canary DB Token | T1552.001, T1078.003 |
| `LURE-ENV-002` | Canary API Token Profile | `canary_env` | `jump-host` | `/etc/profile.d/corp_cloud_api.sh` | Canary Cloud API Credential | T1552.001, T1078.003 |
| `LURE-CFG-001` | Synthetic Ansible Inventory | `config_file` | `jump-host` | `/srv/ansible/hosts.yaml` | `10.10.2.20`, `10.10.3.60` | T1083, T1046 |
| `LURE-CFG-002` | Synthetic Docker Compose Decoy | `config_file` | `eng-ws` | `/opt/internal/docker-compose.backup.yml` | `10.10.2.30:3306` | T1083, T1552.001 |
| `LURE-CFG-003` | Synthetic Kubernetes Config | `config_file` | `jump-host` | `/home/svc_backup/.kube/config` | Synthetic Cluster Decoy | T1083, T1552.001 |
| `LURE-CFG-004` | Decoy SCADA Engineering Config | `config_file` | `eng-ws` | `/opt/scada/config/controllers.conf` | `10.10.3.60:502` (Decoy PLC) | T1083, T0846 |
| `LURE-SHR-001` | Decoy Share Directory (`IT_Backups`)| `decoy_share` | `file-srv` | `/srv/share/IT_Backups/credentials.bak`| Honey Credentials | T1135, T1039 |
| `LURE-SHR-002` | Decoy Share Directory (`SCADA_Configs`)| `file-srv` | `/srv/share/SCADA_Configs/plc_map.txt` | `10.10.3.60` Decoy Mapping | T1135, T1039 |
| `LURE-CRON-001`| Decoy Cron Maintenance Task | `scheduled_task` | `eng-ws` | `/etc/cron.d/decoy_backup_sync` | Harmless inert script | T1053.003 |
| `LURE-WIN-001` | Windows PowerShell History Stub | `powershell_history`| `unsupported` | `ConsoleHost_history.txt` | N/A (Linux Lab) | T1552.001, T1059.001 |

*Note on Windows PowerShell History (`LURE-WIN-001`):* In accordance with Rule 4.3 (Evidence over assumptions) and Rule 7.6, Windows-specific artifacts are registered with status `unsupported` or `not_applicable` in the Linux container lab. They are not faked or declared functional without a true Windows endpoint.

---

## 5. Security & Operational Boundaries

1. **Non-Destructive File Operations**:
   - The Lure Manager checks target paths before writing.
   - If a file exists that is not in the Lure Manager's manifest, the deployment will fail safe rather than overwriting.
   - File deletion is restricted strictly to files registered in the manifest.
2. **Response Safety Guard Preservation**:
   - All response recommendations generated from LotL deception events are marked with the advisory notice:
     `"ADVISORY SAFETY MODE — NO AUTOMATIC EXECUTION"`.
   - The platform never issues automated firewall blocks, account deactivations, process kills, or PLC register overrides.
3. **Redaction & Credential Hygiene**:
   - Synthetic private keys and passwords generated for lures are flagged as canary tokens.
   - APIs returning lure details expose lure metadata, file paths, and telemetry statistics, but redact private key bodies and credentials.

---

## 6. Failure Modes & Resilience

| Failure Mode | Detection | System Behavior |
| :--- | :--- | :--- |
| **Lure file deleted or modified externally** | Lure Health Monitor sha256 checksum check | Lure status changed to `tampered` or `missing`. Health alert emitted. |
| **Endpoint audit logging agent dies** | Lure Health Monitor heartbeat check | Host sensor marked `offline`. Lures on that host transition to `unmonitored`. |
| **Out-of-order telemetry delivery** | Idempotent event ID and sequence timestamping | Correlator correlates events based on event timestamp `ts`, not arrival order. |
| **High telemetry volume during scan** | UI rate limiter (20 events/sec) & batch SQLite inserts | Events persisted via WAL mode without memory leaks or UI freezing. |
| **Container restart** | Lure deployment idempotent recheck | Deployment script verifies existing artifacts and maintains manifest state. |

