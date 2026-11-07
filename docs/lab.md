# SentinelX Lab Architecture & Verification Guide (Phase 1)

This document describes the reproducible SentinelX Docker lab environment, designed to simulate a realistic, segmented IT/OT enterprise network under living-off-the-land adversary activity and passive deception sensing.

---

## 1. Network Topology

The lab isolates traffic strictly across four Docker bridge networks with `internal: true`. No lab traffic ever escapes to the public internet.

```
                      [ PUBLIC INTERNET: BLOCKED (internal: true) ]
                                            X
                                            |
+===========================================|===========================================+
|                                           |                                           |
|   IT ZONE (10.10.1.0/24, br-sx-it)        |                                           |
|   +------------------------------------+  |                                           |
|   | attacker (10.10.1.5)               |  |                                           |
|   | - nmap, sshpass, psql, pymodbus    |  |                                           |
|   | - /opt/attack/ALLOWED_TARGETS      |  |                                           |
|   +-----------------+------------------+  |                                           |
|                     |                     |                                           |
|     +---------------+---------------+     |                                           |
|     |               |               |     |                                           |
|   +-v-------------+ +-v-----------+ +-v---v---------+ +-v---------------+             |
|   | file-srv      | | db-srv      | | jump-host     | | benign          |             |
|   | (10.10.1.20)  | | (10.10.1.30)| | (10.10.1.10)  | | (10.10.1.50)    |             |
|   | - /srv/share  | | - PostgreSQL| | - dual-homed  | | - normal ops    |             |
|   | - honey creds | | - fake data | | - pivot point | | - alice/bob/eng1|             |
|   +-------+-------+ +-----+-------+ +-------+-------+ +---------+-------+             |
|           |               |                 |                   |                     |
|           |               |   +-------------+                   |                     |
|           |               |   |                                 |                     |
|           |               |   |   DMZ ZONE (10.10.2.0/24, br-sx-dmz)                  |
|           |               |   |   +---------------------------------------+           |
|           |               |   +---> cowrie (10.10.2.20)                   |           |
|           |               |   |   | - SSH Decoy ("backup-srv-02")         |           |
|           |               |   |   | - Honey user: svc_dbadmin             |           |
|           |               |   |   +---------------------------------------+           |
|           |               |   |   +---------------------------------------+           |
|           |               |   +---> opencanary (10.10.2.30)               |           |
|           |               |       | - Services: MySQL(3306), HTTP, FTP    |           |
|           |               |       | - Node: db-prod-02                    |           |
|           |               |       +---------------------------------------+           |
|           |               |                                                           |
|   +-------v---------------v-------------------------------------+                     |
|   | eng-ws (10.10.1.40, IT / 10.10.3.40, OT)                    |                     |
|   | - Engineering Workstation (PyModbus, read/write scripts)    |                     |
|   +-----------------------+-------------------------------------+                     |
|                           |                                                           |
|                           |   OT ZONE (10.10.3.0/24, br-sx-ot)                        |
|                           |   +---------------------------------------+               |
|                           +---> plc-sim (10.10.3.20)                  |               |
|                           |   | - PyModbus Tank Server (:502)         |               |
|                           |   | - 1 Hz Physics Loop + State (:8080)   |               |
|                           |   +---------------------------------------+               |
|                           |   +---------------------------------------+               |
|                           + - > decoy-plc (10.10.3.60)                |               |
|                             X | - Secondary Pump Station Decoy        |               |
|                             | | - NEVER contacted by normal hosts     |               |
|                             | +---------------------------------------+               |
|                                                                                       |
+=======================================================================================+
|   MANAGEMENT ZONE (10.10.9.0/24, br-sx-mgmt)                                          |
|   - wazuh-manager (10.10.9.2): collects OSSEC events, FIM, audit logs into archives.json|
|   - Connected to: jump-host, file-srv, db-srv, eng-ws, benign                         |
+=======================================================================================+
|   PASSIVE SENSORS (network_mode: host, Linux packet capture on bridge interfaces)      |
|   - zeek-it  -> sniffs br-sx-it  -> outputs data/logs/zeek-it/conn.log                |
|   - zeek-dmz -> sniffs br-sx-dmz -> outputs data/logs/zeek-dmz/conn.log               |
|   - zeek-ot  -> sniffs br-sx-ot  -> outputs data/logs/zeek-ot/modbus.log              |
+=======================================================================================+
```

---

## 2. Service Inventory Table

| Service Name | Container Name | IP Address(es) | Networks | Role / Purpose | Log Output Path |
|---|---|---|---|---|---|
| `wazuh-manager` | `sentinelx-wazuh-manager` | `10.10.9.2` | `mgmt` | Central telemetry & FIM collector | `./data/logs/wazuh/archives.json` |
| `attacker` | `sentinelx-attacker` | `10.10.1.5` | `it` | Red-team Living-off-the-Land test runner | Stdout / `/opt/attack/` |
| `jump-host` | `sentinelx-jump-host` | `10.10.1.10`, `10.10.2.10`, `10.10.9.10` | `it`, `dmz`, `mgmt` | Dual-homed pivot gateway with honey ssh config | `/var/log/sentinelx/cmd.jsonl` (container) |
| `file-srv` | `sentinelx-file-srv` | `10.10.1.20`, `10.10.9.20` | `it`, `mgmt` | Internal file share with honey credential file | `/var/log/sentinelx/cmd.jsonl` (container) |
| `db-srv` | `sentinelx-db-srv` | `10.10.1.30`, `10.10.9.30` | `it`, `mgmt` | Production PostgreSQL with sample customer data | `/var/log/sentinelx/cmd.jsonl` (container) |
| `eng-ws` | `sentinelx-eng-ws` | `10.10.1.40`, `10.10.3.40`, `10.10.9.40` | `it`, `ot`, `mgmt` | Engineering workstation controlling physical PLC | `/var/log/sentinelx/cmd.jsonl` (container) |
| `benign` | `sentinelx-benign` | `10.10.1.50`, `10.10.9.50` | `it`, `mgmt` | Heartbeat generator executing normal IT/OT jobs | Container logs (`benign_loop.py`) |
| `plc-sim` | `sentinelx-plc-sim` | `10.10.3.20` | `ot` | Primary water tank PLC with 1 Hz physics simulation | `./data/logs/plc/plc-sim-state.jsonl`, `plc-sim-writes.jsonl` |
| `decoy-plc` | `sentinelx-decoy-plc` | `10.10.3.60` | `ot` | Modbus decoy (Station 02); trips on any interaction | `./data/logs/plc/decoy-plc.jsonl` |
| `cowrie` | `sentinelx-cowrie` | `10.10.2.20` | `dmz` | SSH Honeypot decoy named `backup-srv-02` | `./data/logs/cowrie/cowrie.json` |
| `opencanary` | `sentinelx-opencanary` | `10.10.2.30` | `dmz` | Multi-service decoy (`db-prod-02`) listening on MySQL/HTTP/FTP | `./data/logs/opencanary/opencanary.log` |
| `zeek-it` | `sentinelx-zeek-it` | Host (`br-sx-it`) | `host` | Passive network monitor for IT network bridge | `./data/logs/zeek-it/conn.log`, `dns.log` |
| `zeek-dmz` | `sentinelx-zeek-dmz` | Host (`br-sx-dmz`) | `host` | Passive network monitor for DMZ network bridge | `./data/logs/zeek-dmz/conn.log` |
| `zeek-ot` | `sentinelx-zeek-ot` | Host (`br-sx-ot`) | `host` | Passive industrial protocol analyzer for Modbus | `./data/logs/zeek-ot/modbus.log`, `conn.log` |

---

## 3. How to Run the Lab

All operations are managed via top-level `make` targets:

```bash
# 1. Build all lab images
make lab-build

# 2. Start the lab services and wait for health checks
make lab-up

# 3. Check telemetry freshness across all 8 sources (<= 60s threshold)
make lab-check

# 4. Run automated attack & pivot smoke test suite
make lab-smoke

# 5. Export realistic log samples for Phase 2 adapter development
make lab-samples

# 6. View logs for any service
make lab-logs SERVICE=wazuh-manager

# 7. Reset the lab (tear down volumes, wipe logs, start clean)
make lab-reset

# 8. Stop the lab
make lab-down
```

---

## 4. Resource Consumption & Memory Footprint

Total lab memory budget is strictly constrained under **7.0 GB** total. Every container has an enforced `mem_limit`.

Runtime memory measurement (taken via `docker stats --no-stream`):

```
CONTAINER ID   NAME                      CPU %     MEM USAGE / LIMIT   MEM %     NET I/O           BLOCK I/O         PIDS
dd98ab9fa689   sentinelx-zeek-it         0.11%     93.66MiB / 512MiB   18.29%    0B / 0B           1.73MB / 254kB    18
16f533db1627   sentinelx-zeek-dmz        0.11%     91.64MiB / 512MiB   17.90%    0B / 0B           28.7kB / 20.5kB   14
889a5fd1c5b7   sentinelx-zeek-ot         0.14%     91.76MiB / 512MiB   17.92%    0B / 0B           4.71MB / 139kB    16
8687ff38ee2e   sentinelx-opencanary      0.01%     45.89MiB / 128MiB   35.86%    2.2kB / 1.38kB    4.1kB / 1.04MB    2
86e64badab4a   sentinelx-cowrie          0.01%     95.76MiB / 256MiB   37.41%    9.06kB / 5.11kB   47.6MB / 377kB    1
7bed046e0ad6   sentinelx-benign          0.01%     21.73MiB / 256MiB   8.49%     1.11MB / 981kB    10.5MB / 1.33MB   34
f99926e25b3c   sentinelx-file-srv        0.05%     27.47MiB / 256MiB   10.73%    386kB / 450kB     16.9MB / 1.8MB    30
241cd336a5b9   sentinelx-db-srv          0.02%     45.45MiB / 512MiB   8.88%     216kB / 213kB     50.6MB / 18.9MB   35
d2deab1f4139   sentinelx-jump-host       0.01%     17.36MiB / 256MiB   6.78%     172kB / 150kB     6.49MB / 1.39MB   29
5fed69d37030   sentinelx-eng-ws          0.01%     17.19MiB / 256MiB   6.72%     798kB / 1.02MB    10.7MB / 2.25MB   29
179bec41c93f   sentinelx-wazuh-manager   0.23%     491.6MiB / 1.5GiB   32.01%    894kB / 750kB     11.9GB / 21.9GB   397
a18101561818   sentinelx-attacker        0.00%     812KiB / 256MiB     0.31%     35.9kB / 27.7kB   15.9MB / 12.3kB   1
4560e4b5ee95   sentinelx-plc-sim         0.03%     14.59MiB / 128MiB   11.40%    51.2kB / 47.2kB   2.49MB / 868kB    1
8a0a9db1b0b3   sentinelx-decoy-plc       0.00%     14.13MiB / 128MiB   11.04%    2.4kB / 497B      3.44MB / 4.1kB    1
```

Total measured footprint: ~1.05 GB (well under the 7.0 GB limit).

---

## 5. Known Limitations & Architectural Notes

1. **Zeek Sniffing in Host Network Mode:**
   - Zeek containers utilize `network_mode: host` with `cap_add: [NET_ADMIN, NET_RAW]` to sniff the dedicated Linux network bridges (`br-sx-it`, `br-sx-dmz`, `br-sx-ot`).
   - *Limitation:* This requires Linux kernel bridge interfaces. On Docker Desktop for macOS and Windows, Docker runs inside a lightweight VM where host-mode attaches to the VM loopback, not the host physical adapter. The lab is optimized and verified on native Linux (Ubuntu, Debian, Arch).
2. **Command Auditing Without `auditd` in Containers:**
   - The Linux kernel `auditd` subsystem is global and cannot be isolated inside unprivileged container namespaces.
   - *Design Solution:* Command auditing is implemented via SSH `ForceCommand /usr/local/bin/audit-shell` combined with `/etc/profile.d/sentinelx-audit.sh` (`PROMPT_COMMAND` hook). This captures both remote SSH commands (`ssh host 'cmd'`) and interactive shell typing into `/var/log/sentinelx/cmd.jsonl` with structured JSON metadata (`ts`, `host`, `user`, `src_ip`, `session`, `cwd`, `cmd`, `mode`).
3. **Wazuh Manager `archives.json` Decoded Logging:**
   - Standard Wazuh manager only writes alerts to `alerts.json`.
   - *Design Solution:* Configured `<logall_json>yes</logall_json>` in `lab/wazuh/ossec.conf` so the manager writes all decoded events (including low-severity syscheck and authentication events) to `/var/ossec/logs/archives/archives.json`.

---

## 6. Production Path Comparison

| Lab Component | Lab Implementation | Production Replacement |
|---|---|---|
| **Host Telemetry & FIM** | Containerized Debian with Wazuh Agent & `audit-shell` | Real Wazuh Agents installed directly on Windows/Linux servers, workstations, and domain controllers, integrated with native Linux Auditd (`auditctl`) and Windows Event Forwarding (WEF) / Sysmon. |
| **Passive Network Sensors** | Zeek containers sniffing Docker virtual bridge interfaces | Physical or virtual Zeek sensor appliances connected to network SPAN / TAP ports or core switch mirror sessions across IT and ICS core switches. |
| **Decoy Systems** | Single Cowrie & OpenCanary containers in a Docker DMZ | Distributed deception grid (e.g. Thinkst Canary, active deception traps, honey tokens in Active Directory, honey SPNs, canary credentials in password managers). |
| **OT Controller / PLC** | PyModbus async water tank simulation with 1 Hz physics loop | Real PLCs (Rockwell Allen-Bradley, Siemens S7, Schneider Electric Modicon) communicating over industrial fieldbuses and Ethernet/IP, with hardware watchdog modules. |
| **Benign Activity** | Python loop generating synthetic heartbeats across hosts | Real enterprise user traffic, scheduled backup agents, IT automated management (Ansible, SCCM), and standard SCADA HMI polling loops. |

---

## 7. Log Format Notes for Adapters (Phase 2 Reference)

This section provides critical parsing and schema mapping facts for downstream telemetry adapters:

### 7.1 Wazuh Syslog (`/var/log/auth.log`)
- In `archives.json`, SSH authentication lines forwarded from `/var/log/auth.log` have **no syslog timestamp or hostname prefix** in `full_log`. The agent strips them before encapsulation.
- The `decoder` field is an empty dictionary (`{}`).
- Authentication outcomes must be parsed directly from `full_log` text (e.g., regex `Accepted (publickey|key)` vs `Failed password`).

*Real Sample Line (Accepted)*:
```json
{"timestamp":"2026-11-07T16:34:14.492+0000","agent":{"id":"003","name":"jump-host","ip":"10.10.9.10"},"manager":{"name":"wazuh-manager"},"id":"1794069254.428064","full_log":"Accepted publickey for alice from 10.10.1.50 port 37162 ssh2: ED25519 SHA256:2Os6CkDbnC0t3xO94DDLgYyc6TxuZUvg0SiziZS2c6A\r","decoder":{},"location":"/var/log/auth.log"}
```

*Real Sample Line (Failed)*:
```json
{"timestamp":"2026-11-07T16:33:36.472+0000","rule":{"level":2,"description":"Unknown problem somewhere in the system.","id":"1002"},"agent":{"id":"003","name":"jump-host","ip":"10.10.9.10"},"manager":{"name":"wazuh-manager"},"id":"1794069216.428064","full_log":"Failed password for svc_backup from 10.10.1.5 port 35968 ssh2\r","decoder":{},"location":"/var/log/auth.log"}
```

### 7.2 Wazuh Command Auditing (`cmd.jsonl`)
- Raw commands written to `/var/log/sentinelx/cmd.jsonl` are decoded with `"decoder": {"name": "json"}`.
- Field renaming: The original `user` key in `cmd.jsonl` is mapped to `data.dstuser` in `archives.json`.
- Boolean conversion: Booleans (such as `"tty": false`) are cast to strings (`"tty": "false"`).

*Real Sample Line*:
```json
{"timestamp":"2026-11-07T14:55:50.236+0000","agent":{"id":"001","name":"eng-ws"},"manager":{"name":"wazuh-manager"},"id":"1794063350.660280","full_log":"{\"ts\":\"2026-11-07T14:55:48Z\",\"host\":\"eng-ws\",\"user\":\"eng1\",\"src_ip\":\"10.10.1.50\",\"session\":\"140\",\"tty\":false,\"cwd\":\"/home/eng1\",\"cmd\":\"/usr/local/bin/read_plc.py 10.10.3.20 502\",\"mode\":\"exec\"}","decoder":{"name":"json"},"data":{"dstuser":"eng1","ts":"2026-11-07T14:55:48Z","host":"eng-ws","src_ip":"10.10.1.50","session":"140","tty":"false","cwd":"/home/eng1","cmd":"/usr/local/bin/read_plc.py 10.10.3.20 502","mode":"exec"},"location":"/var/log/sentinelx/cmd.jsonl"}
```

### 7.3 Wazuh Syscheck (FIM)
- Syscheck realtime file integrity events **do NOT contain a `full_log` field**.
- File metadata is structured under the `syscheck` JSON object: `path`, `mode`, `size_after`, `perm_before`, `perm_after`, `md5_after`, `sha256_after`, `changed_attributes`, `event`.

*Real Sample Line*:
```json
{"timestamp":"2026-11-07T14:58:27.855+0000","rule":{"level":7,"description":"Integrity checksum changed.","id":"550"},"agent":{"id":"002","name":"file-srv","ip":"10.10.9.20"},"location":"syscheck","syscheck":{"path":"/srv/share/backup/.db_creds","mode":"realtime","size_after":"50","perm_before":"rw-r--r--","perm_after":"rwxrwxrwx","md5_after":"b3bfed64bbc2070646fb013012643755","sha256_after":"419d725758b19f70095a99b04808edf5463258924817601d7183519f299f7228","event":"modified"},"decoder":{"name":"syscheck_integrity_changed"}}
```

### 7.4 Zeek JSON Log Fields
- `conn.log`: `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `orig_pkts`, `resp_pkts`
- `modbus.log`: `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `func`, `pdu_type`, `unit`
- `dns.log`: `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `trans_id`, `query`, `qclass_name`, `qtype_name`, `answers`

### 7.5 Cowrie SSH Decoy
- `eventid` types observed in `data/logs/cowrie/cowrie.json`:
  - `cowrie.session.connect`: incoming connection established
  - `cowrie.login.success`: authentication succeeded (honey user `svc_dbadmin` / `Winter2026!`)
  - `cowrie.login.failed`: authentication rejected
  - `cowrie.command.input`: command typed into honeypot shell
  - `cowrie.session.closed`: connection terminated

### 7.6 OpenCanary Multi-Service Decoy
- `logtype` integer codes observed in `data/logs/opencanary/opencanary.log`:
  - `3001`: HTTP request (method, URI, headers)
  - `5001`: FTP connection attempt
  - `8001`: MySQL login probe (`logdata.USERNAME`, `logdata.PASSWORD` hash)

---

## 8. Secrets & Permissions Architecture

1. **Untracked Secrets**: The Wazuh enrollment password is stored in untracked `lab/.env.local` (mode `0600`), dynamically generated from `lab/.env.example` by `make lab-build` if absent. No passwords or private tokens are tracked in git.
2. **Minimal Log Directory Permissions**:
   - `data/logs`: `0755`
   - `data/logs/wazuh` & `data/logs/cowrie`: `0777` (Wazuh manager and Cowrie run as non-root UID `999`. Because the host workspace is owned by UID `1000`, setting targeted `0777` on these two log mounts is the minimum required to allow container daemons to append logs without running container processes as root or requiring host-level UID remapping).
   - `data/logs/opencanary`, `plc`, `zeek-*`: `0755` (daemons run as root / UID `0`).
   - Blanket `chmod -R 777` across repository files is strictly eliminated.
3. **Storage Quotas & Leak Prevention**:
   - Every service enforces `json-file` log rotation with `max-size: 10m` and `max-file: 3`.
   - `wazuh-manager` disables `<vulnerability-detection>` and `<indexer>` (preventing 10+ GB tar decompression loops and indexer buffering), uses a `64M` tmpfs on `/var/ossec/tmp`, and disables unused Filebeat.
   - `make lab-disk` enforces a strict 500 MB per-container writable layer limit and fails if violated.


