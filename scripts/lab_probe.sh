#!/usr/bin/env bash
set -euo pipebash
# SentinelX Explicit Lab Probe Stimulus (ATTACK-LIKE TRAFFIC)
# WARNING: DO NOT RUN THIS SCRIPT DURING BENIGN TELEMETRY CAPTURES.
# This script explicitly touches decoys and triggers bridge sensors.

echo ">>> [PROBE] Sending probe traffic to IT, DMZ, and OT sensors..."

# 1. Touch Jump-host cmd.jsonl via attacker
docker exec sentinelx-attacker sshpass -p "Backup2024!" \
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
  svc_backup@10.10.1.10 "uptime" >/dev/null 2>&1 || true

# 2. Touch Cowrie SSH decoy from jump-host
docker exec sentinelx-jump-host sshpass -p "Winter2026!" \
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
  -p 22 svc_dbadmin@10.10.2.20 "whoami" >/dev/null 2>&1 || true

# 3. Touch OpenCanary MySQL & HTTP decoys from jump-host
docker exec sentinelx-jump-host mariadb -h 10.10.2.30 -u svc_dbadmin -pWinter2026! \
  --connect-timeout=2 -e "SHOW DATABASES;" >/dev/null 2>&1 || true
docker exec sentinelx-jump-host curl -s -m 2 http://10.10.2.30/ >/dev/null 2>&1 || true

# 4. Touch Decoy PLC & Zeek OT Modbus from eng-ws
docker exec sentinelx-eng-ws /usr/local/bin/read_plc.py 10.10.3.60 502 1 >/dev/null 2>&1 || true
docker exec sentinelx-eng-ws /usr/local/bin/read_plc.py 10.10.3.20 502 1 >/dev/null 2>&1 || true

# 5. Touch Zeek IT from benign
docker exec sentinelx-benign su - alice -c \
  "ssh -o StrictHostKeyChecking=no alice@10.10.1.20 'uptime'" >/dev/null 2>&1 || true

echo ">>> [PROBE] Probe traffic generated successfully."

