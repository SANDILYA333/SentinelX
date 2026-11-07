#!/bin/bash
# SentinelX Lab Smoke Test Suite
set -u

# Resolve logs directory path (host or container)
if [ -d "data/logs" ]; then
    LOGS_DIR="data/logs"
elif [ -d "/opt/attack/data/logs" ]; then
    LOGS_DIR="/opt/attack/data/logs"
else
    LOGS_DIR=""
fi

# Detect execution context
IN_CONTAINER=false
if [ -f "/opt/attack/ALLOWED_TARGETS" ]; then
    IN_CONTAINER=true
fi

run_attacker_cmd() {
    local cmd="$1"
    if [ "$IN_CONTAINER" = true ]; then
        eval "$cmd"
    else
        docker exec sentinelx-attacker bash -c "$cmd"
    fi
}

echo "================================================================================"
echo "                   SENTINELX LAB SMOKE TEST SUITE"
echo "================================================================================"

OVERALL_PASS=true

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
STEP1_OUT=$(run_attacker_cmd 'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 svc_backup@10.10.1.10 "echo SMOKE_STEP_1_SUCCESS && whoami" 2>&1' || true)
echo "Output: $STEP1_OUT"

# Retrieve and print matching cmd.jsonl log line
echo "--- Step 1 Log Evidence (/var/log/sentinelx/cmd.jsonl on jump-host) ---"
CMD_LOG_LINE=$(run_attacker_cmd 'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.10 "tail -n 1 /var/log/sentinelx/cmd.jsonl" 2>/dev/null' || true)
if [ -z "$CMD_LOG_LINE" ] && [ "$IN_CONTAINER" = false ]; then
    CMD_LOG_LINE=$(docker exec sentinelx-jump-host tail -n 1 /var/log/sentinelx/cmd.jsonl 2>/dev/null || true)
fi
echo "$CMD_LOG_LINE"

if echo "$STEP1_OUT" | grep -q "SMOKE_STEP_1_SUCCESS" && echo "$CMD_LOG_LINE" | grep -q "svc_backup"; then
    pass_step "Step 1: SSH to jump-host succeeded and command audit was verified in cmd.jsonl."
else
    fail_step "Step 1: SSH to jump-host failed or cmd.jsonl log evidence missing."
fi

# ------------------------------------------------------------------------------
# STEP 2: Isolation check (Direct attacker -> OT and DMZ connections fail)
# ------------------------------------------------------------------------------
echo ">>> STEP 2: Verifying network isolation (Attacker direct connections to OT & DMZ)..."
echo "Attempting direct TCP connection to PLC (10.10.3.20:502)..."
if run_attacker_cmd "nc -z -w 3 10.10.3.20 502 2>/dev/null"; then
    fail_step "Step 2: Isolation violation! Attacker reached 10.10.3.20:502 directly!"
else
    echo "Direct connection to 10.10.3.20 timed out / unreachable as expected."
fi

echo "Attempting direct TCP connection to Cowrie DMZ (10.10.2.20:22)..."
if run_attacker_cmd "nc -z -w 3 10.10.2.20 22 2>/dev/null"; then
    fail_step "Step 2: Isolation violation! Attacker reached 10.10.2.20:22 directly!"
else
    echo "Direct connection to 10.10.2.20 timed out / unreachable as expected."
fi
pass_step "Step 2: Isolation holds. Attacker cannot reach OT (10.10.3.0/24) or DMZ (10.10.2.0/24) directly."

# ------------------------------------------------------------------------------
# STEP 3: Internet restriction check
# ------------------------------------------------------------------------------
echo ">>> STEP 3: Verifying no outbound internet access from lab network..."
CURL_OUT=$(run_attacker_cmd "curl -m 3 -s https://example.com 2>&1" || true)
if [ -z "$CURL_OUT" ] || echo "$CURL_OUT" | grep -E -q "timed out|Could not resolve|Failed to connect"; then
    echo "curl https://example.com failed as expected ($CURL_OUT)."
    pass_step "Step 3: Internet isolation holds (curl https://example.com timed out/failed)."
else
    fail_step "Step 3: Internet leak detected! curl returned: $CURL_OUT"
fi

# ------------------------------------------------------------------------------
# STEP 4: Harvesting honey credentials & pivoting via jump-host to DMZ decoys
# ------------------------------------------------------------------------------
echo ">>> STEP 4: Harvesting honey credentials and pivoting via jump-host to DMZ decoys..."
echo "Harvesting credentials from file-srv /srv/share/backup/.db_creds..."
CREDS_HARVEST=$(run_attacker_cmd 'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.20 "cat /srv/share/backup/.db_creds" 2>&1' || true)
echo "Harvested credentials: $CREDS_HARVEST"

STEP4_OUT=$(run_attacker_cmd 'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.10 '\''
    echo "Connecting to Cowrie SSH decoy at 10.10.2.20:22 as svc_dbadmin / Winter2026!..."
    sshpass -p "Winter2026!" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 svc_dbadmin@10.10.2.20 "whoami" 2>&1 || true
    echo "Connecting to OpenCanary MySQL decoy at 10.10.2.30:3306 as svc_dbadmin / Winter2026!..."
    mariadb -h 10.10.2.30 -u svc_dbadmin -pWinter2026! --connect-timeout=3 -e "SHOW DATABASES;" 2>&1 || true
'\'' 2>&1' || true)
echo "Output from jump-host pivot:"
echo "$STEP4_OUT"

sleep 2

echo "--- Step 4 Log Evidence (Cowrie: cowrie.json) ---"
COWRIE_LOG_LINE=""
if [ -n "$LOGS_DIR" ] && [ -f "$LOGS_DIR/cowrie/cowrie.json" ]; then
    COWRIE_LOG_LINE=$(tail -n 20 "$LOGS_DIR/cowrie/cowrie.json" | grep "svc_dbadmin" | tail -n 1 || true)
fi
if [ -z "$COWRIE_LOG_LINE" ] && [ "$IN_CONTAINER" = false ]; then
    COWRIE_LOG_LINE=$(docker exec sentinelx-cowrie tail -n 20 /cowrie/cowrie-git/var/log/cowrie/cowrie.json 2>/dev/null | grep "svc_dbadmin" | tail -n 1 || true)
fi
echo "$COWRIE_LOG_LINE"

echo "--- Step 4 Log Evidence (OpenCanary: opencanary.log) ---"
CANARY_LOG_LINE=""
if [ -n "$LOGS_DIR" ] && [ -f "$LOGS_DIR/opencanary/opencanary.log" ]; then
    CANARY_LOG_LINE=$(tail -n 20 "$LOGS_DIR/opencanary/opencanary.log" | grep -E "3001|svc_dbadmin" | tail -n 1 || true)
fi
if [ -z "$CANARY_LOG_LINE" ] && [ "$IN_CONTAINER" = false ]; then
    CANARY_LOG_LINE=$(docker exec sentinelx-opencanary tail -n 20 /var/log/opencanary/opencanary.log 2>/dev/null | grep -E "3001|svc_dbadmin" | tail -n 1 || true)
fi
echo "$CANARY_LOG_LINE"

if [ -n "$COWRIE_LOG_LINE" ] && [ -n "$CANARY_LOG_LINE" ]; then
    pass_step "Step 4: Pivot to Cowrie and OpenCanary executed with honey credentials and verified in logs."
else
    fail_step "Step 4: Honey credential pivot log evidence not found."
fi

# ------------------------------------------------------------------------------
# STEP 5: Modbus reads from engineering workstation (eng-ws)
# ------------------------------------------------------------------------------
echo ">>> STEP 5: Modbus reads from eng-ws to plc-sim (10.10.3.20) and decoy-plc (10.10.3.60)..."
STEP5_OUT=$(run_attacker_cmd 'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 '\''
    echo "Reading plc-sim:"
    /usr/local/bin/read_plc.py 10.10.3.20 502 3
    echo "Reading decoy-plc:"
    /usr/local/bin/read_plc.py 10.10.3.60 502 3
'\'' 2>&1' || true)
echo "Output from eng-ws:"
echo "$STEP5_OUT"

sleep 2

echo "--- Step 5 Log Evidence (Decoy PLC: decoy-plc.jsonl) ---"
DECOY_PLC_LOG=""
if [ -n "$LOGS_DIR" ] && [ -f "$LOGS_DIR/plc/decoy-plc.jsonl" ]; then
    DECOY_PLC_LOG=$(tail -n 5 "$LOGS_DIR/plc/decoy-plc.jsonl" | tail -n 1 || true)
fi
echo "$DECOY_PLC_LOG"

echo "--- Step 5 Log Evidence (Zeek OT: modbus.log) ---"
ZEEK_OT_LOG=""
if [ -n "$LOGS_DIR" ] && [ -f "$LOGS_DIR/zeek-ot/modbus.log" ]; then
    ZEEK_OT_LOG=$(tail -n 10 "$LOGS_DIR/zeek-ot/modbus.log" | tail -n 1 || true)
fi
echo "$ZEEK_OT_LOG"

if echo "$STEP5_OUT" | grep -q "input_registers" && [ -n "$DECOY_PLC_LOG" ] && [ -n "$ZEEK_OT_LOG" ]; then
    pass_step "Step 5: Modbus reads succeeded and verified in decoy-plc.jsonl and zeek-ot modbus.log."
else
    fail_step "Step 5: Modbus read log evidence missing."
fi

# ------------------------------------------------------------------------------
# STEP 6: Physical impact demonstration & honest recovery on plc-sim via eng-ws
# ------------------------------------------------------------------------------
echo ">>> STEP 6: Physical impact test (close valve_position=0, reach unsafe, and verify honest recovery)..."
run_attacker_cmd 'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 '\''
    echo "Setting valve_position = 0% (register 1) to create unsafe pressure/level rise..."
    /usr/local/bin/write_plc.py 10.10.3.20 1 0

    echo "Initial state:"
    curl -s http://10.10.3.20:8080/state | grep -E "tank_level_pct|valve_position_pct|flag"

    reached_unsafe=false
    for sample in 1 2 3 4 5 6 7 8; do
        echo "Waiting 15 seconds (attack observation)..."
        sleep 15
        echo "Sample $sample:"
        state=$(curl -s http://10.10.3.20:8080/state)
        echo "$state" | grep -E "tank_level_pct|valve_position_pct|flag"
        if echo "$state" | grep -q "\"flag\": \"unsafe\""; then
            echo "--> Reached UNSAFE state (>92% level) as required!"
            reached_unsafe=true
            break
        fi
    done

    if [ "$reached_unsafe" != true ]; then
        echo "ERROR: Failed to reach unsafe flag within expected timeframe."
        exit 1
    fi

    echo "Restoring safe operating parameters (valve=50%, pump=50%)..."
    /usr/local/bin/write_plc.py 10.10.3.20 1 50
    /usr/local/bin/write_plc.py 10.10.3.20 0 50

    echo "Monitoring recovery to NORMAL baseline..."
    recovered=false
    for rsample in 1 2 3 4 5 6 7 8 9 10 11 12; do
        echo "Waiting 15 seconds (recovery observation)..."
        sleep 15
        echo "Recovery Sample $rsample:"
        rstate=$(curl -s http://10.10.3.20:8080/state)
        echo "$rstate" | grep -E "tank_level_pct|valve_position_pct|flag"
        if echo "$rstate" | grep -q "\"flag\": \"normal\""; then
            echo "--> Process successfully returned to NORMAL baseline (<80% level)!"
            recovered=true
            break
        fi
    done

    if [ "$recovered" != true ]; then
        echo "ERROR: Process did not return to normal within recovery window."
        exit 1
    fi
'\'' 2>&1'

if [ $? -eq 0 ]; then
    pass_step "Step 6: Physical impact verified: water tank reached unsafe (>92%) and honestly recovered to normal."
else
    fail_step "Step 6: Physical impact or honest recovery test failed."
fi

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
