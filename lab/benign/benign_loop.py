#!/usr/bin/env python3
"""Benign traffic generator simulating legitimate IT/OT operations."""
import logging
import random
import subprocess
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [BENIGN] %(message)s")
logger = logging.getLogger("benign")

def run_cmd(user: str, cmd: str):
    try:
        full_cmd = ["su", "-", user, "-c", cmd]
        res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=15)
        if res.returncode == 0:
            logger.info(f"[{user}] Command succeeded: {cmd}")
        else:
            logger.warning(f"[{user}] Command failed ({res.returncode}): {cmd}\n{res.stderr.strip()}")
    except Exception as e:
        logger.error(f"[{user}] Execution error: {e}")

def main():
    logger.info("Starting benign activity loop...")
    # Initial sleep to allow services to start and Wazuh to enroll
    time.sleep(10)

    plc_read_counter = 0

    while True:
        try:
            # 1. Engineering workstation reads PLC every ~10s
            plc_read_counter += 1
            run_cmd("eng1", "ssh -o StrictHostKeyChecking=no eng1@10.10.1.40 '/usr/local/bin/read_plc.py 10.10.3.20 502'")

            # Occasionally write pump speed within safe operational range (40 - 70)
            if plc_read_counter % 3 == 0:
                speed = random.randint(45, 65)
                run_cmd("eng1", f"ssh -o StrictHostKeyChecking=no eng1@10.10.1.40 '/usr/local/bin/write_plc.py 10.10.3.20 0 {speed}'")

            # 2. General IT action every 20-40s
            action = random.choice(["alice_share", "bob_db", "alice_jumphost", "alice_dns"])
            if action == "alice_share":
                run_cmd("alice", "ssh -o StrictHostKeyChecking=no alice@10.10.1.20 'ls -la /srv/share'")
            elif action == "bob_db":
                run_cmd("bob", "PGPASSWORD=BobDatabasePass2026! psql -h 10.10.1.30 -U bob -d postgres -c 'SELECT count(*) FROM customers;'")
            elif action == "alice_jumphost":
                run_cmd("alice", "ssh -o StrictHostKeyChecking=no alice@10.10.1.10 'uptime'")
            elif action == "alice_dns":
                run_cmd("alice", "python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b\"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x08filesrv\\x04corp\\x00\\x00\\x01\\x00\\x01\", (\"10.10.1.20\", 53))'")

        except Exception as e:
            logger.error(f"Loop iteration error: {e}")

        # Sleep between 10 and 15 seconds so PLC is read roughly every ~10-15s and IT actions occur every 20-40s
        time.sleep(random.uniform(10.0, 15.0))

if __name__ == "__main__":
    main()

