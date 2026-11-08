#!/usr/bin/env python3
"""Realistic benign activity generator simulating legitimate IT/OT operations with diurnal patterns."""

import argparse
import logging
import os
import random
import signal
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [BENIGN] %(message)s")
logger = logging.getLogger("benign")

DEFAULT_CONFIG_PATH = Path("/etc/sentinelx/config.yaml")
LOCAL_CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"

FORBIDDEN_DECOYS = ["10.10.2.20", "10.10.2.30", "10.10.3.60"]
FORBIDDEN_CREDS = ["svc_dbadmin", "Winter2026!"]

# Fallback default configuration
DEFAULT_CONFIG: dict[str, Any] = {
    "sim_speed": 96,
    "diurnal_weights": {
        0: 0.15,
        1: 0.15,
        2: 0.15,
        3: 0.15,
        4: 0.20,
        5: 0.25,
        6: 0.40,
        7: 0.70,
        8: 0.90,
        9: 1.00,
        10: 1.00,
        11: 0.90,
        12: 0.50,
        13: 0.60,
        14: 0.95,
        15: 1.00,
        16: 0.90,
        17: 0.75,
        18: 0.50,
        19: 0.35,
        20: 0.25,
        21: 0.20,
        22: 0.20,
        23: 0.15,
    },
    "maintenance_window": {
        "start_hour": 2,
        "end_hour": 4,
        "min_pump_speed": 48,
        "max_pump_speed": 62,
    },
    "targets": {
        "jump_host": "10.10.1.10",
        "file_srv": "10.10.1.20",
        "db_srv": "10.10.1.30",
        "eng_ws": "10.10.1.40",
        "plc_sim": "10.10.3.20",
    },
    "actors": {
        "alice": {"enabled": True, "interval_range": [15, 30]},
        "bob": {"enabled": True, "interval_range": [25, 45]},
        "eng1": {"enabled": True, "read_interval": 10},
        "svc_backup": {"enabled": True, "interval_range": [40, 70]},
    },
    "noise": {
        "alice_failed_login_prob": 0.05,
        "disconnect_prob": 0.04,
    },
}


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load configuration from YAML file or return defaults."""
    target_path = None
    if config_path and config_path.exists():
        target_path = config_path
    elif DEFAULT_CONFIG_PATH.exists():
        target_path = DEFAULT_CONFIG_PATH
    elif LOCAL_CONFIG_PATH.exists():
        target_path = LOCAL_CONFIG_PATH

    if target_path:
        try:
            import yaml

            with open(target_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    cfg = dict(DEFAULT_CONFIG)
                    cfg.update(loaded)
                    logger.info(f"Loaded config from {target_path}")
                    return cfg
        except Exception as e:
            logger.warning(f"Could not load {target_path} ({e}), using default config.")

    return DEFAULT_CONFIG


def run_cmd(user: str, cmd: str, timeout: int = 15) -> tuple[int, str]:
    """Execute command safely as specific user with strict decoy guard."""
    # STRICT GUARD: Never touch decoys or honey credentials
    for decoy in FORBIDDEN_DECOYS:
        if decoy in cmd:
            raise RuntimeError(f"VIOLATION: Attempted benign action towards decoy IP {decoy}!")
    for cred in FORBIDDEN_CREDS:
        if cred in cmd:
            raise RuntimeError(f"VIOLATION: Attempted benign action using honey credential {cred}!")

    try:
        # Check if running as root inside container or standalone
        if os.geteuid() == 0 and user != "root":
            full_cmd = ["su", "-", user, "-c", cmd]
        else:
            full_cmd = ["bash", "-c", cmd]

        res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        if res.returncode == 0:
            logger.info(f"[{user}] Command succeeded: {cmd[:80]}")
        else:
            logger.debug(f"[{user}] Command returned {res.returncode}: {cmd[:80]}")
        return res.returncode, res.stdout + res.stderr
    except subprocess.TimeoutExpired:
        logger.warning(f"[{user}] Command timed out after {timeout}s: {cmd[:80]}")
        return -1, "timeout"
    except Exception as e:
        logger.error(f"[{user}] Execution error: {e}")
        return -2, str(e)


def run_ssh_password(
    user: str, host: str, password: str, cmd: str, timeout: int = 15
) -> tuple[int, str]:
    """Run password-based SSH command via sshpass or SSH_ASKPASS fallback."""
    # STRICT GUARD
    for decoy in FORBIDDEN_DECOYS:
        if decoy in host:
            raise RuntimeError(f"VIOLATION: Attempted password SSH towards decoy IP {decoy}!")
    for cred in FORBIDDEN_CREDS:
        if cred in password or cred in user:
            raise RuntimeError("VIOLATION: Attempted password SSH using honey credential!")

    # 1. Try sshpass if available
    ssh_cmd = (
        f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
        f"-o PreferredAuthentications=password -o PubkeyAuthentication=no "
        f"{user}@{host} '{cmd}'"
    )
    code, out = run_cmd(user, ssh_cmd, timeout=timeout)
    if code != 127 and "sshpass: not found" not in out:
        return code, out

    # 2. Fallback via SSH_ASKPASS script
    askpass_path = Path("/tmp/sentinelx_askpass.sh")
    try:
        askpass_path.write_text(f"#!/bin/sh\necho '{password}'\n")
        askpass_path.chmod(0o755)
        askpass_cmd = (
            f"SSH_ASKPASS={askpass_path} SSH_ASKPASS_REQUIRE=force DISPLAY=dummy "
            f"ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password "
            f"-o PubkeyAuthentication=no {user}@{host} '{cmd}'"
        )
        return run_cmd(user, askpass_cmd, timeout=timeout)
    finally:
        if askpass_path.exists():
            askpass_path.unlink()


class BenignActivityRunner:
    """Manages actor scheduling, diurnal rate compression, and maintenance windows."""

    def __init__(
        self,
        config: dict[str, Any],
        sim_speed: float | None = None,
        seed: int | None = None,
        start_hour: int | None = None,
    ):
        self.config = config
        self.sim_speed = float(sim_speed or os.getenv("SIM_SPEED") or config.get("sim_speed", 96))
        self.targets = config.get("targets", DEFAULT_CONFIG["targets"])
        self.diurnal_weights = config.get("diurnal_weights", DEFAULT_CONFIG["diurnal_weights"])
        self.maint_cfg = config.get("maintenance_window", DEFAULT_CONFIG["maintenance_window"])
        self.noise_cfg = config.get("noise", DEFAULT_CONFIG["noise"])

        if seed is not None:
            random.seed(seed)
            logger.info(f"Initialized random seed: {seed}")

        self.running = False
        self.wall_start_time = time.time()

        # Staggered simulated start time support
        sh_val = (
            start_hour
            if start_hour is not None
            else int(os.getenv("SIM_START_HOUR"))
            if os.getenv("SIM_START_HOUR") is not None
            else config.get("start_hour")
        )
        now_utc = datetime.now(UTC)
        if sh_val is not None:
            self.sim_start_time = now_utc.replace(
                hour=int(sh_val) % 24, minute=0, second=0, microsecond=0
            )
            logger.info(
                f"Initialized simulated start time: {self.sim_start_time.isoformat()} "
                f"(sim_hour: {int(sh_val) % 24:02d}:00)"
            )
        else:
            self.sim_start_time = now_utc

        # Action timers
        self.last_alice_time = 0.0
        self.last_bob_time = 0.0
        self.last_eng_time = 0.0
        self.last_backup_time = 0.0
        self.read_counter = 0

    def get_simulated_time(self) -> tuple[datetime, int, float]:
        """Calculate current simulated datetime, hour (0-23), and diurnal weight."""
        elapsed_wall = time.time() - self.wall_start_time
        sim_elapsed_seconds = elapsed_wall * self.sim_speed
        current_sim = self.sim_start_time + timedelta(seconds=sim_elapsed_seconds)
        sim_hour = current_sim.hour
        weight = float(
            self.diurnal_weights.get(sim_hour, self.diurnal_weights.get(str(sim_hour), 0.5))
        )
        return current_sim, sim_hour, weight

    def run_alice_action(self):
        """Alice sysadmin tasks: check files, services, uptime, patch checks, short sessions."""
        actions = [
            f"ssh -o StrictHostKeyChecking=no alice@{self.targets['file_srv']} 'ls -la /srv/share'",
            f"ssh -o StrictHostKeyChecking=no alice@{self.targets['file_srv']} 'df -h'",
            f"ssh -o StrictHostKeyChecking=no alice@{self.targets['file_srv']} 'cat /etc/hosts'",
            f"ssh -o StrictHostKeyChecking=no alice@{self.targets['jump_host']} 'uptime'",
            f"ssh -o StrictHostKeyChecking=no alice@{self.targets['jump_host']} 'cat /etc/issue'",
            f"ssh -o StrictHostKeyChecking=no alice@{self.targets['file_srv']} 'apt list --upgradable 2>/dev/null || echo \"All packages current.\"'",
            f"ssh -o StrictHostKeyChecking=no alice@{self.targets['jump_host']} 'ps aux | head -n 10'",
        ]
        cmd = random.choice(actions)
        run_cmd("alice", cmd)

        # Inject light realistic noise: occasional mistyped password by alice (NOT svc_backup or honey)
        if random.random() < self.noise_cfg.get("alice_failed_login_prob", 0.05):
            logger.info("[NOISE] Simulating occasional mistyped password for alice...")
            run_ssh_password(
                "alice", self.targets["jump_host"], "WrongPass2026!", "exit", timeout=5
            )

    def run_bob_action(self):
        """Bob DBA tasks: query customer records, check database stats, small backup."""
        db_ip = self.targets["db_srv"]
        actions = [
            f"PGPASSWORD=BobDatabasePass2026! psql -h {db_ip} -U bob -d postgres -c 'SELECT count(*) FROM customers;'",
            f"PGPASSWORD=BobDatabasePass2026! psql -h {db_ip} -U bob -d postgres -c 'SELECT MAX(id), count(*) FROM customers;'",
            f"PGPASSWORD=BobDatabasePass2026! psql -h {db_ip} -U bob -d postgres -c 'SELECT datname, numbackends FROM pg_stat_database WHERE datname=\\'postgres\\';'",
        ]
        if random.random() < 0.2:
            # Occasional light pg_dump to /tmp, immediately cleaned up
            actions.append(
                f"PGPASSWORD=BobDatabasePass2026! pg_dump -h {db_ip} -U bob -d postgres -t customers -f /tmp/cust_dump.sql && rm -f /tmp/cust_dump.sql"
            )
        cmd = random.choice(actions)
        run_cmd("bob", cmd)

    def run_eng_action(self, sim_hour: int):
        """Eng1 operations: read PLC telemetry; write pump speed ONLY inside maintenance window."""
        self.read_counter += 1
        eng_ip = self.targets["eng_ws"]
        plc_ip = self.targets["plc_sim"]

        # 1. Periodic read every cycle
        read_cmd = f"ssh -o StrictHostKeyChecking=no eng1@{eng_ip} '/usr/local/bin/read_plc.py {plc_ip} 502'"
        run_cmd("eng1", read_cmd)

        # 2. Bounded pump writes ONLY inside maintenance window (simulated hours e.g. 02:00-04:00)
        m_start = self.maint_cfg.get("start_hour", 2)
        m_end = self.maint_cfg.get("end_hour", 4)
        is_maint_hour = m_start <= sim_hour < m_end

        if is_maint_hour and self.read_counter % 3 == 0:
            min_speed = self.maint_cfg.get("min_pump_speed", 48)
            max_speed = self.maint_cfg.get("max_pump_speed", 62)
            speed = random.randint(min_speed, max_speed)
            logger.info(
                f"[eng1] Maintenance window active (sim hour {sim_hour:02d}:00): writing pump speed {speed}%"
            )
            write_cmd = f"ssh -o StrictHostKeyChecking=no eng1@{eng_ip} '/usr/local/bin/write_plc.py {plc_ip} 0 {speed}'"
            run_cmd("eng1", write_cmd)

    def run_svc_backup_action(self):
        """svc_backup cron-style password login performing a single fixed command."""
        jump_ip = self.targets["jump_host"]
        # Password-based SSH using legitimate credentials
        run_ssh_password("svc_backup", jump_ip, "Backup2024!", "uptime", timeout=10)

    def step(self):
        """Execute one evaluation iteration of actors based on elapsed time and diurnal weight."""
        now = time.time()
        sim_dt, sim_hour, diurnal_weight = self.get_simulated_time()

        # Dynamic scaling factor: lower diurnal weight increases inter-action delay
        effective_scale = max(0.2, diurnal_weight)

        # 1. Eng1 Modbus read every ~10s / scale
        eng_interval = self.config["actors"]["eng1"].get("read_interval", 10) / effective_scale
        if now - self.last_eng_time >= eng_interval:
            self.run_eng_action(sim_hour)
            self.last_eng_time = now

        # 2. Alice admin checks
        alice_range = self.config["actors"]["alice"].get("interval_range", [15, 30])
        alice_interval = random.uniform(alice_range[0], alice_range[1]) / effective_scale
        if now - self.last_alice_time >= alice_interval:
            self.run_alice_action()
            self.last_alice_time = now

        # 3. Bob DBA queries
        bob_range = self.config["actors"]["bob"].get("interval_range", [25, 45])
        bob_interval = random.uniform(bob_range[0], bob_range[1]) / effective_scale
        if now - self.last_bob_time >= bob_interval:
            self.run_bob_action()
            self.last_bob_time = now

        # 4. svc_backup periodic cron checks
        backup_range = self.config["actors"]["svc_backup"].get("interval_range", [40, 70])
        backup_interval = random.uniform(backup_range[0], backup_range[1]) / effective_scale
        if now - self.last_backup_time >= backup_interval:
            self.run_svc_backup_action()
            self.last_backup_time = now

    def loop(self, duration_seconds: float | None = None):
        """Run the generator loop for a given duration or indefinitely."""
        self.running = True
        logger.info(
            f"Starting Benign Activity Loop (sim_speed: {self.sim_speed}x, "
            f"duration: {duration_seconds if duration_seconds else 'infinite'}s)..."
        )

        def handle_signal(sig, frame):
            logger.info("Termination signal received. Exiting benign loop gracefully...")
            self.running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        start = time.time()
        while self.running:
            if duration_seconds and (time.time() - start) >= duration_seconds:
                logger.info(f"Target duration of {duration_seconds}s reached. Stopping loop.")
                break

            self.step()
            time.sleep(1.0)

        logger.info("Benign activity loop finished.")


def main():
    parser = argparse.ArgumentParser(description="SentinelX Benign Traffic Generator")
    parser.add_argument(
        "--duration", type=float, default=None, help="Wall-clock duration in seconds"
    )
    parser.add_argument(
        "--sim-speed",
        type=float,
        default=None,
        help="Compression factor (default: from config or 96x)",
    )
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument(
        "--start-hour",
        type=int,
        default=None,
        help="Simulated start hour (0-23) for diurnal staggering",
    )
    parser.add_argument("--config", type=Path, default=None, help="Path to config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    runner = BenignActivityRunner(
        cfg, sim_speed=args.sim_speed, seed=args.seed, start_hour=args.start_hour
    )
    runner.loop(duration_seconds=args.duration)


if __name__ == "__main__":
    main()
