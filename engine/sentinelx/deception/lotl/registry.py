"""Lure Registry for managing deception artifact definitions, metadata, and state."""

import hashlib
import logging
import sqlite3
from datetime import UTC, datetime
from typing import Any

from sentinelx.deception.lotl.lures import (
    get_canary_env_content,
    get_config_file_content,
    get_decoy_cron_content,
    get_decoy_ssh_config_content,
    get_decoy_ssh_key_content,
    get_share_file_content,
    get_shell_history_content,
)
from sentinelx.schemas.common import Severity
from sentinelx.schemas.deception import LotLLure
from sentinelx.store.sqlite import (
    get_lotl_lure,
    list_lotl_lures,
    set_lotl_lure_enabled,
    upsert_lotl_lure,
)

logger = logging.getLogger(__name__)


def compute_sha256(content: str) -> str:
    """Compute sha256 checksum of string content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


DEFAULT_LURE_DEFINITIONS: list[dict[str, Any]] = [
    {
        "lure_id": "LURE-HIST-001",
        "name": "Legacy Engineering Workstation Bash History",
        "lure_type": "shell_history",
        "platform": "linux",
        "host": "eng-ws",
        "path": "/home/svc_backup/.bash_history",
        "status": "active",
        "expected_interactions": ["read", "discovery"],
        "decoy_destination": "10.10.2.20:22",
        "mitre_techniques": ["T1552.001", "T1059.004"],
        "severity": Severity.high,
        "description": "Planted administrative shell history referencing decoy SSH backup destination and SCADA controllers.",
        "content_generator": lambda: get_shell_history_content("eng-ws"),
    },
    {
        "lure_id": "LURE-HIST-002",
        "name": "Jump-Host Maintenance Bash History",
        "lure_type": "shell_history",
        "platform": "linux",
        "host": "jump-host",
        "path": "/home/svc_backup/.bash_history",
        "status": "active",
        "expected_interactions": ["read", "discovery"],
        "decoy_destination": "10.10.2.30:3306",
        "mitre_techniques": ["T1552.001", "T1059.004"],
        "severity": Severity.high,
        "description": "Administrative history containing database maintenance commands targeting OpenCanary decoy.",
        "content_generator": lambda: get_shell_history_content("jump-host"),
    },
    {
        "lure_id": "LURE-SSH-001",
        "name": "Decoy SSH Private Key",
        "lure_type": "ssh_key",
        "platform": "linux",
        "host": "eng-ws",
        "path": "/home/svc_backup/.ssh/id_ed25519_backup",
        "status": "active",
        "expected_interactions": ["read", "credential_theft", "network_pivot"],
        "decoy_destination": "backup-srv-02 (10.10.2.20)",
        "mitre_techniques": ["T1552.004", "T1021.004"],
        "severity": Severity.critical,
        "description": "Synthetic OpenSSH ED25519 private key referencing Cowrie backup server decoy.",
        "content_generator": get_decoy_ssh_key_content,
    },
    {
        "lure_id": "LURE-SSH-002",
        "name": "Decoy SSH Client Config Stanza",
        "lure_type": "ssh_config",
        "platform": "linux",
        "host": "eng-ws",
        "path": "/home/svc_backup/.ssh/config",
        "status": "active",
        "expected_interactions": ["read", "discovery"],
        "decoy_destination": "10.10.2.20, 10.10.2.30",
        "mitre_techniques": ["T1552.004", "T1021.004"],
        "severity": Severity.high,
        "description": "SSH configuration aliases directing attacker SSH sessions to honeypot services.",
        "content_generator": get_decoy_ssh_config_content,
    },
    {
        "lure_id": "LURE-ENV-001",
        "name": "Canary Backup Environment Credentials",
        "lure_type": "canary_env",
        "platform": "linux",
        "host": "eng-ws",
        "path": "/etc/profile.d/backup_env.sh",
        "status": "active",
        "expected_interactions": ["read", "canary_token_presentation"],
        "decoy_destination": "http://10.10.2.30:8080/canary/auth",
        "mitre_techniques": ["T1552.001", "T1078.003"],
        "severity": Severity.high,
        "description": "Canary environment variables containing canary backup token and decoy database connection string.",
        "content_generator": lambda: get_canary_env_content("backup"),
    },
    {
        "lure_id": "LURE-ENV-002",
        "name": "Canary Cloud Management Profile",
        "lure_type": "canary_env",
        "platform": "linux",
        "host": "jump-host",
        "path": "/etc/profile.d/corp_cloud_api.sh",
        "status": "active",
        "expected_interactions": ["read", "canary_token_presentation"],
        "decoy_destination": "http://10.10.2.20:2222/auth",
        "mitre_techniques": ["T1552.001", "T1078.003"],
        "severity": Severity.high,
        "description": "Canary cloud environment variables referencing isolated decoy management endpoint.",
        "content_generator": lambda: get_canary_env_content("cloud"),
    },
    {
        "lure_id": "LURE-CFG-001",
        "name": "Synthetic Ansible Inventory",
        "lure_type": "config_file",
        "platform": "linux",
        "host": "jump-host",
        "path": "/srv/ansible/hosts.yaml",
        "status": "active",
        "expected_interactions": ["read", "infrastructure_discovery"],
        "decoy_destination": "10.10.2.20, 10.10.3.60",
        "mitre_techniques": ["T1083", "T1046"],
        "severity": Severity.medium,
        "description": "Ansible infrastructure inventory listing DMZ and OT controllers including honey-PLC.",
        "content_generator": lambda: get_config_file_content("ansible"),
    },
    {
        "lure_id": "LURE-CFG-002",
        "name": "Decoy Docker Compose Infrastructure",
        "lure_type": "config_file",
        "platform": "linux",
        "host": "eng-ws",
        "path": "/opt/internal/docker-compose.backup.yml",
        "status": "active",
        "expected_interactions": ["read", "credential_theft"],
        "decoy_destination": "10.10.2.30:3306",
        "mitre_techniques": ["T1083", "T1552.001"],
        "severity": Severity.high,
        "description": "Decoy Docker Compose file containing database credentials pointing to OpenCanary.",
        "content_generator": lambda: get_config_file_content("compose"),
    },
    {
        "lure_id": "LURE-CFG-003",
        "name": "Synthetic Kubernetes Cluster Config",
        "lure_type": "config_file",
        "platform": "linux",
        "host": "jump-host",
        "path": "/home/svc_backup/.kube/config",
        "status": "active",
        "expected_interactions": ["read", "credential_theft"],
        "decoy_destination": "https://10.10.2.25:6443",
        "mitre_techniques": ["T1083", "T1552.001"],
        "severity": Severity.high,
        "description": "Synthetic kubeconfig with canary service token pointing to decoy API server.",
        "content_generator": lambda: get_config_file_content("kube"),
    },
    {
        "lure_id": "LURE-CFG-004",
        "name": "Decoy SCADA Controllers Config",
        "lure_type": "config_file",
        "platform": "linux",
        "host": "eng-ws",
        "path": "/opt/scada/config/controllers.conf",
        "status": "active",
        "expected_interactions": ["read", "ot_discovery"],
        "decoy_destination": "10.10.3.60:502",
        "mitre_techniques": ["T1083", "T0846"],
        "severity": Severity.critical,
        "description": "SCADA controller config file referencing secondary decoy PLC (10.10.3.60).",
        "content_generator": lambda: get_config_file_content("scada"),
    },
    {
        "lure_id": "LURE-SHR-001",
        "name": "Decoy Share Credentials Backup",
        "lure_type": "decoy_share",
        "platform": "linux",
        "host": "file-srv",
        "path": "/srv/share/IT_Backups/credentials.bak",
        "status": "active",
        "expected_interactions": ["read", "share_enumeration", "credential_theft"],
        "decoy_destination": "10.10.2.30",
        "mitre_techniques": ["T1135", "T1039", "T1552.001"],
        "severity": Severity.high,
        "description": "Decoy IT backup credentials stored in SMB/NFS shared directory.",
        "content_generator": lambda: get_share_file_content("credentials"),
    },
    {
        "lure_id": "LURE-SHR-002",
        "name": "Decoy Share SCADA Subnet Map",
        "lure_type": "decoy_share",
        "platform": "linux",
        "host": "file-srv",
        "path": "/srv/share/SCADA_Configs/plc_map.txt",
        "status": "active",
        "expected_interactions": ["read", "share_enumeration", "ot_discovery"],
        "decoy_destination": "10.10.3.60",
        "mitre_techniques": ["T1135", "T1039", "T0846"],
        "severity": Severity.high,
        "description": "Decoy network architecture map stored in shared engineering directory.",
        "content_generator": lambda: get_share_file_content("scada"),
    },
    {
        "lure_id": "LURE-CRON-001",
        "name": "Decoy Scheduled Maintenance Task",
        "lure_type": "scheduled_task",
        "platform": "linux",
        "host": "eng-ws",
        "path": "/etc/cron.d/decoy_backup_sync",
        "status": "active",
        "expected_interactions": ["read", "tampering", "persistence_investigation"],
        "decoy_destination": None,
        "mitre_techniques": ["T1053.003", "T1565.001"],
        "severity": Severity.medium,
        "description": "Inert decoy cron job executing harmless placeholder script to monitor tampering.",
        "content_generator": get_decoy_cron_content,
    },
    {
        "lure_id": "LURE-WIN-001",
        "name": "Windows PowerShell ConsoleHost History Stub",
        "lure_type": "powershell_history",
        "platform": "windows",
        "host": "unsupported",
        "path": "C:\\Users\\svc_backup\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        "status": "unsupported",
        "expected_interactions": ["read", "powershell_discovery"],
        "decoy_destination": "10.10.2.20",
        "mitre_techniques": ["T1552.001", "T1059.001"],
        "severity": Severity.low,
        "description": "Platform-specific stub for Windows environments. Unsupported in Linux Docker lab.",
        "content_generator": lambda: "# Windows PowerShell history stub",
    },
]


class LureRegistry:
    """Thread-safe registry managing deception lure definitions and operational state."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self._ensure_seed()

    def _ensure_seed(self) -> None:
        """Seed registry in SQLite if empty."""
        existing = list_lotl_lures(self.db)
        if not existing:
            now = datetime.now(UTC)
            for d in DEFAULT_LURE_DEFINITIONS:
                content = d["content_generator"]()
                sha = compute_sha256(content)
                # Redact preview for sensitive credential or key lures
                if d["lure_type"] in ("ssh_key", "canary_env") or "private key" in content.lower():
                    preview = "[REDACTED_DECEPTION_CANARY_SECRET]"
                else:
                    preview = content[:120].strip()

                lure = LotLLure(
                    lure_id=d["lure_id"],
                    name=d["name"],
                    lure_type=d["lure_type"],
                    platform=d["platform"],
                    host=d["host"],
                    path=d["path"],
                    status=d["status"],
                    created_at=now,
                    expected_interactions=d["expected_interactions"],
                    decoy_destination=d["decoy_destination"],
                    mitre_techniques=d["mitre_techniques"],
                    severity=d["severity"],
                    enabled=d["status"] != "unsupported",
                    sha256_hash=sha,
                    description=d["description"],
                    metadata={"content_sample_preview": preview},
                )
                upsert_lotl_lure(self.db, lure)
            logger.info("LureRegistry seeded with %d default lures.", len(DEFAULT_LURE_DEFINITIONS))

    def get_lure(self, lure_id: str) -> LotLLure | None:
        """Retrieve a lure by ID."""
        return get_lotl_lure(self.db, lure_id)

    def list_lures(
        self,
        host: str | None = None,
        lure_type: str | None = None,
        status: str | None = None,
        enabled: bool | None = None,
    ) -> list[LotLLure]:
        """List lures matching filter criteria."""
        return list_lotl_lures(self.db, host=host, lure_type=lure_type, status=status, enabled=enabled)

    def enable_lure(self, lure_id: str) -> LotLLure | None:
        """Enable a lure."""
        return set_lotl_lure_enabled(self.db, lure_id, True)

    def disable_lure(self, lure_id: str) -> LotLLure | None:
        """Disable a lure."""
        return set_lotl_lure_enabled(self.db, lure_id, False)

    def find_lures_by_path(self, path: str, host: str | None = None) -> list[LotLLure]:
        """Find active lures matching a file path or filename substring."""
        all_lures = self.list_lures(host=host, enabled=True)
        path_clean = path.lower().strip()
        matched = []
        for lure in all_lures:
            lure_path_clean = lure.path.lower().strip()
            if lure_path_clean == path_clean:
                matched.append(lure)
            elif lure_path_clean.endswith(path_clean) or path_clean.endswith(lure_path_clean):
                matched.append(lure)
            elif "/" in lure_path_clean and lure_path_clean.split("/")[-1] in path_clean:
                # e.g. .bash_history or id_ed25519_backup
                matched.append(lure)
        return matched

    def find_lure_by_command(self, cmdline: str, host: str | None = None) -> LotLLure | None:
        """Find a lure matching an executed command string."""
        if not cmdline:
            return None
        all_lures = self.list_lures(host=host, enabled=True)
        cmd_clean = cmdline.lower()

        # Check exact path or key tokens
        for lure in all_lures:
            lure_path = lure.path.lower()
            filename = lure_path.split("/")[-1] if "/" in lure_path else lure_path

            if lure_path in cmd_clean or filename in cmd_clean:
                return lure

            # Check canary tokens
            if "canary" in lure.lure_type or "env" in lure.lure_type:
                if "canary" in cmd_clean or "backup_env" in cmd_clean or "corp_cloud" in cmd_clean:
                    return lure

        return None
