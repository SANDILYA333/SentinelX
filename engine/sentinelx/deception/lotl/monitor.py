"""Interaction Monitor for detecting and attributing LotL deception artifact touches."""

import logging
import sqlite3
from typing import Any

from sentinelx.deception.lotl.registry import LureRegistry
from sentinelx.schemas.common import Outcome, Severity
from sentinelx.schemas.deception import DeceptionInteractionType, LotLInteraction
from sentinelx.schemas.event import Event
from sentinelx.store.sqlite import record_lotl_interaction

logger = logging.getLogger(__name__)


class InteractionMonitor:
    """Evaluates incoming telemetry events against the Lure Registry to attribute deception touches."""

    def __init__(self, registry: LureRegistry, db: sqlite3.Connection):
        self.registry = registry
        self.db = db

    def evaluate_event(self, event: Event) -> LotLInteraction | None:
        """Inspect a normalized SentinelX Event and return a LotLInteraction if it touches a lure."""
        cmdline = (event.cmdline or "").strip()
        host = event.host or "unknown"
        user = event.user
        action = event.action or ""
        category = event.category or ""
        tags = [t.lower() for t in (event.tags or [])]

        # 1. Command execution / File Read Monitoring (from audit-shell / cmd.jsonl)
        if category == "process" and cmdline:
            lure = self.registry.find_lure_by_command(cmdline, host=host)
            if not lure:
                # Fallback: check across all hosts if cmdline contains exact path
                lure = self.registry.find_lure_by_command(cmdline, host=None)

            if lure:
                interaction_type = self._determine_command_interaction_type(cmdline, lure.lure_type)
                interaction = LotLInteraction(
                    interaction_id=f"lotl_act_{event.event_id.replace('evt_', '')}",
                    lure_id=lure.lure_id,
                    lure_name=lure.name,
                    lure_type=lure.lure_type,
                    interaction_type=interaction_type,
                    host=host,
                    user=user,
                    process=event.process,
                    cmdline=cmdline,
                    target=lure.path,
                    ts=event.ts,
                    event_id=event.event_id,
                    severity=lure.severity,
                    evidence_source=str(event.source_tool),
                    provenance="observed",
                    mitre_technique=lure.mitre_techniques[0] if lure.mitre_techniques else None,
                    outcome=Outcome.success,
                    raw_ref=event.raw_ref or {},
                    metadata={
                        "tags": tags,
                        "session_id": event.session_id,
                        "src_ip": event.src_ip,
                    },
                )
                record_lotl_interaction(self.db, interaction)
                return interaction

        # 2. Filesystem Integrity Monitoring (Wazuh FIM syscheck events)
        if category == "file" or "fim" in tags:
            raw_path = str(event.raw.get("path") or event.raw.get("syscheck", {}).get("path") or "")
            if raw_path:
                matching_lures = self.registry.find_lures_by_path(raw_path, host=host)
                if matching_lures:
                    lure = matching_lures[0]
                    interaction_type: DeceptionInteractionType = (
                        "decoy_task_modified"
                        if "cron" in lure.lure_type or "task" in lure.lure_type
                        else "decoy_file_modified"
                    )
                    interaction = LotLInteraction(
                        interaction_id=f"lotl_act_{event.event_id.replace('evt_', '')}",
                        lure_id=lure.lure_id,
                        lure_name=lure.name,
                        lure_type=lure.lure_type,
                        interaction_type=interaction_type,
                        host=host,
                        user=user,
                        process=event.process,
                        cmdline=cmdline or f"FIM action '{action}' on {raw_path}",
                        target=raw_path,
                        ts=event.ts,
                        event_id=event.event_id,
                        severity=Severity.high,
                        evidence_source="wazuh_syscheck",
                        provenance="observed",
                        mitre_technique="T1565.001",
                        outcome=Outcome.success,
                        raw_ref=event.raw_ref or {},
                        metadata={"action": action, "raw_path": raw_path},
                    )
                    record_lotl_interaction(self.db, interaction)
                    return interaction

        # 3. Decoy Service Authentication / Connection Pivots (Cowrie / OpenCanary)
        if event.domain == "decoy" or event.source_tool in ("cowrie", "opencanary"):
            # Check if this interaction directly followed or referenced a known lure
            dst_ip = event.dst_ip or ""
            matching_lures = [
                l for l in self.registry.list_lures(enabled=True)
                if l.decoy_destination and (dst_ip in l.decoy_destination or (event.host and event.host in l.decoy_destination))
            ]
            if matching_lures:
                lure = matching_lures[0]
                is_canary_tok = False
                if event.user and "canary" in event.user.lower():
                    is_canary_tok = True

                interaction_type = (
                    "canary_credential_presented" if is_canary_tok
                    else ("ssh_login_success" if "login_success" in action else "ssh_connection")
                )
                interaction = LotLInteraction(
                    interaction_id=f"lotl_act_{event.event_id.replace('evt_', '')}",
                    lure_id=lure.lure_id,
                    lure_name=lure.name,
                    lure_type=lure.lure_type,
                    interaction_type=interaction_type,
                    host=host,
                    user=user,
                    process=event.process,
                    cmdline=cmdline,
                    target=f"{event.host or dst_ip}:{event.dst_port or 22}",
                    ts=event.ts,
                    event_id=event.event_id,
                    severity=Severity.critical if is_canary_tok else Severity.high,
                    evidence_source=str(event.source_tool),
                    provenance="observed",
                    mitre_technique="T1078.003",
                    outcome=event.outcome or Outcome.success,
                    raw_ref=event.raw_ref or {},
                    metadata={
                        "decoy_target": lure.decoy_destination,
                        "src_ip": event.src_ip,
                        "dst_ip": event.dst_ip,
                    },
                )
                record_lotl_interaction(self.db, interaction)
                return interaction

        return None

    def _determine_command_interaction_type(
        self, cmdline: str, lure_type: str
    ) -> DeceptionInteractionType:
        """Map command string and lure type to specific interaction category."""
        cmd_lower = cmdline.lower()

        if lure_type == "shell_history":
            return "shell_history_read"
        elif lure_type == "ssh_key":
            if "ssh " in cmd_lower or "-i" in cmd_lower:
                return "ssh_key_read"
            return "ssh_key_read"
        elif lure_type == "ssh_config":
            return "ssh_config_read"
        elif lure_type == "canary_env":
            if "canary" in cmd_lower and ("curl" in cmd_lower or "auth" in cmd_lower):
                return "canary_credential_presented"
            return "canary_variable_read"
        elif lure_type == "config_file":
            return "config_file_read"
        elif lure_type == "decoy_share":
            if "ls " in cmd_lower or "dir " in cmd_lower or "find " in cmd_lower:
                return "share_enumerated"
            return "share_file_read"
        elif lure_type == "scheduled_task":
            return "decoy_task_modified"

        return "config_file_read"

