"""Deterministic deception event classifier and intelligence interpretation layer."""

import logging
from typing import Any

from sentinelx.normalize.assets import get_assets
from sentinelx.schemas.common import Outcome, Severity
from sentinelx.schemas.deception import DeceptionActivity, DeceptionInteractionType
from sentinelx.schemas.event import Event

logger = logging.getLogger(__name__)


def is_deception_event(event: Event) -> bool:
    """Return True if an event involves deceptive canary infrastructure."""
    assets = get_assets()
    host_clean = (event.host or "").lower().strip()
    dst_ip = event.dst_ip
    source_tool = str(
        event.source_tool.value if hasattr(event.source_tool, "value") else event.source_tool
    ).lower()
    tags = [t.lower() for t in (event.tags or [])]

    is_decoy_tool = source_tool in ("cowrie", "opencanary")
    is_decoy_domain = getattr(event, "domain", None) == "decoy" or "decoy" in tags
    is_decoy_host = (
        "decoy" in host_clean
        or host_clean in ("backup-srv-02", "db-prod-02", "cowrie", "opencanary", "decoy-plc")
        or assets.is_decoy(event.host)
        or assets.is_decoy(dst_ip)
    )
    return bool(is_decoy_tool or is_decoy_domain or is_decoy_host)


def classify_deception_event(
    event: Event,
    incident_id: str | None = None,
    signal_id: str | None = None,
) -> DeceptionActivity | None:
    """Classify a normalized Event into a structured DeceptionActivity record.

    Returns None if the event is not associated with deceptive canary infrastructure.
    """
    assets = get_assets()

    # Determine if event touches deception infrastructure
    host_clean = (event.host or "").lower().strip()
    src_ip = event.src_ip
    dst_ip = event.dst_ip
    action = (event.action or "").lower()
    source_tool = str(
        event.source_tool.value if hasattr(event.source_tool, "value") else event.source_tool
    ).lower()
    tags = [t.lower() for t in (event.tags or [])]

    is_decoy_tool = source_tool in ("cowrie", "opencanary")
    is_decoy_domain = getattr(event, "domain", None) == "decoy" or "decoy" in tags
    is_decoy_host = (
        "decoy" in host_clean
        or host_clean in ("backup-srv-02", "db-prod-02", "cowrie", "opencanary", "decoy-plc")
        or assets.is_decoy(event.host)
        or assets.is_decoy(dst_ip)
    )

    if not (is_decoy_tool or is_decoy_domain or is_decoy_host):
        return None

    # Resolve canonical target decoy asset
    target_host = None
    if event.host:
        target_host = assets.get_host_by_name(event.host)
    if not target_host and dst_ip:
        target_host = assets.get_host_by_ip(dst_ip)
    if not target_host and "cowrie" in source_tool:
        target_host = assets.get_host_by_name("cowrie")
    if not target_host and "canary" in source_tool:
        target_host = assets.get_host_by_name("opencanary")

    if target_host and target_host.is_decoy:
        decoy_asset = target_host.name
        decoy_hostname = target_host.hostname or target_host.name
        decoy_type = target_host.role
        network_zone = target_host.zone
    elif (
        "cowrie" in source_tool
        or "backup-srv" in host_clean
        or "cowrie" in host_clean
        or (dst_ip and dst_ip == "10.10.2.20")
    ):
        decoy_asset = "cowrie"
        decoy_hostname = event.host or "backup-srv-02"
        decoy_type = "ssh_decoy"
        network_zone = "dmz"
    elif (
        "canary" in source_tool
        or "db-prod" in host_clean
        or "opencanary" in host_clean
        or (dst_ip and dst_ip == "10.10.2.30")
    ):
        decoy_asset = "opencanary"
        decoy_hostname = event.host or "db-prod-02"
        decoy_type = "multi_service_decoy"
        network_zone = "dmz"
    elif "decoy-plc" in host_clean or (dst_ip and dst_ip == "10.10.3.60"):
        decoy_asset = "decoy-plc"
        decoy_hostname = "decoy-plc"
        decoy_type = "plc_decoy"
        network_zone = "ot"
    else:
        decoy_asset = host_clean or source_tool or "unknown_decoy"
        decoy_hostname = event.host or decoy_asset
        decoy_type = "generic_decoy"
        network_zone = assets.get_zone_for_ip(dst_ip) or "dmz"

    # Attacker role
    attacker_role = None
    if src_ip == "10.10.1.5" or (event.user and assets.is_honey_user(event.user)):
        attacker_role = "untrusted_actor"

    # Deterministic interaction classification
    interaction_type: DeceptionInteractionType = "unauthorized_interaction"
    title = f"Deception Interaction on {decoy_hostname}"
    description = f"Observed activity on deceptive canary asset '{decoy_hostname}'."
    outcome = event.outcome or Outcome.success
    severity = Severity.medium
    mitre_technique = None
    metadata: dict[str, Any] = {
        "user": event.user,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
    }

    # Cowrie SSH interactions
    if decoy_asset == "cowrie" or source_tool == "cowrie":
        if "login_success" in action or action == "ssh_login_success":
            interaction_type = "ssh_login_success"
            title = "Successful Honeypot Authentication"
            description = (
                f"Attacker successfully authenticated as '{event.user}' on Cowrie SSH decoy ({decoy_hostname}). "
                "Bait credentials confirmed."
            )
            outcome = Outcome.success
            severity = Severity.high
            mitre_technique = "T1078.003"
        elif "login_failed" in action or action == "ssh_login_failed":
            interaction_type = "ssh_login_attempt"
            title = "Failed Honeypot Authentication Attempt"
            description = f"Failed SSH authentication attempt for '{event.user}' on Cowrie decoy ({decoy_hostname})."
            outcome = Outcome.failure
            severity = Severity.low
            mitre_technique = "T1110"
        elif "command" in action or event.cmdline:
            interaction_type = "ssh_command_input"
            cmd = event.cmdline or (str(event.raw.get("input", "")) if event.raw else "")
            title = "Command Execution in Honeypot Sandbox"
            description = (
                f"Attacker executed command `{cmd}` inside Cowrie sandbox."
                if cmd
                else f"Attacker submitted input inside Cowrie sandbox ({decoy_hostname})."
            )
            outcome = Outcome.success
            severity = Severity.high
            mitre_technique = "T1059.004"
            metadata["cmdline"] = cmd
        elif "connect" in action:
            interaction_type = "ssh_connection"
            title = "Inbound Connection to SSH Decoy"
            description = (
                f"Inbound SSH connection established to honeypot from {src_ip or 'unknown IP'}."
            )
            outcome = Outcome.success
            severity = Severity.low
            mitre_technique = "T1021.004"
        elif "close" in action:
            interaction_type = "session_closed"
            title = "Honeypot SSH Session Terminated"
            description = f"SSH session closed on Cowrie decoy ({decoy_hostname})."
            outcome = Outcome.success
            severity = Severity.low
        elif "file" in action or "download" in action:
            interaction_type = "ssh_file_transfer"
            title = "File Transfer Attempt in Honeypot"
            description = "Attacker initiated file transfer inside honeypot sandbox."
            outcome = Outcome.success
            severity = Severity.medium
            mitre_technique = "T1105"

    # OpenCanary multi-service interactions
    elif decoy_asset == "opencanary" or source_tool == "opencanary":
        logtype = event.raw.get("logtype") if event.raw else None
        if logtype == 8001 or "mysql" in action:
            interaction_type = "mysql_login_attempt"
            title = "MySQL Database Authentication Probe on Decoy"
            description = f"Unauthorized MySQL login probe against OpenCanary decoy ({decoy_hostname}) for user '{event.user}'."
            outcome = Outcome.failure
            severity = Severity.high
            mitre_technique = "T1078"
            metadata["logtype"] = 8001
        elif logtype == 3001 or "http" in action:
            interaction_type = "http_interaction"
            title = "HTTP Service Probe on Decoy"
            description = (
                f"HTTP request received on OpenCanary decoy web service ({decoy_hostname})."
            )
            outcome = Outcome.success
            severity = Severity.medium
            mitre_technique = "T1190"
            metadata["logtype"] = 3001
        elif logtype in (9003, 5001) or "probe" in action or action == "conn":
            interaction_type = "port_probe"
            title = "Service Port Probe on Multi-Service Decoy"
            description = f"TCP port scan/probe against OpenCanary decoy ({decoy_hostname}) on port {event.dst_port or 3306}."
            outcome = Outcome.success
            severity = Severity.medium
            mitre_technique = "T1046"
            metadata["logtype"] = logtype
        else:
            interaction_type = "service_discovery"
            title = "Service Discovery Probe on Decoy"
            description = f"Discovery interaction observed on OpenCanary decoy ({decoy_hostname})."
            outcome = Outcome.success
            severity = Severity.low
            mitre_technique = "T1046"

    # Decoy PLC / Modbus interactions
    elif decoy_asset == "decoy-plc" or "modbus" in action or "plc" in host_clean:
        if "write" in action:
            interaction_type = "modbus_write_attempt"
            title = "Modbus OT Write Attempt on Decoy PLC"
            description = (
                f"Unauthorized Modbus write command delivered to decoy PLC ({decoy_hostname})."
            )
            outcome = event.outcome or Outcome.success
            severity = Severity.critical
            mitre_technique = "T0855"
        elif "read" in action or "input_registers" in action:
            interaction_type = "modbus_read"
            title = "Modbus Telemetry Query on Decoy PLC"
            description = f"Unauthorized Modbus register polling on decoy PLC ({decoy_hostname}) from {src_ip or 'unknown IP'}."
            outcome = Outcome.success
            severity = Severity.high
            mitre_technique = "T0814"
        else:
            interaction_type = "modbus_discovery"
            title = "Industrial Device Discovery on Decoy PLC"
            description = f"OT device discovery probe targeting decoy PLC ({decoy_hostname})."
            outcome = Outcome.success
            severity = Severity.medium
            mitre_technique = "T0846"

    activity_id = f"decoy_act_{event.event_id.replace('evt_', '')}"

    return DeceptionActivity(
        activity_id=activity_id,
        event_id=event.event_id,
        incident_id=incident_id,
        signal_id=signal_id,
        decoy_asset=decoy_asset,
        decoy_hostname=decoy_hostname,
        decoy_type=decoy_type,
        sensor_tool=source_tool,
        network_zone=network_zone,
        src_ip=src_ip,
        attacker_role=attacker_role,
        interaction_type=interaction_type,
        title=title,
        description=description,
        ts=event.ts,
        outcome=outcome,
        severity=severity,
        provenance="observed",
        mitre_technique=mitre_technique,
        raw_evidence_ref=event.raw_ref or {},
        metadata=metadata,
    )


def generate_deception_interpretations(activities: list[DeceptionActivity]) -> list[str]:
    """Generate evidence-grounded interpretations separating observed facts from inferred intent."""
    if not activities:
        return ["No deceptive interactions recorded in this environment."]

    interpretations: list[str] = []

    ssh_logins = [a for a in activities if a.interaction_type == "ssh_login_success"]
    ssh_cmds = [a for a in activities if a.interaction_type == "ssh_command_input"]
    mysql_probes = [a for a in activities if a.interaction_type == "mysql_login_attempt"]
    port_probes = [
        a for a in activities if a.interaction_type in ("port_probe", "service_discovery")
    ]
    ot_probes = [
        a for a in activities if a.interaction_type in ("modbus_read", "modbus_write_attempt")
    ]

    if ssh_logins:
        interpretations.append(
            f"OBSERVED: {len(ssh_logins)} successful authentication(s) captured on Cowrie SSH decoy (backup-srv-02). "
            "INFERRED: Attacker obtained and tested bait credentials (e.g. svc_dbadmin honeytoken)."
        )

    if ssh_cmds:
        interpretations.append(
            f"OBSERVED: {len(ssh_cmds)} command(s) executed inside honeypot sandbox environment. "
            "INFERRED: Attacker attempted host reconnaissance to discover network topology and filesystem contents."
        )

    if mysql_probes or port_probes:
        count = len(mysql_probes) + len(port_probes)
        interpretations.append(
            f"OBSERVED: {count} service discovery probe(s) against OpenCanary database decoy (db-prod-02). "
            "INFERRED: Automated or manual lateral service enumeration across DMZ/IT subnet boundary."
        )

    if ot_probes:
        interpretations.append(
            f"OBSERVED: {len(ot_probes)} industrial protocol command(s) delivered to decoy PLC (10.10.3.60). "
            "INFERRED: Attacker traversed into the OT zone and attempted ICS controller discovery."
        )

    return interpretations
