"""Evidence packet builder for untrusted event logs with secret redaction and control char stripping."""

import re

from sentinelx.schemas.event import Event
from sentinelx.schemas.incident import Incident

# Regex for control character stripping (non-printable ASCII controls, preserving \n and \t)
RE_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Secret redaction patterns (e.g. sshpass -p <pass>, password=..., secret=...)
RE_SSHPASS = re.compile(r"(sshpass\s+-p\s*)([^\s\"']+)", re.IGNORECASE)
RE_SSHPASS_ATTACHED = re.compile(r"(sshpass\s+-p)([^\s\"']+)", re.IGNORECASE)
RE_PASSWORD_ARG = re.compile(
    r"(--?password|--?passwd|--?secret)(?:=|\s+)([^\s\"']+)", re.IGNORECASE
)
RE_PASSWORD_KEYVAL = re.compile(r"\b(password|passwd|secret)\s*[:=]\s*([^\s,;\"']+)", re.IGNORECASE)


def strip_control_characters(text: str) -> str:
    """Remove non-printable control characters, preserving basic whitespace."""
    if not text:
        return ""
    return RE_CONTROL_CHARS.sub("", text)


def redact_secrets(text: str) -> str:
    """Redact passwords and secrets commonly observed in command-line strings and payloads."""
    if not text:
        return ""

    # Redact sshpass -p <secret>
    redacted = RE_SSHPASS.sub(r"\1[REDACTED]", text)
    redacted = RE_SSHPASS_ATTACHED.sub(r"\1[REDACTED]", redacted)

    # Redact --password <secret> or --password=<secret>
    redacted = RE_PASSWORD_ARG.sub(r"\1 [REDACTED]", redacted)

    # Redact password: ... or password=...
    redacted = RE_PASSWORD_KEYVAL.sub(r"\1=[REDACTED]", redacted)

    return redacted


def sanitize_cmdline(cmdline: str | None, max_len: int = 200) -> str:
    """Strip control characters, redact secrets, and truncate command line string."""
    if not cmdline:
        return "--"
    cleaned = strip_control_characters(cmdline)
    redacted = redact_secrets(cleaned)
    if len(redacted) > max_len:
        return redacted[:max_len] + "..."
    return redacted


def build_evidence_packet(
    incident: Incident,
    events: list[Event],
    max_cmdline_len: int = 200,
) -> str:
    """Build a bounded, sanitized, and labeled UNTRUSTED DATA evidence packet from cited events.

    Only events present in incident.event_ids are included.
    """
    cited_ids = set(incident.event_ids)
    cited_events = [e for e in events if e.event_id in cited_ids]

    # Sort events by timestamp
    cited_events.sort(key=lambda ev: ev.ts)

    lines = [
        "=== BEGIN UNTRUSTED DATA ===",
        f"# Incident ID: {incident.incident_id} (Score: {incident.score:.4f}, Severity: {incident.severity.value})",
        f"# Kill-Chain Stages: {', '.join(incident.kill_chain_stages)}",
        f"# Total Cited Events: {len(cited_events)}",
        "",
    ]

    for ev in cited_events:
        # Extract process command line or raw details
        cmd = None
        if ev.process:
            cmd = ev.process
        if isinstance(ev.raw, dict):
            if "cmd" in ev.raw:
                cmd = str(ev.raw["cmd"])
            elif "cmdline" in ev.raw:
                cmd = str(ev.raw["cmdline"])
            elif "full_log" in ev.raw and isinstance(ev.raw["full_log"], str):
                cmd = ev.raw["full_log"]

        sanitized_cmd = sanitize_cmdline(cmd, max_len=max_cmdline_len)

        # OT Fields if present
        ot_details = []
        if isinstance(ev.raw, dict):
            for k in ("unit_id", "func_code", "reg_addr", "val", "register", "action"):
                if k in ev.raw and ev.raw[k] is not None:
                    ot_details.append(f"{k}={ev.raw[k]}")
        ot_str = f" | OT: {', '.join(ot_details)}" if ot_details else ""

        sanitized_action = redact_secrets(strip_control_characters(ev.action))

        line = (
            f"Event [{ev.event_id}] | ts: {ev.ts.isoformat()} | host: {ev.host or '--'} | "
            f"user: {ev.user or '--'} | src: {ev.src_ip or '--'} | dst: {ev.dst_ip or '--'} | "
            f"action: {sanitized_action} | cmd: {sanitized_cmd}{ot_str}"
        )
        lines.append(line)

    lines.append("=== END UNTRUSTED DATA ===")
    return "\n".join(lines)
