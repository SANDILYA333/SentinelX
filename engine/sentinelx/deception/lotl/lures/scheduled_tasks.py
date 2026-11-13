"""Scheduled Task and Cron Deception lure generators."""

from typing import Final

DECOY_CRON_FILE: Final[str] = """# /etc/cron.d/decoy_backup_sync
# SentinelX Decoy Maintenance Task
# This task executes an inert placeholder script to monitor tampering and privilege persistence attempts.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Routine backup integrity synchronization
0 * * * * svc_backup /usr/local/bin/sync_backup_telemetry.sh >/dev/null 2>&1
"""

INERT_PLACEHOLDER_SCRIPT: Final[str] = """#!/bin/sh
# SentinelX inert deception placeholder
# This script does not execute active logic or privileged operations.
# File modification or execution triggers security alert RULE-LOTL-006.
exit 0
"""


def get_decoy_cron_content() -> str:
    """Return synthetic decoy cron table definition."""
    return DECOY_CRON_FILE


def get_inert_script_content() -> str:
    """Return inert harmless placeholder script content."""
    return INERT_PLACEHOLDER_SCRIPT

