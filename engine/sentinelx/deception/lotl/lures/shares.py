"""Decoy SMB/NFS Share artifact generators."""

from typing import Final

CREDENTIALS_BAK_CONTENT: Final[str] = """# Emergency Database Recovery Credentials
# ARCHIVED: 2026-04-12
DB_HOST=10.10.2.30
DB_PORT=3306
DB_USER=svc_dbadmin
DB_PASSWORD=Winter2026!
BACKUP_TARGET=10.10.2.20
"""

SCADA_MAP_CONTENT: Final[str] = """# OT / SCADA Subnet Map & Asset Directory
# Subnet: 10.10.3.0/24
10.10.3.20  plc-sim-primary     Modbus Port 502  (Process Critical Water Tank Controller)
10.10.3.40  eng-ws-interface    Engineering Workstation Modbus Master
10.10.3.60  decoy-plc-secondary Modbus Port 502  (Auxiliary RTU Substation)
"""

RECOVERY_KEYS_CONTENT: Final[str] = """# Disaster Recovery Key Manifest
# Encrypted Archives - Contact IT SecOps before mounting
VAULT_ENDPOINT=https://10.10.2.20:8200
CANARY_RECOVERY_KEY=sx_vault_unseal_canary_39fa8b12e09c
"""


def get_share_file_content(filename: str) -> str:
    """Return synthetic decoy share file content."""
    clean = filename.lower()
    if "credentials" in clean:
        return CREDENTIALS_BAK_CONTENT
    elif "plc" in clean or "scada" in clean:
        return SCADA_MAP_CONTENT
    elif "recovery" in clean or "key" in clean:
        return RECOVERY_KEYS_CONTENT
    return CREDENTIALS_BAK_CONTENT

