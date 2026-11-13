"""Decoy SSH Private Keys and SSH Client Configuration deception lure generators."""

from typing import Final

# Synthetic OpenSSH Private Key (Non-functional against production systems, flagged as honeytoken)
SYNTHETIC_DECOY_PRIVATE_KEY: Final[str] = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCSxJp1zV0L78fMhA+wM0z2A/0Y6UjT2jQJ1yF6uR3s8AAAAJgA6GzVAO
hs1QAAAAtzc2gtZWQyNTUxOQAAACCSxJp1zV0L78fMhA+wM0z2A/0Y6UjT2jQJ1yF6uR
3s8AAAEEA0t9E7H4mY/857e4uR+uS3s4N9lK2m8U9p8L9m8N2QJLLEmnXNXQvvx8yED7
AzTPYD/RjpSNPaNAnXIXq5HezwAAABlzdmNfZGJhZG1pbkBzZW50aW5lbHgtZGVjb3kB
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"""

SYNTHETIC_DECOY_PUBLIC_KEY: Final[str] = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJLEmnXNXQvvx8yED7AzTPYD/RjpSNPaNAnXIXq5Hezw "
    "svc_dbadmin@sentinelx-decoy\n"
)

DECOY_SSH_CONFIG: Final[str] = """# Managed infrastructure SSH config
Host backup-srv-02
    HostName 10.10.2.20
    User svc_dbadmin
    IdentityFile ~/.ssh/id_ed25519_backup
    Port 22
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host db-prod-02
    HostName 10.10.2.30
    User svc_dbadmin
    Port 22
    StrictHostKeyChecking no
"""


def get_decoy_ssh_key_content() -> str:
    """Return synthetic OpenSSH private key content."""
    return SYNTHETIC_DECOY_PRIVATE_KEY


def get_decoy_ssh_config_content() -> str:
    """Return synthetic SSH config stanza referencing decoy destination."""
    return DECOY_SSH_CONFIG

