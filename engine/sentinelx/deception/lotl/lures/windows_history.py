"""Windows PowerShell History deception lure definition.

Per Section 7.6 of Phase F specification:
"Design this as a platform-specific module. Only implement actual deployment
if the repository contains a Windows lab endpoint... Do not claim this
functionality is runtime-tested if no Windows endpoint exists."
"""

from typing import Final

POWERSHELL_HISTORY_CONTENT: Final[str] = """# PowerShell ConsoleHost History Decoy
Get-Service -Name W32Time
Test-NetConnection -ComputerName 10.10.2.20 -Port 22
ssh -i C:\\Users\\svc_backup\\.ssh\\id_rsa svc_dbadmin@10.10.2.20
Get-ADUser -Filter * -SearchBase "OU=ServiceAccounts,DC=corp,DC=local"
net use Z: \\\\10.10.1.20\\IT_Backups /user:svc_backup Backup2024!
"""


def get_powershell_history_content() -> str:
    """Return synthetic Windows PowerShell command history."""
    return POWERSHELL_HISTORY_CONTENT

