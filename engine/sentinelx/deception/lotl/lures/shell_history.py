"""Linux Shell History (.bash_history / .zsh_history) deception lure generators."""

from typing import Final

ENG_WS_BASH_HISTORY: Final[str] = """# Administrative Session - svc_backup
uptime
df -h /srv/backup
cat /opt/scada/config/controllers.conf
ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519_backup svc_dbadmin@10.10.2.20 "whoami; uptime"
rsync -avz -e "ssh -i ~/.ssh/id_ed25519_backup" /srv/backup/ svc_dbadmin@10.10.2.20:/srv/archives/
systemctl status sentinelx-backup.service
ping -c 3 10.10.2.20
cat /etc/profile.d/backup_env.sh
exit
"""

JUMP_HOST_BASH_HISTORY: Final[str] = """# Systems Administration - Maintenance
w
last -n 5
mariadb -h 10.10.2.30 -u svc_dbadmin -p"Winter2026!" -e "SHOW DATABASES;"
ansible-playbook -i /srv/ansible/hosts.yaml site.yml --check
curl -s http://10.10.2.30:80/status
ssh svc_dbadmin@10.10.2.20
cat /srv/ansible/hosts.yaml | grep -E "backup|database"
exit
"""


def get_shell_history_content(host: str) -> str:
    """Return synthetic shell history tailored to the target host."""
    if host == "eng-ws":
        return ENG_WS_BASH_HISTORY
    elif host == "jump-host":
        return JUMP_HOST_BASH_HISTORY
    return ENG_WS_BASH_HISTORY

