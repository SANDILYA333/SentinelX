"""Synthetic Infrastructure Configuration file deception lure generators."""

from typing import Final

ANSIBLE_INVENTORY_CONTENT: Final[str] = """# Ansible Inventory - IT / DMZ / OT Infrastructure
all:
  children:
    dmz_servers:
      hosts:
        backup-srv-02:
          ansible_host: 10.10.2.20
          ansible_port: 22
          ansible_user: svc_dbadmin
        db-prod-02:
          ansible_host: 10.10.2.30
          ansible_port: 3306
          ansible_user: svc_dbadmin
    ot_controllers:
      hosts:
        primary_plc:
          ansible_host: 10.10.3.20
          ansible_port: 502
        decoy_backup_plc:
          ansible_host: 10.10.3.60
          ansible_port: 502
"""

DOCKER_COMPOSE_BACKUP_CONTENT: Final[str] = """version: '3.8'

services:
  db_backup_service:
    image: internal-registry.local/backup-agent:v2.1
    environment:
      - DATABASE_HOST=10.10.2.30
      - DATABASE_PORT=3306
      - DATABASE_USER=svc_dbadmin
      - DATABASE_PASS=Winter2026!
      - SYNC_TARGET=10.10.2.20:22
    networks:
      - dmz_net

networks:
  dmz_net:
    external: true
"""

KUBE_CONFIG_CONTENT: Final[str] = """apiVersion: v1
clusters:
- cluster:
    server: https://10.10.2.25:6443
    insecure-skip-tls-verify: true
  name: staging-cluster
contexts:
- context:
    cluster: staging-cluster
    user: cluster-admin-canary
  name: staging
current-context: staging
kind: Config
preferences: {}
users:
- name: cluster-admin-canary
  user:
    token: sx_canary_kube_token_98fa721be4a012cd
"""

SCADA_CONFIG_CONTENT: Final[str] = """# SCADA Substation Engineering Unit Configuration
# Version 3.4.1 (Protected Engineering Zone)

[substation_alpha]
controller_name = plc-sim-water-treatment
ip_address = 10.10.3.20
modbus_port = 502
holding_registers = 1-10
criticality = HIGH_PRIORITY_PHYSICAL

[substation_telemetry_backup]
controller_name = decoy-plc-secondary
ip_address = 10.10.3.60
modbus_port = 502
holding_registers = 1-10
criticality = AUXILIARY_CANARY
notes = Secondary redundant RTU telemetry polling station
"""


def get_config_file_content(path_or_name: str) -> str:
    """Return synthetic configuration file content matching the artifact role."""
    clean = path_or_name.lower()
    if "ansible" in clean:
        return ANSIBLE_INVENTORY_CONTENT
    elif "compose" in clean:
        return DOCKER_COMPOSE_BACKUP_CONTENT
    elif "kube" in clean:
        return KUBE_CONFIG_CONTENT
    elif "scada" in clean or "controllers" in clean:
        return SCADA_CONFIG_CONTENT
    return ANSIBLE_INVENTORY_CONTENT

