# syntax=docker/dockerfile:1
ARG DEBIAN_TAG=bookworm-slim
ARG WAZUH_VERSION=4.14.10
ARG PYMODBUS_VERSION=3.6.8

# ==========================================
# Base Host Stage (jump-host, file-srv, db-srv, eng-ws, benign)
# ==========================================
FROM debian:${DEBIAN_TAG} AS base

ARG WAZUH_VERSION
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    procps \
    curl \
    gnupg \
    ca-certificates \
    net-tools \
    iputils-ping \
    lsb-release \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh Agent
RUN curl -sSL "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_amd64.deb" -o /tmp/wazuh-agent.deb \
    && dpkg -i /tmp/wazuh-agent.deb \
    && rm -f /tmp/wazuh-agent.deb

# Create users: alice (sysadmin, sudo), bob (dba), eng1 (engineer), svc_backup (service account, weak password)
RUN useradd -m -s /bin/bash alice && usermod -aG sudo alice && echo "alice ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/alice \
    && useradd -m -s /bin/bash bob \
    && useradd -m -s /bin/bash eng1 \
    && useradd -m -s /bin/bash svc_backup \
    && echo "svc_backup:Backup2024!" | chpasswd

# Setup key-based login for alice, bob, eng1
COPY ssh_keys/id_ed25519.pub /tmp/id_ed25519.pub
RUN for u in alice bob eng1; do \
      mkdir -p /home/$u/.ssh && \
      cp /tmp/id_ed25519.pub /home/$u/.ssh/authorized_keys && \
      chown -R $u:$u /home/$u/.ssh && \
      chmod 700 /home/$u/.ssh && \
      chmod 600 /home/$u/.ssh/authorized_keys; \
    done && rm -f /tmp/id_ed25519.pub

# Audit logging directory and hooks
RUN mkdir -p /var/log/sentinelx && chmod 1777 /var/log/sentinelx && touch /var/log/sentinelx/cmd.jsonl && chmod 0666 /var/log/sentinelx/cmd.jsonl
COPY audit-shell.sh /usr/local/bin/audit-shell
COPY prompt-command.sh /etc/profile.d/sentinelx-audit.sh
RUN chmod +x /usr/local/bin/audit-shell

# SSH configuration
RUN mkdir -p /run/sshd && \
    sed -i 's/#LogLevel INFO/LogLevel INFO/' /etc/ssh/sshd_config && \
    echo "ForceCommand /usr/local/bin/audit-shell" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config && \
    echo "Match User svc_backup" >> /etc/ssh/sshd_config && \
    echo "    PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Wazuh agent configuration
COPY ossec-agent.conf /var/ossec/etc/ossec.conf

# Internal DNS responder for lab IT zone
COPY dns_responder.py /usr/local/bin/dns_responder.py
RUN chmod +x /usr/local/bin/dns_responder.py

# Entrypoint
COPY entrypoint-common.sh /usr/local/bin/entrypoint-common.sh
RUN chmod +x /usr/local/bin/entrypoint-common.sh

ENTRYPOINT ["/usr/local/bin/entrypoint-common.sh"]

# ==========================================
# Jump Host Stage
# ==========================================
FROM base AS jump-host

RUN apt-get update && apt-get install -y --no-install-recommends \
    mariadb-client \
    sshpass \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Add honey SSH config and bash history for alice pointing to backup-srv-02
RUN mkdir -p /home/alice/.ssh && \
    printf 'Host backup-srv-02\n    HostName 10.10.2.20\n    User svc_dbadmin\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n' > /home/alice/.ssh/config && \
    printf 'ssh backup-srv-02\n# Note: backup-srv-02 password is the standard winter rotation: Winter2026!\n' > /home/alice/.bash_history && \
    chown -R alice:alice /home/alice/.ssh /home/alice/.bash_history && \
    chmod 600 /home/alice/.ssh/config /home/alice/.bash_history

# ==========================================
# File Server Stage
# ==========================================
FROM base AS file-srv

# Setup /srv/share with honey credential file
RUN mkdir -p /srv/share/backup && \
    printf 'host=db-prod-02 user=svc_dbadmin pass=Winter2026!\n' > /srv/share/backup/.db_creds && \
    chmod -R 777 /srv/share && \
    chmod 666 /srv/share/backup/.db_creds

# ==========================================
# Database Server Stage
# ==========================================
FROM base AS db-srv

RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql \
    postgresql-contrib \
    && rm -rf /var/lib/apt/lists/*

# Configure PostgreSQL for remote access within lab network
RUN PG_CONF=$(ls -d /etc/postgresql/*/main/postgresql.conf | head -n 1) && \
    PG_HBA=$(ls -d /etc/postgresql/*/main/pg_hba.conf | head -n 1) && \
    echo "listen_addresses = '*'" >> "$PG_CONF" && \
    echo "host all all 0.0.0.0/0 trust" >> "$PG_HBA" && \
    echo "host all all 10.10.0.0/16 trust" >> "$PG_HBA"

COPY entrypoint-dbsrv.sh /usr/local/bin/entrypoint-dbsrv.sh
RUN chmod +x /usr/local/bin/entrypoint-dbsrv.sh

ENTRYPOINT ["/usr/local/bin/entrypoint-dbsrv.sh"]

# ==========================================
# Engineering Workstation Stage
# ==========================================
FROM base AS eng-ws

ARG PYMODBUS_VERSION
RUN pip install --no-cache-dir --break-system-packages pymodbus==${PYMODBUS_VERSION}

COPY read_plc.py /usr/local/bin/read_plc.py
COPY write_plc.py /usr/local/bin/write_plc.py
RUN chmod +x /usr/local/bin/read_plc.py /usr/local/bin/write_plc.py

# ==========================================
# Benign Host Stage
# ==========================================
FROM base AS benign

ARG PYMODBUS_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    openssh-client \
    && rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir --break-system-packages pymodbus==${PYMODBUS_VERSION}

# Setup SSH private keys for alice, bob, eng1
COPY ssh_keys/id_ed25519 /tmp/id_ed25519
RUN for u in alice bob eng1; do \
      mkdir -p /home/$u/.ssh && \
      cp /tmp/id_ed25519 /home/$u/.ssh/id_ed25519 && \
      printf 'Host *\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n' > /home/$u/.ssh/config && \
      chown -R $u:$u /home/$u/.ssh && \
      chmod 700 /home/$u/.ssh && \
      chmod 600 /home/$u/.ssh/id_ed25519 /home/$u/.ssh/config; \
    done && rm -f /tmp/id_ed25519

COPY benign_loop.py /usr/local/bin/benign_loop.py
RUN chmod +x /usr/local/bin/benign_loop.py

CMD ["python3", "/usr/local/bin/benign_loop.py"]

# ==========================================
# Attacker Stage
# ==========================================
FROM debian:${DEBIAN_TAG} AS attacker

ARG PYMODBUS_VERSION
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    openssh-client \
    curl \
    netcat-openbsd \
    postgresql-client \
    python3 \
    python3-pip \
    sshpass \
    iputils-ping \
    procps \
    && rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir --break-system-packages pymodbus==${PYMODBUS_VERSION}

# Allowed targets file and guidelines
RUN mkdir -p /opt/attack
RUN echo "10.10.0.0/16" > /opt/attack/ALLOWED_TARGETS && \
    printf '# SentinelX Attacker Node\n\nAll attack activities MUST strictly target subnets defined in /opt/attack/ALLOWED_TARGETS.\nDirect connections to OT (10.10.3.0/24) or DMZ (10.10.2.0/24) are blocked by network segmentation.\n' > /opt/attack/README.md

WORKDIR /opt/attack
CMD ["tail", "-f", "/dev/null"]
