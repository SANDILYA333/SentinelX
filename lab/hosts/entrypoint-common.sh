#!/bin/bash
# /usr/local/bin/entrypoint-common.sh
set -e

# Ensure logging paths exist with proper permissions
mkdir -p /var/log/sentinelx /run/sshd
touch /var/log/auth.log
chmod 0644 /var/log/auth.log
touch /var/log/sentinelx/cmd.jsonl
chmod 0666 /var/log/sentinelx/cmd.jsonl
chmod 1777 /var/log/sentinelx

# Start sshd with standard auth logging (INFO)
/usr/sbin/sshd -e -E /var/log/auth.log -o LogLevel=INFO
echo "SSHD service started."

# Start DNS responder if on file-srv
if [ "$(hostname)" = "file-srv" ] && [ -f /usr/local/bin/dns_responder.py ]; then
  python3 /usr/local/bin/dns_responder.py &
  echo "Internal DNS responder service started on port 53."
fi

# Enroll and start Wazuh Agent
MANAGER_IP="${WAZUH_MANAGER_IP:-10.10.9.2}"
PASS="${WAZUH_REGISTRATION_PASSWORD:-SentinelXRegistrationPass2026!}"
HOST_NAME="$(hostname)"

start_wazuh() {
  echo "Enrolling Wazuh agent ${HOST_NAME} with manager ${MANAGER_IP}..."
  local enrolled=0
  for i in $(seq 1 30); do
    if /var/ossec/bin/agent-auth -m "${MANAGER_IP}" -p 1515 -P "${PASS}" -A "${HOST_NAME}" >/dev/null 2>&1; then
      echo "Agent ${HOST_NAME} enrolled successfully."
      enrolled=1
      break
    fi
    sleep 2
  done

  if [ $enrolled -eq 1 ] || [ -s /var/ossec/etc/client.keys ]; then
    echo "Starting Wazuh agent control..."
    /var/ossec/bin/wazuh-control start || true
  else
    echo "Warning: Agent enrollment timed out, will retry in background."
    (
      for i in $(seq 1 30); do
        if /var/ossec/bin/agent-auth -m "${MANAGER_IP}" -p 1515 -P "${PASS}" -A "${HOST_NAME}" >/dev/null 2>&1; then
          /var/ossec/bin/wazuh-control start || true
          break
        fi
        sleep 3
      done
    ) &
  fi
}

start_wazuh &

cleanup() {
  echo "Received termination signal. Shutting down services..."
  /var/ossec/bin/wazuh-control stop || true
  pkill sshd || true
  exit 0
}

trap cleanup SIGTERM SIGINT

if [ "$#" -gt 0 ]; then
  exec "$@"
else
  while true; do
    sleep 5 &
    wait $!
  done
fi

