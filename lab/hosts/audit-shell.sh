#!/bin/bash
# /usr/local/bin/audit-shell
# Logs SSH executed and interactive commands to /var/log/sentinelx/cmd.jsonl
set -u

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOST=$(hostname 2>/dev/null || echo "unknown")
USER_NAME=$(whoami 2>/dev/null || echo "${USER:-unknown}")
SRC_IP="${SSH_CLIENT%% *}"
SRC_IP="${SRC_IP:-127.0.0.1}"
SESSION_ID="${SSH_TTY:-$$}"
CWD=$(pwd 2>/dev/null || echo "/")
IS_TTY=false
if [ -t 0 ]; then
  IS_TTY=true
fi

mkdir -p /var/log/sentinelx 2>/dev/null || true

json_escape() {
  python3 -c 'import json, sys; print(json.dumps(sys.stdin.read()), end="")' 2>/dev/null || printf '"%s"' "$1"
}

if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  # Non-interactive command mode (e.g., ssh host "cmd")
  CMD_JSON=$(printf '%s' "$SSH_ORIGINAL_COMMAND" | json_escape "$SSH_ORIGINAL_COMMAND")
  printf '{"ts":"%s","host":"%s","user":"%s","src_ip":"%s","session":"%s","tty":%s,"cwd":"%s","cmd":%s,"mode":"exec"}\n' \
    "$TS" "$HOST" "$USER_NAME" "$SRC_IP" "$SESSION_ID" "$IS_TTY" "$CWD" "$CMD_JSON" \
    >> /var/log/sentinelx/cmd.jsonl 2>/dev/null || true
  exec /bin/bash -c "$SSH_ORIGINAL_COMMAND"
else
  # Interactive login shell mode
  printf '{"ts":"%s","host":"%s","user":"%s","src_ip":"%s","session":"%s","tty":%s,"cwd":"%s","cmd":"bash","mode":"interactive"}\n' \
    "$TS" "$HOST" "$USER_NAME" "$SRC_IP" "$SESSION_ID" "$IS_TTY" "$CWD" \
    >> /var/log/sentinelx/cmd.jsonl 2>/dev/null || true
  exec /bin/bash --login
fi

