# /etc/profile.d/sentinelx-audit.sh
# Logs interactive shell commands to /var/log/sentinelx/cmd.jsonl

__sentinelx_audit_log() {
  local LAST_CMD
  LAST_CMD=$(HISTTIMEFORMAT= history 1 2>/dev/null | sed -e 's/^[ ]*[0-9]*[ ]*//')

  if [ -n "$LAST_CMD" ] && [ "${LAST_CMD}" != "${__LAST_AUDITED_CMD:-}" ]; then
    __LAST_AUDITED_CMD="$LAST_CMD"
    local TS HOST USER_NAME SRC_IP SESSION_ID CWD CMD_JSON
    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    HOST=$(hostname 2>/dev/null || echo "unknown")
    USER_NAME=$(whoami 2>/dev/null || echo "${USER:-unknown}")
    SRC_IP="${SSH_CLIENT%% *}"
    SRC_IP="${SRC_IP:-127.0.0.1}"
    SESSION_ID="${SSH_TTY:-$$}"
    CWD=$(pwd 2>/dev/null || echo "/")

    CMD_JSON=$(python3 -c 'import json, sys; print(json.dumps(sys.argv[1]), end="")' "$LAST_CMD" 2>/dev/null || printf '"%s"' "$LAST_CMD")

    printf '{"ts":"%s","host":"%s","user":"%s","src_ip":"%s","session":"%s","tty":true,"cwd":"%s","cmd":%s,"mode":"interactive"}\n' \
      "$TS" "$HOST" "$USER_NAME" "$SRC_IP" "$SESSION_ID" "$CWD" "$CMD_JSON" \
      >> /var/log/sentinelx/cmd.jsonl 2>/dev/null || true
  fi
}

if [[ $- =~ i ]]; then
  if [[ -z "${PROMPT_COMMAND:-}" ]]; then
    PROMPT_COMMAND="__sentinelx_audit_log"
  else
    PROMPT_COMMAND="__sentinelx_audit_log; $PROMPT_COMMAND"
  fi
fi

