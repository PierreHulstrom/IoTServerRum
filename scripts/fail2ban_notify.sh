#!/usr/bin/env bash
set -u
IP="${1:-ukendt}"
JAIL="${2:-sshd}"
FAILURES="${3:-flere}"
BANTIME="${4:-3600}"

/usr/bin/docker exec serverroom-backend python3 /app/fail2ban_notify.py "$IP" "$JAIL" "$FAILURES" "$BANTIME" \
  2>&1 | /usr/bin/logger -t serverroom-fail2ban || true
exit 0
