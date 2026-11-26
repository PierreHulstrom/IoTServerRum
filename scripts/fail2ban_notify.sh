#!/usr/bin/env bash
# Host-side fail2ban action wrapper: forwards SSH ban details into the backend container
# to log in MariaDB (visible in Dashboard) and send a CRITICAL Azure Email alert.
set -u

IP="${1:-ukendt}"
JAIL="${2:-sshd}"
FAILURES="${3:-flere}"
BANTIME="${4:-3600}"

# Always exit 0 and log output to syslog so a container restart never blocks fail2ban's firewall ban
/usr/bin/docker exec serverroom-backend python3 /app/fail2ban_notify.py "$IP" "$JAIL" "$FAILURES" "$BANTIME" \
  2>&1 | /usr/bin/logger -t serverroom-fail2ban || true
exit 0
