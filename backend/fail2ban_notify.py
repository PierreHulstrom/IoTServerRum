"""Kaldes af værtens fail2ban ved SSH-ban: logger i MariaDB (Dashboard) og sender Azure Email."""

from __future__ import annotations

import json
import re
import sys

from db import get_conn
from emailer import send_email


def _clean(val: str, max_len: int = 80) -> str:
    return re.sub(r"[\r\n\t]+", " ", str(val or "")).strip()[:max_len]


def _write_system_log(message: str, details: dict) -> tuple[bool, str]:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO system_logs (source, level, message, details) VALUES (%s, %s, %s, %s)",
                    ("fail2ban", "ERROR", message, json.dumps(details)),
                )
        return True, "OK"
    except Exception as exc:
        return False, str(exc)


def main() -> int:
    ip = _clean(sys.argv[1] if len(sys.argv) > 1 else "ukendt", 64)
    jail = _clean(sys.argv[2] if len(sys.argv) > 2 else "sshd", 32)
    failures = _clean(sys.argv[3] if len(sys.argv) > 3 else "flere", 16)
    bantime = _clean(sys.argv[4] if len(sys.argv) > 4 else "3600", 16)

    msg = f"fail2ban udelukkede SSH-IP {ip} ({jail}) efter {failures} fejlforsøg (ban: {bantime}s)"
    details = {"ip": ip, "jail": jail, "failures": failures, "bantime": bantime}
    db_ok, db_info = _write_system_log(msg, details)

    body = (
        f"En angriber er netop blevet automatisk blokeret af fail2ban på Azure-serveren (lamp-vm).\n\n"
        f"Blokeret IP: {ip}\n"
        f"Tjeneste (jail): {jail}\n"
        f"Fejlede login-forsøg: {failures}\n"
        f"Udelukkelsestid: {bantime} sekunder\n\n"
        f"Hændelsen er samtidig logget i Operations Center Dashboardet under Systemlog."
    )
    mail_ok, mail_info = send_email(
        subject=f"SSH brute-force blokeret: {ip}",
        body=body,
        severity="CRITICAL",
    )
    print(
        f"[fail2ban_notify] DB={'OK' if db_ok else 'FEJL (' + db_info + ')'} | "
        f"Email={'OK' if mail_ok else 'FEJL'} ({mail_info})",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
