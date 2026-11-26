"""Lightweight Azure Communication Services (ACS) Email sender (REST API 2023-03-31).

Uses pure Python stdlib (HMAC-SHA256 signing + HTTPSConnection) with zero external
SDK dependencies so both the FastAPI/MQTT backend and host fail2ban hooks can send
security alerts to school Outlook accounts reliably over HTTPS.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import html
import http.client
import json
import os
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from typing import Iterable, Optional, Tuple

ACS_API_PATH = "/emails:send?api-version=2023-03-31"
DASHBOARD_URL = "https://serverrum-iot-2026.swedencentral.cloudapp.azure.com"

# Thread-safe per-alert cooldown tracker to prevent inbox spam
_COOLDOWN_LOCK = threading.Lock()
_LAST_SENT: dict[str, float] = {}


def _load_dotenv_fallback(env_path: str = "/opt/serverroom-iot/.env") -> None:
    """Load ACS settings from .env when invoked directly from the host CLI."""
    if os.getenv("ACS_CONNECTION_STRING") or not os.path.isfile(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key in ("ACS_CONNECTION_STRING", "ACS_SENDER_ADDRESS", "ALERT_EMAIL_TO") and not os.getenv(key):
                    os.environ[key] = val
    except OSError:
        return


def parse_connection_string(conn_str: str) -> Tuple[str, str]:
    """Extract and validate (https endpoint, base64 access_key) from an ACS connection string."""
    endpoint = ""
    access_key = ""
    for part in conn_str.strip().strip('"').strip("'").split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k_low = k.strip().lower()
        v = v.strip()
        if k_low == "endpoint":
            endpoint = v.rstrip("/")
        elif k_low == "accesskey":
            access_key = v
    if not endpoint or not access_key:
        raise ValueError("ACS_CONNECTION_STRING mangler endpoint eller accesskey")
    # Enforce HTTPS-only endpoint to prevent insecure plaintext calls
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("ACS endpoint skal være en gyldig https://-adresse")
    return endpoint, access_key


def get_recipients(override: Optional[Iterable[str]] = None) -> list[str]:
    """Parse comma-separated recipient email addresses from ALERT_EMAIL_TO."""
    raw_list = override if override is not None else os.getenv("ALERT_EMAIL_TO", "").split(",")
    return [addr.strip() for addr in raw_list if addr and "@" in addr.strip()]


def is_configured() -> bool:
    """Return True if ACS connection string, sender address, and recipients are all set."""
    return bool(
        os.getenv("ACS_CONNECTION_STRING", "").strip()
        and os.getenv("ACS_SENDER_ADDRESS", "").strip()
        and get_recipients()
    )


def _build_html(subject: str, body: str, severity: str) -> str:
    """Render an XSS-escaped dark NOC HTML email body with severity banner."""
    colors = {
        "CRITICAL": "#dc2626",
        "ERROR": "#dc2626",
        "WARNING": "#d97706",
        "INFO": "#2563eb",
    }
    badge_color = colors.get(severity.upper(), "#2563eb")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Escape all dynamic values so untrusted IPs/usernames cannot inject HTML
    safe_subject = html.escape(subject)
    safe_body = html.escape(body).replace("\n", "<br>")
    safe_sev = html.escape(severity.upper())
    return (
        "<!doctype html><html><body style='font-family:Segoe UI,Arial,sans-serif;"
        "background:#0f172a;color:#e2e8f0;padding:24px;'>"
        "<div style='max-width:600px;margin:0 auto;background:#1e293b;"
        "border:1px solid #334155;border-radius:8px;overflow:hidden;'>"
        f"<div style='background:{badge_color};color:#ffffff;padding:12px 20px;"
        f"font-weight:700;letter-spacing:0.5px;'>SERVERRUM IoT // {safe_sev}</div>"
        "<div style='padding:20px;'>"
        f"<h2 style='margin:0 0 12px 0;color:#f8fafc;font-size:18px;'>{safe_subject}</h2>"
        f"<p style='margin:0 0 16px 0;line-height:1.5;color:#cbd5e1;'>{safe_body}</p>"
        f"<p style='margin:0 0 16px 0;font-size:12px;color:#94a3b8;'>Tidspunkt: {now_str}</p>"
        f"<a href='{DASHBOARD_URL}' style='display:inline-block;background:#2563eb;"
        "color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:6px;"
        "font-weight:600;'>Åbn Operations Center Dashboard</a>"
        "</div></div></body></html>"
    )


def send_email(
    subject: str,
    body: str,
    severity: str = "WARNING",
    recipients: Optional[Iterable[str]] = None,
    timeout: int = 15,
) -> Tuple[bool, str]:
    """Sign and POST an email payload to Azure Communication Services over HTTPS."""
    conn_str = os.getenv("ACS_CONNECTION_STRING", "").strip()
    sender = os.getenv("ACS_SENDER_ADDRESS", "").strip()
    to_list = get_recipients(recipients)

    if not conn_str or not sender or not to_list:
        return False, "Email ikke konfigureret (tjek ACS_CONNECTION_STRING, ACS_SENDER_ADDRESS, ALERT_EMAIL_TO)"

    try:
        endpoint, access_key = parse_connection_string(conn_str)
        host = urllib.parse.urlparse(endpoint).netloc

        payload = {
            "senderAddress": sender,
            "content": {
                "subject": f"[Serverrum IoT - {severity.upper()}] {subject}",
                "plainText": f"{body}\n\nDashboard: {DASHBOARD_URL}",
                "html": _build_html(subject, body, severity),
            },
            "recipients": {
                "to": [{"address": addr} for addr in to_list],
            },
        }
        body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        # Compute required Azure ACS HMAC-SHA256 request signature headers
        request_date = email.utils.formatdate(usegmt=True)
        content_hash = base64.b64encode(hashlib.sha256(body_bytes).digest()).decode("ascii")
        string_to_sign = f"POST\n{ACS_API_PATH}\n{request_date};{host};{content_hash}"
        decoded_key = base64.b64decode(access_key)
        signature = base64.b64encode(
            hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode("ascii")

        headers = {
            "Content-Type": "application/json",
            "Host": host,
            "x-ms-date": request_date,
            "x-ms-content-sha256": content_hash,
            "Authorization": f"HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature={signature}",
        }

        conn = http.client.HTTPSConnection(host, timeout=timeout)
        try:
            conn.request("POST", ACS_API_PATH, body=body_bytes, headers=headers)
            resp = conn.getresponse()
            resp_text = resp.read().decode("utf-8", errors="replace")
            if 200 <= resp.status < 300:
                return True, f"HTTP {resp.status} til {len(to_list)} modtager(e)"
            return False, f"HTTP {resp.status}: {resp_text[:300]}"
        finally:
            conn.close()
    except Exception as exc:
        return False, f"Undtagelse ved mailafsendelse: {exc}"


def send_alert_async(
    alert_key: str,
    subject: str,
    body: str,
    severity: str = "WARNING",
    cooldown_sec: int = 300,
) -> bool:
    """Send an email in a background daemon thread with per-key cooldown protection."""
    if not is_configured():
        return False
    now = time.monotonic()
    with _COOLDOWN_LOCK:
        last = _LAST_SENT.get(alert_key, 0.0)
        if last and (now - last) < cooldown_sec:
            return False
        _LAST_SENT[alert_key] = now

    def _worker() -> None:
        ok, info = send_email(subject=subject, body=body, severity=severity)
        status = "OK" if ok else "FEJL"
        print(f"[EMAILER] {status} ({alert_key}): {info}", flush=True)

    threading.Thread(target=_worker, daemon=True).start()
    return True


if __name__ == "__main__":
    # Manual CLI test: python3 emailer.py --test
    _load_dotenv_fallback()
    if "--test" in sys.argv:
        ok, detail = send_email(
            subject="Test-notifikation fra Azure Serverrum IoT",
            body="Tillykke! Azure Communication Services Email er nu forbundet til jeres Serverrum IoT-system og kan sende sikkerhedsalarmer og fail2ban-notifikationer direkte til jeres skole-Outlook.",
            severity="INFO",
        )
        print("RESULTAT:", "OK -" if ok else "FEJL -", detail)
        sys.exit(0 if ok else 1)
