import json
import os
import socket
import ssl
import unittest
import urllib.error
import urllib.request

BASE_LOCAL = "http://127.0.0.1:8000"
PUBLIC_HOST = "serverrum-iot-2026.swedencentral.cloudapp.azure.com"
PUBLIC_HTTPS = f"https://{PUBLIC_HOST}"
USER = os.getenv("DASHBOARD_USER", "admin")
PASS = os.getenv("DASHBOARD_PASS", "")


def req(url, method="GET", body=None, headers=None, timeout=5):
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="ignore")


class TestLiveAPIAndSecurity(unittest.TestCase):
    def test_01_health_endpoint_db_and_mqtt_online(self):
        code, _, body = req(f"{BASE_LOCAL}/api/health")
        data = json.loads(body)
        self.assertEqual(code, 200)
        self.assertTrue(data["db"])
        self.assertTrue(data["mqtt"])

    def test_02_overview_blocked_without_login(self):
        code, _, _ = req(f"{BASE_LOCAL}/api/overview")
        self.assertEqual(code, 401)

    def test_03_remote_command_blocked_without_login(self):
        code, _, _ = req(
            f"{BASE_LOCAL}/api/command",
            method="POST",
            body={"device_id": "pi1", "command": "unlock_door"},
        )
        self.assertEqual(code, 401)

    def test_04_wrong_password_and_sqli_rejected(self):
        c1, _, _ = req(f"{BASE_LOCAL}/api/login", method="POST", body={"username": USER, "password": "forkert"})
        c2, _, _ = req(f"{BASE_LOCAL}/api/login", method="POST", body={"username": "' OR '1'='1", "password": "' OR '1'='1"})
        self.assertEqual(c1, 401)
        self.assertEqual(c2, 401)

    def test_05_valid_login_and_authenticated_overview(self):
        code, _, body = req(f"{BASE_LOCAL}/api/login", method="POST", body={"username": USER, "password": PASS})
        self.assertEqual(code, 200)
        token = json.loads(body)["token"]
        code2, _, body2 = req(f"{BASE_LOCAL}/api/overview", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(code2, 200)
        data = json.loads(body2)
        for key in ("health", "readings", "devices", "anomalies", "cards", "access_logs", "system_logs", "commands"):
            self.assertIn(key, data)

    def test_06_public_https_tls_and_security_headers(self):
        code, headers, _ = req(f"{PUBLIC_HTTPS}/api/health", timeout=8)
        lower_h = {k.lower(): v for k, v in headers.items()}
        self.assertEqual(code, 200)
        self.assertIn("max-age=", lower_h.get("strict-transport-security", ""))
        self.assertEqual(lower_h.get("x-content-type-options"), "nosniff")
        self.assertEqual(lower_h.get("x-frame-options"), "SAMEORIGIN")
        self.assertNotIn("server", lower_h)

    def test_07_unencrypted_port_80_is_closed(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            result = s.connect_ex((PUBLIC_HOST, 80))
            self.assertNotEqual(result, 0, "Port 80 bør være lukket!")
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
