"""Unit test suite for auth/RBAC, SHA-256 access control, 4+1-layer AI engine, and MQTT resilience."""

import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import HTTPException
import main
import ai_engine
import mqtt_worker


def make_mock_conn(fetchall_val=None, fetchone_val=None):
    """Build a mock MariaDB context-manager connection returning preset query results."""
    cur = MagicMock()
    cur.fetchall.return_value = fetchall_val if fetchall_val is not None else []
    cur.fetchone.return_value = fetchone_val
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.cursor.return_value.__enter__.return_value = cur
    return conn, cur


class TestAuthAndTokens(unittest.TestCase):
    """Verify HMAC-SHA256 bearer token issuance, tampering rejection, and expiry checks."""

    def test_valid_token_accepted(self):
        token = main.create_token("pierre")
        user = main.verify_token(f"Bearer {token}")
        self.assertEqual(user, "pierre")

    def test_tampered_signature_rejected(self):
        token = main.create_token("admin")
        bad_token = token[:-4] + "0000"
        with self.assertRaises(HTTPException) as ctx:
            main.verify_token(f"Bearer {bad_token}")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_expired_token_rejected(self):
        with patch.object(main, "TOKEN_TTL_SEC", -10):
            expired = main.create_token("admin")
        with self.assertRaises(HTTPException) as ctx:
            main.verify_token(f"Bearer {expired}")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_missing_header_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            main.verify_token(None)
        self.assertEqual(ctx.exception.status_code, 401)


class TestAccessControl(unittest.TestCase):
    """Verify SHA-256 credential hashing and physical door access authorization decisions."""

    def test_sha256_hashing_and_normalization(self):
        h1 = mqtt_worker.hash_credential("A1B2C3D4:1234")
        h2 = mqtt_worker.hash_credential("  A1B2C3D4:1234\n")
        h3 = mqtt_worker.hash_credential("A1B2C3D4:9999")
        self.assertEqual(len(h1), 64)
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)
        self.assertNotIn("1234", h1)

    def test_access_granted_for_active_card(self):
        conn, _ = make_mock_conn(fetchone_val={"owner_name": "Pierre", "role": "admin", "is_active": True})
        mock_client = MagicMock()
        with patch("mqtt_worker.get_conn", return_value=conn), \
             patch("mqtt_worker._client", mock_client), \
             patch("mqtt_worker.log_system"):
            mqtt_worker._handle_access_request({"device_id": "pi1", "credential": "1234"})
        topic, payload_str = mock_client.publish.call_args[0][0], mock_client.publish.call_args[0][1]
        resp = json.loads(payload_str)
        self.assertEqual(topic, "serverroom/access/response")
        self.assertTrue(resp["granted"])
        self.assertEqual(resp["owner"], "Pierre")

    def test_access_denied_for_disabled_card(self):
        conn, _ = make_mock_conn(fetchone_val={"owner_name": "Tidligere", "role": "staff", "is_active": False})
        mock_client = MagicMock()
        with patch("mqtt_worker.get_conn", return_value=conn), \
             patch("mqtt_worker._client", mock_client), \
             patch("mqtt_worker.log_system"):
            mqtt_worker._handle_access_request({"device_id": "pi1", "credential": "9999"})
        resp = json.loads(mock_client.publish.call_args[0][1])
        self.assertFalse(resp["granted"])
        self.assertIn("deaktiveret", resp["reason"])

    def test_access_denied_for_unknown_card(self):
        conn, _ = make_mock_conn(fetchone_val=None)
        mock_client = MagicMock()
        with patch("mqtt_worker.get_conn", return_value=conn), \
             patch("mqtt_worker._client", mock_client), \
             patch("mqtt_worker.log_system"):
            mqtt_worker._handle_access_request({"device_id": "pi1", "credential": "UKENDT"})
        resp = json.loads(mock_client.publish.call_args[0][1])
        self.assertFalse(resp["granted"])


class TestAIEngine(unittest.TestCase):
    """Verify ASHRAE rules, missing sensor handling, trend noise filter, Z-score, and Isolation Forest."""

    def test_normal_reading_no_alarm(self):
        conn, _ = make_mock_conn(fetchall_val=[])
        with patch("ai_engine.get_conn", return_value=conn):
            res = ai_engine.analyze_reading("pi1", 22.0, 45.0, 50.0)
        self.assertFalse(res["is_anomaly"])
        self.assertIsNone(res["predicted_critical_min"])

    def test_ashrae_threshold_violations_detected(self):
        conn, _ = make_mock_conn(fetchall_val=[])
        with patch("ai_engine.get_conn", return_value=conn):
            hot = ai_engine.analyze_reading("pi1", 29.5, 45.0, 50.0)
            cold = ai_engine.analyze_reading("pi1", 15.0, 45.0, 50.0)
            humid = ai_engine.analyze_reading("pi1", 22.0, 88.0, 50.0)
            loud = ai_engine.analyze_reading("pi1", 22.0, 45.0, 82.0)
        self.assertTrue(hot["is_anomaly"])
        self.assertTrue(cold["is_anomaly"])
        self.assertTrue(humid["is_anomaly"])
        self.assertTrue(loud["is_anomaly"])

    def test_missing_sensor_values_do_not_crash(self):
        conn, _ = make_mock_conn(fetchall_val=[])
        with patch("ai_engine.get_conn", return_value=conn):
            res = ai_engine.analyze_reading("pi1", None, None, 52.0)
        self.assertFalse(res["is_anomaly"])

    def test_noise_filter_blocks_false_positive_trend(self):
        base_ts = int(time.time())
        # 15 stable readings around 22.0 C (+/- 0.2 C jitter) must NOT trigger a false overheat prediction
        noisy_rows = [
            {"ts": base_ts - i * 5, "temperature": 22.0 + (0.2 if i % 2 == 0 else -0.2), "humidity": 45.0, "noise_db": 50.0}
            for i in range(15)
        ]
        conn, _ = make_mock_conn(fetchall_val=noisy_rows)
        with patch("ai_engine.get_conn", return_value=conn):
            res = ai_engine.analyze_reading("pi1", 22.2, 45.0, 50.0)
        self.assertIsNone(res["predicted_critical_min"])

    def test_real_heating_trend_returns_whole_integer_minutes(self):
        base_ts = int(time.time())
        # Real temperature rise from 21.0 C to 24.5 C over 70s (ORDER BY time DESC -> newest first)
        rising_rows = [
            {"ts": base_ts - i * 5, "temperature": 24.5 - i * 0.25, "humidity": 45.0, "noise_db": 50.0}
            for i in range(15)
        ]
        conn, _ = make_mock_conn(fetchall_val=rising_rows)
        with patch("ai_engine.get_conn", return_value=conn):
            res = ai_engine.analyze_reading("pi1", 24.5, 45.0, 50.0)
        self.assertIsNotNone(res["predicted_critical_min"])
        self.assertIsInstance(res["predicted_critical_min"], int)
        self.assertTrue(any("om ca." in r and "." not in r.split("om ca.")[1] for r in res["reasons"]))

    def test_flat_baseline_outlier_caught_by_zscore(self):
        base_ts = int(time.time())
        flat_rows = [
            {"ts": base_ts - i * 5, "temperature": 22.0, "humidity": 45.0, "noise_db": 50.0}
            for i in range(40)
        ]
        conn, _ = make_mock_conn(fetchall_val=flat_rows)
        with patch("ai_engine.get_conn", return_value=conn):
            res = ai_engine.analyze_reading("pi1", 26.8, 78.0, 74.0)
        self.assertTrue(res["is_anomaly"])
        self.assertTrue(any("Z-score" in r for r in res["reasons"]))

    def test_isolation_forest_detects_multivariate_outlier(self):
        base_ts = int(time.time())
        normal_rows = [
            {
                "ts": base_ts - i * 5,
                "temperature": 22.0 + ((i % 5) - 2) * 0.2,
                "humidity": 45.0 + ((i % 7) - 3) * 0.6,
                "noise_db": 50.0 + ((i % 6) - 2.5) * 0.8,
            }
            for i in range(50)
        ]
        conn, _ = make_mock_conn(fetchall_val=normal_rows)
        with patch("ai_engine.get_conn", return_value=conn):
            res = ai_engine.analyze_reading("pi1", 26.8, 78.0, 74.0)
        self.assertTrue(res["is_anomaly"])
        self.assertTrue(any("Isolation Forest" in r for r in res["reasons"]))


class TestMqttResilience(unittest.TestCase):
    """Verify corrupt MQTT handling and fan auto-stop while keeping alarms latched."""

    def test_corrupt_json_payload_logged_without_crash(self):
        fake_msg = MagicMock()
        fake_msg.topic = "serverroom/pi1/telemetry"
        fake_msg.payload = b"CORRUPT_NOT_JSON{{{"
        with patch("mqtt_worker.log_system") as mock_log:
            mqtt_worker._on_message(None, None, fake_msg)
        mock_log.assert_called_once()
        self.assertEqual(mock_log.call_args[0][1], "ERROR")

    def test_ai_autopilot_auto_clears_env_and_fan_when_normalized(self):
        mqtt_worker._last_auto_action_ts.clear()
        mqtt_worker._active_env_alarm.clear()
        mqtt_worker._active_auto_fan.clear()
        mqtt_worker.set_auto_cooling(True)
        conn, _ = make_mock_conn(fetchall_val=[])
        with patch("mqtt_worker.get_conn", return_value=conn), \
             patch("mqtt_worker.update_device_status"), \
             patch("mqtt_worker.publish_command") as mock_pub:
            # Step 1: Overheating triggers BOTH latched alarm_test and fan_auto
            with patch("mqtt_worker.analyze_reading", return_value={"threshold_breached": True, "critical_action_needed": True, "is_anomaly": True, "score": -0.5, "reasons": ["Temp > 27"]}):
                mqtt_worker._handle_telemetry("pi1", {"temperature": 28.5, "humidity": 45.0, "noise_db": 42.0})
            cmds_hot = [c[0][1] for c in mock_pub.call_args_list]
            self.assertIn("alarm_test", cmds_hot)
            self.assertIn("fan_auto", cmds_hot)

            mock_pub.reset_mock()
            # Step 2: Temp drops < 27 C -> auto-stops fan (fan_auto_off), does NOT auto-stop alarm
            with patch("mqtt_worker.analyze_reading", return_value={"threshold_breached": False, "critical_action_needed": False, "is_anomaly": False, "score": 0.1, "reasons": []}):
                mqtt_worker._handle_telemetry("pi1", {"temperature": 25.0, "humidity": 45.0, "noise_db": 42.0})
            cmds_ok = [c[0][1] for c in mock_pub.call_args_list]
            self.assertNotIn("alarm_stop", cmds_ok)
            self.assertIn("fan_auto_off", cmds_ok)


class TestHardeningAndAutomation(unittest.TestCase):
    """Verify flatline fault detection, door brute-force alarm, AI autopilot, and server metrics."""

    def test_flatline_sensor_defect_detected(self):
        base_ts = int(time.time())
        stuck_rows = [
            {"ts": base_ts - i * 5, "temperature": 22.0, "humidity": 45.0, "noise_db": 50.0}
            for i in range(25)
        ]
        conn, _ = make_mock_conn(fetchall_val=stuck_rows)
        with patch("ai_engine.get_conn", return_value=conn):
            res = ai_engine.analyze_reading("pi1", 22.0, 45.0, 50.0)
        self.assertTrue(res["is_anomaly"])
        self.assertTrue(any("flatline" in r.lower() for r in res["reasons"]))

    def test_door_bruteforce_triggers_alarm_after_3_failures(self):
        mqtt_worker._failed_access_attempts.clear()
        conn, _ = make_mock_conn(fetchone_val=None)
        mock_client = MagicMock()
        with patch("mqtt_worker.get_conn", return_value=conn), \
             patch("mqtt_worker._client", mock_client), \
             patch("mqtt_worker.log_system"), \
             patch("mqtt_worker.publish_command") as mock_pub:
            for _ in range(3):
                mqtt_worker._handle_access_request({"device_id": "door1", "credential": "FORKERT"})
            mock_pub.assert_called_once()
            self.assertEqual(mock_pub.call_args[0][1], "alarm_test")

    def test_ai_autopilot_sends_fan_on_on_critical_temp(self):
        mqtt_worker._last_auto_action_ts.clear()
        mqtt_worker._active_auto_fan.clear()
        mqtt_worker.set_auto_cooling(True)
        conn, _ = make_mock_conn(fetchall_val=[])
        with patch("mqtt_worker.get_conn", return_value=conn), \
             patch("mqtt_worker.update_device_status"), \
             patch("mqtt_worker.analyze_reading", return_value={"critical_action_needed": True}), \
             patch("mqtt_worker.publish_command") as mock_pub:
            mqtt_worker._handle_telemetry("pi1", {"temperature": 29.0, "humidity": 45.0, "noise_db": 55.0})
            mock_pub.assert_called_once()
            self.assertEqual(mock_pub.call_args[0][1], "fan_auto")

    def test_ai_autopilot_triggers_alarm_on_threshold_breach(self):
        mqtt_worker._last_auto_action_ts.clear()
        mqtt_worker._active_auto_fan.clear()
        mqtt_worker.set_auto_cooling(True)
        conn, _ = make_mock_conn(fetchall_val=[])
        with patch("mqtt_worker.get_conn", return_value=conn), \
             patch("mqtt_worker.update_device_status"), \
             patch("mqtt_worker.analyze_reading", return_value={"threshold_breached": True, "critical_action_needed": False}), \
             patch("mqtt_worker.publish_command") as mock_pub:
            mqtt_worker._handle_telemetry("pi1", {"temperature": 22.0, "humidity": 86.0, "noise_db": 50.0})
            mock_pub.assert_called_once()
            self.assertEqual(mock_pub.call_args[0][1], "alarm_test")

    def test_server_metrics_returns_valid_fields(self):
        m = main.get_server_metrics()
        for k in ("cpu_load", "ram_pct", "disk_pct", "uptime"):
            self.assertIn(k, m)


class TestRBACAndUsers(unittest.TestCase):
    """Verify PBKDF2-SHA256 salting, RBAC HTTP 403 enforcement, and disabled user lockout."""

    def test_pbkdf2_password_hash_and_verify(self):
        import auth_utils
        h1 = auth_utils.hash_password("Hemmeligt123!")
        h2 = auth_utils.hash_password("Hemmeligt123!")
        self.assertNotEqual(h1, h2)  # Unique random salt per hash
        self.assertNotIn("Hemmeligt123!", h1)
        self.assertTrue(auth_utils.verify_password("Hemmeligt123!", h1))
        self.assertFalse(auth_utils.verify_password("Forkert123!", h1))

    def test_rbac_viewer_blocked_from_commands(self):
        dep = main.require_role("admin", "operator")
        with self.assertRaises(HTTPException) as ctx:
            dep({"username": "censor", "role": "viewer"})
        self.assertEqual(ctx.exception.status_code, 403)

    def test_rbac_operator_blocked_from_admin_user_mgmt(self):
        dep = main.require_role("admin")
        with self.assertRaises(HTTPException) as ctx:
            dep({"username": "op1", "role": "operator"})
        self.assertEqual(ctx.exception.status_code, 403)

    def test_disabled_user_blocked_at_login(self):
        import auth_utils
        pw_hash = auth_utils.hash_password("StaerktPass99!")
        conn, _ = make_mock_conn(
            fetchone_val={"id": 2, "username": "spaerret", "password_hash": pw_hash, "role": "operator", "is_active": False}
        )
        with patch("auth_utils.get_conn", return_value=conn):
            self.assertIsNone(auth_utils.authenticate_user("spaerret", "StaerktPass99!"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
