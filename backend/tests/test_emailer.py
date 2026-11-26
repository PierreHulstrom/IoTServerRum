"""Offline unit tests for Azure Communication Services Email parsing, XSS escaping, and cooldown."""

import os
import unittest
from unittest.mock import patch

import emailer


class TestEmailer(unittest.TestCase):
    """Validate ACS Email connection string security, HTML escaping, and anti-spam cooldown."""

    def test_parse_connection_string_valid(self):
        ep, key = emailer.parse_connection_string(
            "endpoint=https://serverrum-acs.europe.communication.azure.com/;accesskey=dGVzdGtleQ=="
        )
        self.assertEqual(ep, "https://serverrum-acs.europe.communication.azure.com")
        self.assertEqual(key, "dGVzdGtleQ==")

    def test_parse_connection_string_rejects_non_https(self):
        with self.assertRaises(ValueError):
            emailer.parse_connection_string("endpoint=http://insecure.local/;accesskey=dGVzdA==")

    def test_html_escapes_xss_payloads(self):
        rendered = emailer._build_html("<script>alert(1)</script>", "IP <img src=x>", "CRITICAL")
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;img src=x&gt;", rendered)

    def test_send_email_unconfigured_returns_false(self):
        with patch.dict(os.environ, {"ACS_CONNECTION_STRING": "", "ACS_SENDER_ADDRESS": "", "ALERT_EMAIL_TO": ""}, clear=False):
            ok, msg = emailer.send_email("Test", "Body")
            self.assertFalse(ok)
            self.assertIn("ikke konfigureret", msg)

    def test_cooldown_prevents_email_spam(self):
        emailer._LAST_SENT.clear()
        fake_env = {
            "ACS_CONNECTION_STRING": "endpoint=https://demo.communication.azure.com/;accesskey=dGVzdA==",
            "ACS_SENDER_ADDRESS": "DoNotReply@demo.azurecomm.net",
            "ALERT_EMAIL_TO": "test@edu.zealand.dk",
        }
        with patch.dict(os.environ, fake_env, clear=False), patch.object(
            emailer, "send_email", return_value=(True, "HTTP 202")
        ):
            first = emailer.send_alert_async("spam_key", "Sub", "Body", cooldown_sec=60)
            second = emailer.send_alert_async("spam_key", "Sub", "Body", cooldown_sec=60)
            self.assertTrue(first)
            self.assertFalse(second)


if __name__ == "__main__":
    unittest.main()
