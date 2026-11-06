import unittest
from unittest.mock import MagicMock, patch
import os
import ses_mailer

class TestSesMailerComprehensive(unittest.TestCase):

    def test_parse_recipients(self):
        # Test comma, semicolon, space, quotes, and invalid emails
        input_str = "team_cloudinfra@bcits.co.in, second@domain.com ; 'third@example.com' , \"fourth@domain.org\" , invalid-email, @no-user.com"
        recipients = ses_mailer.parse_recipients(input_str)
        self.assertEqual(len(recipients), 4)
        self.assertIn("team_cloudinfra@bcits.co.in", recipients)
        self.assertIn("second@domain.com", recipients)
        self.assertIn("third@example.com", recipients)
        self.assertIn("fourth@domain.org", recipients)
        self.assertNotIn("invalid-email", recipients)

    def test_sanitize_alert_for_external_ai(self):
        # Mask IP, token, password
        raw = "User admin failed login from 192.168.150.16 with token sp-token-4801a6894e410ea6a74df1378ddbcfd0 and password=SecretPass123"
        sanitized = ses_mailer.sanitize_alert_for_external_ai(raw)
        self.assertNotIn("192.168.150.16", sanitized)
        self.assertIn("[REDACTED_IP]", sanitized)
        self.assertNotIn("sp-token-4801a6894e410ea6a74df1378ddbcfd0", sanitized)
        self.assertIn("[REDACTED_TOKEN]", sanitized)
        self.assertNotIn("SecretPass123", sanitized)
        self.assertIn("password=[REDACTED]", sanitized)

    def test_missing_credentials_report(self):
        with patch.dict(os.environ, {}, clear=True):
            cfg = ses_mailer.get_ses_config()
            self.assertTrue(len(cfg["missing"]) > 0)
            self.assertIn("SES_AWS_REGION", cfg["missing"])
            self.assertIn("SES_SENDER_EMAIL", cfg["missing"])

    def test_critical_alert_dedup(self):
        with patch("ses_mailer.send_email_per_recipient") as mock_send:
            mock_send.return_value = {"ok": True, "results": []}
            # First send should succeed
            res1 = ses_mailer.send_smart_alert_email(
                alert_id=1, alert_title="Spike", alert_type="TEST_CRITICAL_RULE",
                message="test", severity="CRITICAL", timestamp="now",
                server_ip="10.0.0.1", hostname="test-host", force=False
            )
            self.assertTrue(res1)
            # Immediate second send for same rule and server should be deduplicated (return False)
            res2 = ses_mailer.send_smart_alert_email(
                alert_id=2, alert_title="Spike", alert_type="TEST_CRITICAL_RULE",
                message="test", severity="CRITICAL", timestamp="now",
                server_ip="10.0.0.1", hostname="test-host", force=False
            )
            self.assertFalse(res2)

if __name__ == '__main__':
    unittest.main()
