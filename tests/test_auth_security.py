import unittest
import asyncio
import json
import os
from starlette.requests import Request
import database as db
import app as app_module

class TestAuthSecurity(unittest.TestCase):
    """
    Verification tests for Item 7:
    - Hardcoded credentials removed; admin/admin returns 401
    - Account lockout after 5 failed attempts (LOGIN_LOCKED)
    - IP allowlist enforcement (ADMIN_ALLOWED_IPS -> 403 LOGIN_BLOCKED_IP)
    """

    def _call_login(self, username, password, client_ip="203.0.113.10"):
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/auth/login",
            "headers": [(b"content-type", b"application/json"), (b"x-forwarded-for", client_ip.encode())],
            "client": (client_ip, 12345),
            "session": {}
        }
        async def receive():
            return {
                "type": "http.request",
                "body": json.dumps({"username": username, "password": password}).encode(),
                "more_body": False
            }
        req = Request(scope, receive)
        return asyncio.run(app_module.auth_login(req))

    def test_admin_default_passwords_rejected(self):
        # admin/admin must return HTTP 401 Unauthorized
        res = self._call_login("admin", "admin", "198.51.100.1")
        self.assertEqual(res.status_code, 401)
        data = json.loads(res.body.decode())
        self.assertFalse(data.get("ok"))
        self.assertIn("Invalid username or password", data.get("error"))

    def test_admin_legacy_fallback_rejected(self):
        # admin / Admin@1234 must not bypass if not matching DB hash
        res = self._call_login("admin", "WrongPass123!", "198.51.100.2")
        self.assertEqual(res.status_code, 401)

    def test_account_lockout_rate_limiting(self):
        # 5 consecutive failures triggers 15-minute lock on that IP
        attacker_ip = "192.0.2.77"
        admin_ip = "198.51.100.5"
        app_module._login_attempts.clear()
        
        for i in range(4):
            res = self._call_login("admin", f"wrong_{i}", attacker_ip)
            self.assertEqual(res.status_code, 401)
        
        # 5th attempt locks attacker IP
        res5 = self._call_login("admin", "wrong_5", attacker_ip)
        self.assertEqual(res5.status_code, 401)

        # 6th attempt from attacker IP is blocked with 429
        res6 = self._call_login("admin", "wrong_6", attacker_ip)
        self.assertEqual(res6.status_code, 429)
        data = json.loads(res6.body.decode())
        self.assertIn("locked", data.get("error", "").lower())

        # Crucial Requirement 4: Real admin from legitimate IP is NOT locked out!
        res_admin = self._call_login("admin", "some_attempt", admin_ip)
        # Should return 401 (normal password check), NOT 429 lockout!
        self.assertEqual(res_admin.status_code, 401)

    def test_admin_ip_allowlist_blocking(self):
        # When ADMIN_ALLOWED_IPS is configured, unauthorized IP gets 403
        orig_allowed = app_module.ADMIN_ALLOWED_IPS
        try:
            app_module.ADMIN_ALLOWED_IPS = ["10.0.0.0/24", "192.168.1.50"]
            
            # Non-whitelisted IP
            res_blocked = self._call_login("admin", "secret", "203.0.113.99")
            self.assertEqual(res_blocked.status_code, 403)
            data = json.loads(res_blocked.body.decode())
            self.assertIn("restricted", data.get("error", "").lower())

            # Whitelisted IP allowed through to authentication check
            res_allowed = self._call_login("admin", "wrong_pass", "10.0.0.5")
            self.assertEqual(res_allowed.status_code, 401)
        finally:
            app_module.ADMIN_ALLOWED_IPS = orig_allowed

if __name__ == '__main__':
    unittest.main()
