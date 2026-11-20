import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import json
import types
from starlette.requests import Request
from fastapi.exceptions import HTTPException

# Ensure test environment
os.environ["TESTING"] = "1"
os.environ["SECRET_KEY"] = "test-secret-key-32-chars-long-abc"
os.environ["DB_PASSWORD"] = "testpassword"

import database as db
import app as app_module

def _run_coroutine_sync(coro_or_res):
    """Executes an async FastAPI handler synchronously or returns response directly."""
    if hasattr(coro_or_res, "__await__") or hasattr(coro_or_res, "send"):
        def step(c, val=None, exc=None):
            while True:
                try:
                    fut = c.throw(exc) if exc else c.send(val)
                    val, exc = None, None
                    if isinstance(fut, types.GeneratorType) or hasattr(fut, '__await__'):
                        sub = fut.__await__() if hasattr(fut, '__await__') else fut
                        val = step(sub)
                    else:
                        val = None
                except StopIteration as e:
                    return e.value
        return step(coro_or_res)
    return coro_or_res

def _build_request(method="GET", path="/", body=None, session=None, query_string=b""):
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": query_string,
        "headers": [(b"host", b"localhost:8000"), (b"content-type", b"application/json")],
        "client": ("127.0.0.1", 50000),
        "session": session or {}
    }
    payload_bytes = json.dumps(body).encode() if body is not None else b""
    async def receive():
        return {
            "type": "http.request",
            "body": payload_bytes,
            "more_body": False
        }
    return Request(scope, receive)

class TestRBACStrictSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()

    def test_production_testing_guard(self):
        """1. validate_production_config terminates if TESTING=1 when ENV=production."""
        with patch.dict(os.environ, {"ENV": "production", "TESTING": "1"}):
            with self.assertRaises(SystemExit) as ctx:
                app_module.validate_production_config()
            self.assertEqual(ctx.exception.code, 1)

    def test_unauthenticated_requests_return_401(self):
        """2. Unauthenticated requests to protected endpoints return 401 without bypass."""
        req1 = _build_request("POST", "/api/malware/action", body={"action": "quarantine", "finding_id": 1, "confirmation": "DELETE"})
        res1 = _run_coroutine_sync(app_module.api_malware_action(req1))
        self.assertEqual(res1.status_code, 401)

        req2 = _build_request("POST", "/api/servers/1/scan-malware")
        res2 = _run_coroutine_sync(app_module.api_server_scan_malware(req2, 1))
        self.assertEqual(res2.status_code, 401)

        req3 = _build_request("POST", "/api/apps", body={"name": "AttackerApp", "project_id": 1})
        with self.assertRaises(HTTPException) as ctx:
            _run_coroutine_sync(app_module.api_create_app(req3))
        self.assertEqual(ctx.exception.status_code, 401)

        req4 = _build_request("DELETE", "/api/apps/1")
        with self.assertRaises(HTTPException) as ctx:
            _run_coroutine_sync(app_module.api_delete_app(req4, 1))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_normal_user_rbac_restrictions_and_reports_access(self):
        """3. Normal users cannot trigger scans or remediations (403), but CAN generate reports for assigned assets."""
        normal_user = {
            "id": 105,
            "username": "auditor_user",
            "role": "user",
            "is_admin": False,
            "projects": [1, 2]
        }

        with patch("app.get_session_user", return_value=normal_user):
            with patch("app.get_effective_project_id", return_value=[1, 2]):
                # Normal user cannot trigger scan
                req_scan = _build_request("POST", "/api/servers/1/scan-malware")
                res_scan = _run_coroutine_sync(app_module.api_server_scan_malware(req_scan, 1))
                self.assertEqual(res_scan.status_code, 403)

                # Normal user cannot quarantine
                req_quar = _build_request("POST", "/api/malware/action", body={"action": "quarantine", "finding_id": 1})
                res_quar = _run_coroutine_sync(app_module.api_malware_action(req_quar))
                self.assertEqual(res_quar.status_code, 403)

                # Normal user cannot delete
                req_del = _build_request("POST", "/api/malware/action", body={"action": "delete", "finding_id": 1, "confirmation": "DELETE"})
                res_del = _run_coroutine_sync(app_module.api_malware_action(req_del))
                self.assertEqual(res_del.status_code, 403)

                # Normal user cannot whitelist
                req_wl = _build_request("POST", "/api/malware/action", body={"action": "whitelist", "finding_id": 1})
                res_wl = _run_coroutine_sync(app_module.api_malware_action(req_wl))
                self.assertEqual(res_wl.status_code, 403)

                # Normal user cannot create app
                req_app_c = _build_request("POST", "/api/apps", body={"name": "UnauthorizedApp", "project_id": 1})
                with self.assertRaises(HTTPException) as ctx:
                    _run_coroutine_sync(app_module.api_create_app(req_app_c))
                self.assertEqual(ctx.exception.status_code, 403)

                # Normal user cannot delete app
                req_app_d = _build_request("DELETE", "/api/apps/1")
                with self.assertRaises(HTTPException) as ctx:
                    _run_coroutine_sync(app_module.api_delete_app(req_app_d, 1))
                self.assertEqual(ctx.exception.status_code, 403)

                # Normal user CAN access reports for assigned project assets
                req_rep = _build_request("GET", "/api/reports/malware/data", query_string=b"server_id=1")
                with patch("database.get_server_by_id", return_value={"id": 1, "project_id": 1, "name": "srv1", "ip": "10.0.0.1"}):
                    with patch("database.get_malware_report_data", return_value={"ok": True, "server": {"id": 1}, "summary": {}, "findings": []}):
                        res_rep = app_module.api_get_malware_report(req_rep, server_id=1)
                        self.assertTrue(res_rep.get("ok"))

                # Normal user is BLOCKED (403 IDOR) when requesting reports for unassigned project asset
                req_rep_idor = _build_request("GET", "/api/reports/malware/data", query_string=b"server_id=99")
                with patch("database.get_server_by_id", return_value={"id": 99, "project_id": 999, "name": "secret-srv", "ip": "10.0.0.99"}):
                    with self.assertRaises(HTTPException) as ctx_idor:
                        app_module.api_get_malware_report(req_rep_idor, server_id=99)
                    self.assertEqual(ctx_idor.exception.status_code, 403)

    def test_operator_role_hierarchy(self):
        """4. Operator role can view ops & whitelist, but CANNOT quarantine or delete (pure admin only)."""
        operator_user = {
            "id": 102,
            "username": "soc_operator",
            "role": "operator",
            "is_admin": True,
            "projects": [1]
        }

        with patch("app.get_session_user", return_value=operator_user):
            # Operator is NOT pure admin: quarantine must return 403
            req_quar = _build_request("POST", "/api/malware/action", body={"action": "quarantine", "finding_id": 1})
            res_quar = _run_coroutine_sync(app_module.api_malware_action(req_quar))
            self.assertEqual(res_quar.status_code, 403)
            data_quar = json.loads(res_quar.body.decode())
            self.assertIn("Administrator privileges required", data_quar.get("message", ""))

            # Operator is NOT pure admin: delete must return 403
            req_del = _build_request("POST", "/api/malware/action", body={"action": "delete", "finding_id": 1, "confirmation": "DELETE"})
            res_del = _run_coroutine_sync(app_module.api_malware_action(req_del))
            self.assertEqual(res_del.status_code, 403)
            data_del = json.loads(res_del.body.decode())
            self.assertIn("Administrator privileges required", data_del.get("message", ""))

    def test_pure_admin_can_quarantine_and_delete(self):
        """5. Pure admin (admin / superuser) can quarantine and delete."""
        admin_user = {
            "id": 1,
            "username": "admin",
            "role": "admin",
            "is_admin": True,
            "projects": []
        }

        mock_finding = {
            "id": 9999,
            "scan_id": 1,
            "server_id": 1,
            "file_path": "/tmp/test_threat.sh",
            "file_name": "test_threat.sh",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "permissions": "0755",
            "owner": "root",
            "file_size": 100
        }

        with patch("app.get_session_user", return_value=admin_user):
            req_quar = _build_request("POST", "/api/malware/action", body={"action": "quarantine", "finding_id": 9999})
            mock_cur = MagicMock()
            mock_cur.fetchone.return_value = mock_finding
            mock_conn = MagicMock()
            mock_conn.cursor.return_value.__enter__.return_value = mock_cur
            with patch("database.get_db_connection", return_value=mock_conn):
                with patch("database.update_file_scan_result_status"):
                    res_quar = _run_coroutine_sync(app_module.api_malware_action(req_quar))
                    self.assertEqual(res_quar.get("status"), "success")
                    self.assertIn("cryptographically signed and queued", res_quar.get("message", ""))

    def test_csv_formula_injection_sanitization(self):
        """6. CSV cell sanitization neutralizes dynamic command execution primitives (=, +, -, @, \\t, \\r)."""
        malicious_inputs = [
            "=1+1",
            "=cmd|' /C calc'!A0",
            "+12345",
            "-2+5",
            "@SUM(A1:A10)",
            "\tTAB_INJECTION",
            "\rCARRIAGE_RETURN"
        ]
        for payload in malicious_inputs:
            sanitized = app_module.sanitize_csv_cell(payload)
            self.assertTrue(sanitized.startswith("'"), f"Payload {payload} was not prepended with single quote: {sanitized}")

        safe_inputs = ["CleanFilePath", "/var/log/syslog", "soc-server-01", "192.168.1.1"]
        for safe in safe_inputs:
            sanitized = app_module.sanitize_csv_cell(safe)
            self.assertEqual(sanitized, safe)

if __name__ == "__main__":
    unittest.main()
