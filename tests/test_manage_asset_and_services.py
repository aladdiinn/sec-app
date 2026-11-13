import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import json, time, os, sys, types

# Set test environment
os.environ["TESTING"] = "1"
os.environ["SECRET_KEY"] = "test-secret-key-32-chars-long-abc"
os.environ["DB_PASSWORD"] = "testpassword"

import database as db
import app

def _init_agent_module():
    if "extracted_agent_test" in sys.modules:
        return sys.modules["extracted_agent_test"]
    with open("app.py", "r", encoding="utf-8") as f:
        text = f.read()
    s_marker = "cat << PY_EOF > /opt/securepulse/node_push_agent.py"
    start = text.find(s_marker)
    end = text.find("PY_EOF", start + len(s_marker))
    agent_code = text[start + len(s_marker) + 1:end].strip()
    agent_standalone = agent_code.replace("{{", "{").replace("}}", "}")
    agent_standalone = agent_standalone.replace("{base_url}", "http://localhost:8000")
    agent_standalone = agent_standalone.replace('{server_id or "None"}', "1")
    mod = types.ModuleType("extracted_agent_test")
    exec(agent_standalone, mod.__dict__)
    sys.modules["extracted_agent_test"] = mod
    return mod

_init_agent_module()

class TestManageAssetAndServices(unittest.TestCase):

    def _run_coro(self, coro):
        stack = [coro]
        val = None
        while stack:
            try:
                curr = stack[-1]
                val = curr.send(val)
                if hasattr(val, 'send'):
                    stack.append(val)
                    val = None
            except StopIteration as e:
                stack.pop()
                val = e.value
        return val

    def test_t1_manage_button_on_total_assets_and_maintenance(self):
        """T1. Manage button exists; agent outdated check triggers on agent_version < 2.0.0."""
        with open("templates/servers.html", "r", encoding="utf-8") as f:
            servers_html = f.read()
        self.assertIn("MANAGE ASSET", servers_html)
        self.assertIn("/servers/${id}?from=assets", servers_html)
        self.assertIn("2.0.0", servers_html)

        with open("templates/maintenance.html", "r", encoding="utf-8") as f:
            maint_html = f.read()
        self.assertIn("Manage Asset", maint_html)
        self.assertIn("/servers/${s.id}?from=maintenance", maint_html)

        with open("templates/server_detail.html", "r", encoding="utf-8") as f:
            detail_html = f.read()
        self.assertIn("goBack()", detail_html)
        self.assertIn("relTime", detail_html)
        self.assertIn("Evidence", detail_html)
        self.assertNotIn("RESTART SERVICE", detail_html)
        self.assertNotIn("service-action-modal", detail_html)

    def test_t2_service_discovery_and_classification(self):
        """T2. Discovery flags system services and synthesis avoids tomcat8 synthetic default."""
        from extracted_agent_test import discover_services

        mock_systemctl = (
            "nginx.service loaded active running Nginx Web Server\n"
            "postgresql.service loaded active running PostgreSQL RDBMS\n"
            "cron.service loaded active running Regular Background Cron\n"
            "ssh.service loaded active running OpenBSD SSH\n"
            "securepulse.service loaded active running SecurePulse Push Agent\n"
        )
        with patch("subprocess.check_output", return_value=mock_systemctl.encode("utf-8")):
            with patch("extracted_agent_test.get_open_ports", return_value=[]):
                services = discover_services(force=True)

        srv_by_name = {s["name"]: s for s in services}
        self.assertIn("nginx", srv_by_name)
        self.assertFalse(srv_by_name["nginx"]["is_system"])
        self.assertEqual(srv_by_name["nginx"]["status"], "running")
        self.assertIn("ssh", srv_by_name)
        self.assertTrue(srv_by_name["ssh"]["is_system"])

        # Test synthesis for server: Tomcat must never be tomcat8.service
        synthesized = db.synthesize_services_for_server(27)
        for s in synthesized:
            self.assertNotEqual(s.get("unit_name"), "tomcat8.service")
            if s.get("name") == "Tomcat":
                self.assertEqual(s.get("managed_by"), "process")
                self.assertIsNone(s.get("unit_name"))
            if s.get("name") == "haproxy":
                self.assertEqual(s.get("managed_by"), "systemd")
                self.assertEqual(s.get("unit_name"), "haproxy.service")

    def test_t3_service_control_decommissioned_routes_removed(self):
        """T3. Remote execution routes (action, poll, status, result) are removed from FastAPI app."""
        app_routes = [route.path for route in app.app.routes]
        self.assertNotIn("/api/servers/{server_id}/services/action", app_routes)
        self.assertNotIn("/api/servers/{server_id}/tasks/{task_id}", app_routes)
        self.assertNotIn("/api/servers/{server_id}/restart-services", app_routes)
        self.assertNotIn("/api/servers/{server_id}/services/pin", app_routes)
        self.assertNotIn("/api/agent/tasks/poll", app_routes)
        self.assertNotIn("/api/agent/tasks/status", app_routes)
        self.assertNotIn("/api/agent/tasks/result", app_routes)
        self.assertFalse(hasattr(app, "api_service_action"))
        self.assertFalse(hasattr(app, "api_agent_tasks_poll"))

    def test_t4_agent_script_has_zero_remote_execution(self):
        """T4. Agent v2.0.0 has zero remote command execution, polling loops, or result queues."""
        with open("app.py", "r", encoding="utf-8") as f:
            text = f.read()
        s_marker = "cat << PY_EOF > /opt/securepulse/node_push_agent.py"
        start = text.find(s_marker)
        end = text.find("PY_EOF", start + len(s_marker))
        agent_code = text[start + len(s_marker) + 1:end].strip()

        self.assertIn('AGENT_VERSION = "2.0.0"', agent_code)
        self.assertNotIn("execute_agent_tasks", agent_code)
        self.assertNotIn("task_polling_loop", agent_code)
        self.assertNotIn("task_results_queue", agent_code)
        self.assertNotIn("systemctl restart", agent_code)
        self.assertNotIn("systemctl stop", agent_code)
        self.assertNotIn("systemctl start", agent_code)
        self.assertNotIn("docker restart", agent_code)
        self.assertNotIn("pkill", agent_code)

    def test_t5_rescan_is_pure_read_only_refresh(self):
        """T5. POST /api/servers/{id}/services/rescan performs a read-only refresh without tasks."""
        req = MagicMock()
        req.session = {"user_id": 1, "username": "admin", "user_role": "admin"}
        req.client.host = "127.0.0.1"

        mock_fresh = [{"id": "proc:tomcat", "name": "Tomcat", "status": "running"}]
        with patch("app.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
            with patch("app.verify_server_project_scope", return_value=(True, "")):
                with patch("app.db.get_server_by_id", return_value={"id": 1, "hostname": "soc-server", "ip_address": "192.168.10.201", "detected_services": []}):
                    with patch("app.db.synthesize_services_for_server", return_value=mock_fresh):
                        with patch("app.db.save_detected_services") as mock_save:
                            with patch("app.db.log_audit") as mock_audit:
                                res = self._run_coro(app.api_rescan_services(server_id=1, request=req))
                                self.assertTrue(res.get("ok"))
                                mock_save.assert_called_once_with(1, mock_fresh)
                                mock_audit.assert_called_once()
                                audit_args = mock_audit.call_args[0]
                                self.assertEqual(audit_args[1], "SERVICE_RESCAN_REQUESTED")

    def test_t6_unexpected_stop_raises_alert(self):
        """T6. When a running service stops unexpectedly, an alert is raised."""
        prev_detected = [{"id": "proc:tomcat", "name": "Tomcat", "status": "running"}]
        new_detected = [{"id": "proc:tomcat", "name": "Tomcat", "status": "stopped"}]

        with patch("database.get_detected_services", return_value=prev_detected):
            with patch("database.get_managed_services", return_value=[]):
                with patch("database.get_server_by_id", return_value={"hostname": "soc-server", "is_maintenance": False}):
                    with patch("database.log_alert") as mock_alert:
                        with patch("database.get_db_connection") as mock_conn:
                            cur = MagicMock()
                            cur.fetchone.return_value = None
                            mock_conn.return_value.cursor.return_value.__enter__.return_value = cur
                            db.save_detected_services(server_id=1, services_list=new_detected)
                            mock_alert.assert_called_once()
                            call_args = mock_alert.call_args[1]
                            self.assertEqual(call_args["alert_type"], "service_stopped")
                            self.assertIn("Tomcat", call_args["title"])

    def test_t7_cases_endpoint_returns_list_without_crash(self):
        """T7. GET /api/cases handles dictionary response from db.get_incidents() without 500 error."""
        req = MagicMock()
        req.session = {"user_id": 1, "username": "admin", "user_role": "admin"}
        mock_incidents = {
            "items": [
                {"id": 10, "title": "SQL Injection attempt", "severity": "critical", "status": "open"}
            ],
            "total": 1
        }
        with patch("app.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
            with patch("app.db.get_incidents", return_value=mock_incidents):
                cases = self._run_coro(app.api_get_cases(request=req))
                self.assertIsInstance(cases, list)
                self.assertEqual(len(cases), 1)
                self.assertEqual(cases[0]["id"], 10)
                self.assertEqual(cases[0]["title"], "SQL Injection attempt")

    def test_t8_server_report_severity_filters_in_api(self):
        """T8. GET /api/alerts filters by severities and hours in SQL, mapping legacy levels."""
        req = MagicMock()
        req.session = {"user_id": 1, "username": "admin", "user_role": "admin"}

        with patch("app.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
            with patch("app.db.get_db_connection") as mock_conn:
                cur = MagicMock()
                cur.fetchone.return_value = {"total": 5, "count": 12}
                cur.fetchall.return_value = [
                    {"id": 1, "title": "Alert 1", "severity": "critical", "created_at": "2026-11-13 10:00:00"}
                ]
                mock_conn.return_value.cursor.return_value.__enter__.return_value = cur
                res = app.api_get_alerts(
                    request=req,
                    server_id=1,
                    severities="critical,warning",
                    hours=24
                )
                self.assertIn("items", res)
                self.assertIn("info_excluded_count", res)
                self.assertEqual(res["info_excluded_count"], 12)

    def test_t9_app_report_severity_filters_events_incidents_users(self):
        """T9. App report applies severity filter across events, incidents, and user peak severities."""
        req = MagicMock()
        req.session = {"user_id": 1, "username": "admin", "user_role": "admin"}

        payload = {
            "type": "all",
            "timeframe": "7d",
            "severities": ["critical", "warning"]
        }

        with patch("app.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
            with patch("app.get_effective_project_id", return_value=None):
                with patch("app.db.get_db_connection") as mock_conn:
                    cur = MagicMock()
                    cur.fetchone.side_effect = [
                        {"id": 1, "name": "Test App", "project_id": 1, "project_name": "Core"}, # app_row
                        {"count": 25}, # info_events_excluded
                        {"count": 2},  # total_events_in_db
                        {"count": 1},  # total_incidents_in_db
                        {"count": 1}   # total_users_in_db
                    ]
                    cur.fetchall.side_effect = [
                        [{"id": 101, "event_time": "2026-11-13", "severity": "critical", "url_path": "/test"}], # events
                        [{"id": 501, "last_event_at": "2026-11-13", "severity": "critical", "title": "Attack"}], # incidents
                        [{"identifier": "attacker1", "peak_severity": "critical", "total_requests": 10, "attack_events": 5}] # users
                    ]
                    mock_conn.return_value.cursor.return_value.__enter__.return_value = cur
                    res = app.api_generate_app_report(request=req, app_id=1, payload=payload)
                    self.assertIn("info_events_excluded", res)
                    self.assertEqual(res["info_events_excluded"], 25)
                    self.assertEqual(len(res["sections"]["events"]), 1)
                    self.assertEqual(len(res["sections"]["incidents"]), 1)
                    self.assertEqual(len(res["sections"]["users"]), 1)

    def test_t10_audit_subsystem_health_retained_and_java8_rule_removed(self):
        """T10. Asset manage page retains Audit Subsystem Health card and removes Java 8 Rule Generator."""
        with open("templates/server_detail.html", "r", encoding="utf-8") as f:
            html = f.read()

        # Retained Audit Subsystem Health card
        self.assertIn("Audit Subsystem & Attribution Health", html)
        self.assertIn("Domain User NSS Resolution", html)
        self.assertIn("Kernel Loginuid Tracking", html)
        self.assertIn("SIEM Raw Forensic Store", html)

        # Removed Java 8 Rule Generator card
        self.assertNotIn("Java 8 Audit Exclusion Rule Generator", html)
        self.assertNotIn("copyJavaRule", html)
        self.assertNotIn("ADD MANUAL SERVICE FALLBACK", html)

if __name__ == "__main__":
    unittest.main()
