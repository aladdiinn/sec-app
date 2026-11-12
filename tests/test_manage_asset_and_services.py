import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import json, time, hmac, hashlib, uuid, os

# Set test environment
os.environ["TESTING"] = "1"
os.environ["SECRET_KEY"] = "test-secret-key-32-chars-long-abc"
os.environ["DB_PASSWORD"] = "testpassword"

import database as db
import app
import types, sys

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

    def test_t1_manage_button_on_total_assets_and_maintenance(self):
        """T1. Every card on Total Assets has Manage and opens the same page as Maintenance page button."""
        # 1. Total Assets (servers.html)
        with open("templates/servers.html", "r", encoding="utf-8") as f:
            servers_html = f.read()
        self.assertIn("MANAGE ASSET", servers_html)
        self.assertIn("/servers/${id}?from=assets", servers_html)

        # 2. Maintenance page (maintenance.html)
        with open("templates/maintenance.html", "r", encoding="utf-8") as f:
            maint_html = f.read()
        self.assertIn("Manage Asset", maint_html)
        self.assertIn("/servers/${s.id}?from=maintenance", maint_html)

        # 3. Both open /servers/<id> and server_detail has back navigation
        with open("templates/server_detail.html", "r", encoding="utf-8") as f:
            detail_html = f.read()
        self.assertIn("goBack()", detail_html)
        self.assertIn("'maintenance'", detail_html)

    def test_t2_service_discovery_and_system_noise_filtering(self):
        """T2. Fresh server install discovers user services; system noise is flagged as is_system."""
        from extracted_agent_test import discover_services, known_services

        # Mock systemctl output with Tomcat, Nginx, PostgreSQL, Cron, SSHD
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
        
        # User-facing services
        self.assertIn("nginx", srv_by_name)
        self.assertFalse(srv_by_name["nginx"]["is_system"], "Nginx should not be flagged as system noise")
        self.assertEqual(srv_by_name["nginx"]["type"], "Nginx")
        self.assertEqual(srv_by_name["nginx"]["status"], "running")

        self.assertIn("postgresql", srv_by_name)
        self.assertFalse(srv_by_name["postgresql"]["is_system"], "PostgreSQL should not be system noise")

        # System noise services
        self.assertIn("ssh", srv_by_name)
        self.assertTrue(srv_by_name["ssh"]["is_system"], "SSH should be flagged as system noise")
        self.assertTrue(srv_by_name["securepulse"]["is_system"], "Monitoring agent should be flagged as system noise")

    def test_t3_admin_restart_stop_start_and_verification(self):
        """T3. As admin: Restart, Stop, Start executed safely with status verification."""
        from extracted_agent_test import execute_agent_tasks, task_results_queue, known_services, AGENT_TOKEN

        known_services["unit:nginx.service"] = {
            "id": "unit:nginx.service",
            "name": "nginx",
            "type": "Nginx",
            "managed_by": "systemd",
            "unit_name": "nginx.service",
            "status": "running",
            "is_system": False
        }

        tid = "task-restart-001"
        action = "restart"
        sid = "unit:nginx.service"
        nonce = uuid.uuid4().hex[:16]
        now_ts = int(time.time())
        recipe_hash = hashlib.sha256("".encode('utf-8')).hexdigest()[:16]
        sig_str = f"{tid}:{action}:{sid}:nginx.service:root:{recipe_hash}:{nonce}:{now_ts}"
        sig = hmac.new(AGENT_TOKEN.encode("utf-8"), sig_str.encode("utf-8"), hashlib.sha256).hexdigest()

        task = {
            "task_id": tid,
            "action": action,
            "service_id": sid,
            "managed_by": "systemd",
            "unit_name": "nginx.service",
            "nonce": nonce,
            "timestamp": now_ts,
            "signature": sig
        }

        with patch("subprocess.run") as mock_run:
            with patch("time.sleep"):
                mock_res_chk = MagicMock(returncode=0, stdout="syntax ok\n", stderr="")
                mock_res1 = MagicMock(returncode=0, stdout="Restarted", stderr="")
                mock_res2 = MagicMock(returncode=0, stdout="active\n", stderr="")
                mock_run.side_effect = [mock_res_chk, mock_res1, mock_res2, MagicMock(returncode=0, stdout="")]
                execute_agent_tasks([task])

        self.assertEqual(len(task_results_queue), 1)
        res = task_results_queue.pop(0)
        self.assertEqual(res["task_id"], tid)
        self.assertIn(res["status"], ("completed", "succeeded"))
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("active", res["output"])

    def test_t4_non_admin_authorization_enforcement_and_denied_audit(self):
        """T4. Non-admin caller receives 403 Forbidden and DENIED audit entry is logged."""
        req = MagicMock()
        req.session = {"user_id": 99, "username": "test_normal_user", "user_role": "normal"}
        req.client.host = "192.168.1.50"
        async def mock_json():
            return {"service_id": "unit:nginx.service", "action": "restart"}
        req.json = mock_json

        with patch("app.get_session_user", return_value={"id": 99, "username": "test_normal_user", "role": "normal"}):
            with patch("app.is_admin_user", return_value=False):
                with patch.object(app.db, "log_audit") as mock_log_audit:
                    res = self._run_coro(app.api_service_action(server_id=1, request=req))
                    self.assertEqual(res.status_code, 403)
                    mock_log_audit.assert_called_with(
                        "test_normal_user", "DENIED", "server", 1,
                        "Non-admin attempted service action", ip_address="192.168.1.50"
                    )

    def test_t5_protected_services_cannot_be_stopped(self):
        """T5. Trying to stop sshd or the agent is refused with a clear message."""
        for protected in ["unit:sshd.service", "securepulse", "systemd-networkd"]:
            req = MagicMock()
            req.session = {"user_id": 1, "username": "admin", "user_role": "admin"}
            req.client.host = "127.0.0.1"
            def make_json(p):
                async def mock_json():
                    return {"service_id": p, "action": "stop", "reason": "Testing"}
                return mock_json
            req.json = make_json(protected)

            with patch("app.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
                with patch("app.is_admin_user", return_value=True):
                    with patch("app.verify_server_project_scope", return_value=(True, "")):
                        res = self._run_coro(app.api_service_action(server_id=1, request=req))
                        self.assertEqual(res.status_code, 400)
                        body = json.loads(res.body.decode("utf-8"))
                        self.assertFalse(body["ok"])
                        self.assertIn("Protected system service", body["message"])

    def test_t6_tampered_request_with_shell_injection_rejected(self):
        """T6. Tampered request with shell string in fields is rejected by API and agent."""
        # API check
        req = MagicMock()
        req.session = {"user_id": 1, "username": "admin", "user_role": "admin"}
        req.client.host = "127.0.0.1"
        async def mock_json():
            return {"service_id": "nginx; rm -rf /", "action": "restart"}
        req.json = mock_json

        with patch("app.get_session_user", return_value={"id": 1, "username": "admin", "role": "admin"}):
            with patch("app.is_admin_user", return_value=True):
                with patch("app.verify_server_project_scope", return_value=(True, "")):
                    with patch.object(app.db, "log_audit"):
                        res = self._run_coro(app.api_service_action(server_id=1, request=req))
                        self.assertEqual(res.status_code, 400)
                        body = json.loads(res.body.decode("utf-8"))
                        self.assertIn("Illegal shell characters", body["message"])

        # Agent check
        from extracted_agent_test import execute_agent_tasks, task_results_queue, AGENT_TOKEN
        tid = "task-tamper-01"
        sid = "unit:app;reboot"
        nonce = uuid.uuid4().hex[:16]
        ts = int(time.time())
        recipe_hash = hashlib.sha256("".encode('utf-8')).hexdigest()[:16]
        sig = hmac.new(AGENT_TOKEN.encode("utf-8"), f"{tid}:restart:{sid}:app;reboot:root:{recipe_hash}:{nonce}:{ts}".encode("utf-8"), hashlib.sha256).hexdigest()

        task = {
            "task_id": tid, "action": "restart", "service_id": sid, "managed_by": "systemd",
            "unit_name": "app;reboot", "nonce": nonce, "timestamp": ts, "signature": sig
        }
        execute_agent_tasks([task])
        self.assertEqual(len(task_results_queue), 1)
        r = task_results_queue.pop(0)
        self.assertIn(r["status"], ("failed", "rejected"))
        self.assertIn("Illegal shell injection", r["output"])

    def test_t7_expired_and_replayed_commands_rejected(self):
        """T7. Replayed or expired signed command is rejected by the agent."""
        from extracted_agent_test import execute_agent_tasks, task_results_queue, AGENT_TOKEN

        # 1. Expired command (> 60s ago)
        tid = "task-exp-01"
        sid = "unit:nginx.service"
        nonce = "nonce-exp-1"
        old_ts = int(time.time()) - 120
        recipe_hash = hashlib.sha256("".encode('utf-8')).hexdigest()[:16]
        sig = hmac.new(AGENT_TOKEN.encode("utf-8"), f"{tid}:restart:{sid}:::root:{recipe_hash}:{nonce}:{old_ts}".encode("utf-8"), hashlib.sha256).hexdigest()

        task = {"task_id": tid, "action": "restart", "service_id": sid, "nonce": nonce, "timestamp": old_ts, "signature": sig}
        execute_agent_tasks([task])
        r1 = task_results_queue.pop(0)
        self.assertEqual(r1["status"], "failed")
        self.assertIn("expired", r1["output"])

        # 2. Replay attack: execute valid command, then re-send same nonce
        tid2 = "task-replay-01"
        nonce2 = "unique-nonce-12345"
        curr_ts = int(time.time())
        sig2 = hmac.new(AGENT_TOKEN.encode("utf-8"), f"{tid2}:rescan:all::root:{recipe_hash}:{nonce2}:{curr_ts}".encode("utf-8"), hashlib.sha256).hexdigest()

        task2 = {"task_id": tid2, "action": "rescan", "service_id": "all", "nonce": nonce2, "timestamp": curr_ts, "signature": sig2}
        with patch("extracted_agent_test.discover_services"):
            execute_agent_tasks([task2])
        r2 = task_results_queue.pop(0)
        self.assertIn(r2["status"], ("completed", "succeeded"))

        # Now replay the exact same task
        execute_agent_tasks([task2])
        r3 = task_results_queue.pop(0)
        self.assertEqual(r3["status"], "failed")
        self.assertIn("duplicate nonce", r3["output"])

    def test_t8_unexpected_stop_raises_alert_dashboard_stop_does_not(self):
        """T8. Killing managed service outside dashboard raises alert; intentional stop does not."""
        pinned = [{"name": "Tomcat", "user": "tomcat", "path": "/opt/tomcat/bin/startup.sh"}]
        prev_detected = [{"id": "proc:tomcat-tomcat", "name": "Tomcat", "status": "running"}]
        new_detected = [{"id": "proc:tomcat-tomcat", "name": "Tomcat", "status": "stopped"}]

        # Scenario A: Unexpected crash (no intentional stop task)
        with patch("database.get_detected_services", return_value=prev_detected):
            with patch("database.get_managed_services", return_value=pinned):
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

        # Scenario B: Intentional dashboard stop (task exists)
        with patch("database.get_detected_services", return_value=prev_detected):
            with patch("database.get_managed_services", return_value=pinned):
                with patch("database.get_server_by_id", return_value={"hostname": "soc-server", "is_maintenance": False}):
                    with patch("database.log_alert") as mock_alert:
                        with patch("database.get_db_connection") as mock_conn:
                            cur = MagicMock()
                            cur.fetchone.return_value = {"id": 10}
                            mock_conn.return_value.cursor.return_value.__enter__.return_value = cur
                            db.save_detected_services(server_id=1, services_list=new_detected)
                            mock_alert.assert_not_called()

    def test_t9_log_analyzer_removed_from_server_detail_retained_in_log_monitor(self):
        """T9. Log Analyzer section is removed from asset page; Log Monitor page retains full management."""
        with open("templates/server_detail.html", "r", encoding="utf-8") as f:
            srv_detail = f.read()
        self.assertNotIn("LOG ANALYZER CONFIGURATION (APPLICATION LOG SOURCES)", srv_detail)
        self.assertNotIn("loadSrvDetailLogSources", srv_detail)
        self.assertNotIn("+ ADD APPLICATION LOG SOURCE", srv_detail)

        with open("templates/log_monitor.html", "r", encoding="utf-8") as f:
            log_monitor = f.read()
        self.assertIn("/api/log-monitor/configs", log_monitor)
        self.assertIn("+ ADD APP", log_monitor)

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

    def test_t10_all_actions_logged_to_audit_log(self):
        """T10. Every service action appears in the Audit Log with user, IP, and result."""
        req = MagicMock()
        req.session = {"user_id": 1, "username": "mannan", "user_role": "admin"}
        req.client.host = "10.0.0.15"
        async def mock_json():
            return {"service_id": "unit:nginx.service", "action": "stop", "reason": "Kernel maintenance"}
        req.json = mock_json

        detected = [{"id": "unit:nginx.service", "name": "nginx", "unit_name": "nginx.service", "status": "running"}]

        with patch("app.get_session_user", return_value={"id": 1, "username": "mannan", "role": "admin"}):
            with patch("app.is_admin_user", return_value=True):
                with patch("app.verify_server_project_scope", return_value=(True, "")):
                    with patch.object(app.db, "get_detected_services", return_value=detected):
                        with patch.object(app.db, "get_managed_services", return_value=[]):
                            with patch.object(app.db, "get_recent_service_action", return_value=None):
                                with patch.object(app.db, "create_agent_task", return_value="task-audit-123"):
                                    with patch.object(app.db, "log_audit") as mock_audit:
                                        res = self._run_coro(app.api_service_action(server_id=1, request=req))
                                        self.assertEqual(res["ok"], True)
                                        mock_audit.assert_called_with(
                                            "mannan", "SERVICE_ACTION_REQUESTED", "server", 1,
                                            "Queued 'stop' for service 'unit:nginx.service'. Reason: Kernel maintenance",
                                            ip_address="10.0.0.15"
                                        )

    def test_t11_poll_returns_signed_task_and_refuses_invalid_signature(self):
        """T11. Polling returns a cryptographically signed task; invalid signature or missing secret is refused."""
        mock_task = {
            "id": 101, "task_id": "task-test-poll-999", "action": "restart",
            "service_id": "unit:cron.service", "managed_by": "systemd",
            "unit_name": "cron.service", "container_id": None,
            "restart_cmd": None, "run_user": "root"
        }
        mock_server = {
            "id": 1, "hostname": "soc-server", "ip_address": "192.168.10.201",
            "agent_token": "sp-token-poll-test-key", "status": "online"
        }

        req = MagicMock()
        async def mock_json():
            return {"server_id": 1, "agent_version": "1.7.0", "server_ip": "192.168.10.201"}
        req.json = mock_json
        req.client.host = "192.168.10.201"

        with patch.object(app.db, "get_server_by_ip", return_value=mock_server):
            with patch.object(app.db, "get_server_by_id", return_value=mock_server):
                with patch.object(app.db, "get_pending_agent_tasks", return_value=[mock_task]):
                    with patch.object(app.db, "mark_tasks_dispatched") as mock_dispatched:
                        res = self._run_coro(app.api_agent_tasks_poll(req))
                        self.assertTrue(res["ok"])
                        self.assertEqual(len(res["tasks"]), 1)
                        signed_task = res["tasks"][0]
                        self.assertEqual(signed_task["task_id"], "task-test-poll-999")
                        self.assertIn("signature", signed_task)
                        self.assertIn("nonce", signed_task)
                        self.assertIn("timestamp", signed_task)
                        mock_dispatched.assert_called_once_with(["task-test-poll-999"], 1)

                        # Verify signature matches expected HMAC
                        nonce = signed_task["nonce"]
                        ts = signed_task["timestamp"]
                        recipe_hash = hashlib.sha256("".encode('utf-8')).hexdigest()[:16]
                        expected_payload = f"task-test-poll-999:restart:unit:cron.service:cron.service:root:{recipe_hash}:{nonce}:{ts}"
                        expected_sig = hmac.new("sp-token-poll-test-key".encode('utf-8'), expected_payload.encode('utf-8'), hashlib.sha256).hexdigest()
                        self.assertEqual(signed_task["signature"], expected_sig)

        # Verify agent verification of valid vs invalid signature
        from extracted_agent_test import execute_agent_tasks, task_results_queue

        # 1. Tampered signature
        bad_task = dict(signed_task)
        bad_task["signature"] = "deadbeef" * 8
        execute_agent_tasks([bad_task])
        self.assertEqual(len(task_results_queue), 1)
        r_bad = task_results_queue.pop(0)
        self.assertEqual(r_bad["status"], "failed")
        self.assertEqual(r_bad["reject_reason"], "bad_signature")

        # 2. Tampered unit name (with a unique nonce so signature mismatch is tested)
        tampered_unit_task = dict(signed_task)
        tampered_unit_task["unit_name"] = "tampered.service"
        tampered_unit_task["nonce"] = uuid.uuid4().hex[:16]
        execute_agent_tasks([tampered_unit_task])
        self.assertEqual(len(task_results_queue), 1)
        r_tamp = task_results_queue.pop(0)
        self.assertEqual(r_tamp["status"], "failed")
        self.assertEqual(r_tamp["reject_reason"], "bad_signature")

if __name__ == "__main__":
    unittest.main()
