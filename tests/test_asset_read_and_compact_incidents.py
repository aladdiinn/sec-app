import os
import unittest
from unittest.mock import MagicMock, patch

class TestAssetReadAndCompactIncidents(unittest.TestCase):
    def setUp(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_templates_contain_required_read_and_compact_elements(self):
        # 1. dashboard.html
        dash_path = os.path.join(self.base_dir, "templates", "dashboard.html")
        with open(dash_path, "r", encoding="utf-8") as f:
            dash_content = f.read()
        self.assertIn("i3-header-btn-read", dash_content)
        self.assertIn("i3-settings-btn-read", dash_content)
        self.assertIn("modal-density-compact", dash_content)
        self.assertIn("modal-density-comfortable", dash_content)
        self.assertIn("deduplicateAssetAlerts", dash_content)
        self.assertIn("renderModalIncidentsList", dash_content)
        self.assertIn("toggleCurrentServerRead", dash_content)
        self.assertIn("badge-read-tag", dash_content)
        # Check problem filter excludes read assets
        self.assertIn("item.isRead", dash_content)

        # 2. servers.html
        srv_path = os.path.join(self.base_dir, "templates", "servers.html")
        with open(srv_path, "r", encoding="utf-8") as f:
            srv_content = f.read()
        self.assertIn("i3-header-btn-read", srv_content)
        self.assertIn("i3-settings-btn-read", srv_content)
        self.assertIn("modal-density-compact", srv_content)
        self.assertIn("modal-density-comfortable", srv_content)
        self.assertIn("deduplicateAssetAlerts", srv_content)
        self.assertIn("renderModalIncidentsList", srv_content)
        self.assertIn("badge-read-tag", srv_content)

        # 3. apps.html
        apps_path = os.path.join(self.base_dir, "templates", "apps.html")
        with open(apps_path, "r", encoding="utf-8") as f:
            apps_content = f.read()
        self.assertIn("badge-read-tag", apps_content)

        # 4. app_detail_modal.html
        app_modal_path = os.path.join(self.base_dir, "templates", "app_detail_modal.html")
        with open(app_modal_path, "r", encoding="utf-8") as f:
            modal_content = f.read()
        self.assertIn("pop-btn-read", modal_content)
        self.assertIn("pop-settings-btn-read", modal_content)
        self.assertIn("toggleCurrentAppRead", modal_content)
        self.assertIn("pop-settings-read-status", modal_content)
        self.assertIn("Dashboard Attention &amp; Read Status", modal_content)

        # 5. theme.css
        theme_path = os.path.join(self.base_dir, "static", "css", "theme.css")
        with open(theme_path, "r", encoding="utf-8") as f:
            theme_content = f.read()
        self.assertIn(".inc-compact-row", theme_content)
        self.assertIn(".density-compact", theme_content)
        self.assertIn(".density-comfortable", theme_content)
        self.assertIn(".badge-read-tag", theme_content)

    def test_ssh_x11_port_recognition_logic(self):
        import database
        # Verify merge_duplicate_incidents_with_audit exists
        self.assertTrue(hasattr(database, "merge_duplicate_incidents_with_audit"))
        self.assertTrue(hasattr(database, "toggle_server_read"))
        self.assertTrue(hasattr(database, "toggle_app_read"))

    def test_app_endpoints_exist(self):
        import app
        routes = [r.path for r in app.app.routes]
        self.assertIn("/api/servers/{id}/read", routes)
        self.assertIn("/api/apps/{id}/read", routes)


    def test_auto_prune_and_compact_app_events(self):
        import app_siem_db
        self.assertTrue(hasattr(app_siem_db, 'auto_prune_and_compact_app_events'))
        from unittest.mock import MagicMock
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur
        mock_cur.rowcount = 42

        res = app_siem_db.auto_prune_and_compact_app_events(mock_conn)
        self.assertEqual(res, 42)
        mock_conn.commit.assert_called()


    def test_user_deletion_actor_attribution_never_unknown(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        # Test Case 1: Correlated with sudo_events
        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "log_lines": ["Nov 9 18:20:25 ubuntu-DEV userdel[400722]: delete user 'prajwal'"],
                "sudo_events": [{"line": "sudo:   ubuntu : TTY=pts/0 ; PWD=/application/Soc ; USER=root ; COMMAND=/usr/sbin/userdel prajwal"}],
                "commands": [],
                "audit_events": []
            }
            app._check_sudo_misuse(1, data)
            self.assertTrue(len(created_alerts) >= 1)
            self.assertIn("ubuntu", created_alerts[0]["title"])
            self.assertNotIn("Unknown", created_alerts[0]["title"])
            self.assertIn("userdel prajwal", created_alerts[0]["message"])

        # Test Case 2: Standalone userdel with root execution (no unprivileged user)
        created_alerts.clear()
        app._last_known_server_user.clear()
        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "log_lines": ["Nov 9 18:20:25 ubuntu-DEV userdel[400722]: delete user 'prajwal'"],
                "sudo_events": [],
                "commands": [],
                "audit_events": []
            }
            app._check_sudo_misuse(1, data)
            self.assertTrue(len(created_alerts) >= 1)
            self.assertIn("root", created_alerts[0]["title"])
            self.assertNotIn("Unknown", created_alerts[0]["title"])

    def test_process_pid_brackets_never_treated_as_port(self):
        import database
        from unittest.mock import MagicMock, patch

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur
        
        # Row with syslog PID in description
        mock_cur.fetchall.return_value = [{
            "id": 885,
            "server_id": 1,
            "title": "User Account Deletion — root",
            "description": "User 'root' executed: userdel[400722]: delete user 'prajwal'",
            "severity": "critical",
            "status": "open",
            "evidence_data": None,
            "occurrences": 1,
            "first_seen": "2026-11-09 18:20:25",
            "last_seen": "2026-11-09 18:20:25",
            "created_at": "2026-11-09 18:20:25"
        }]

        with patch.object(database, 'get_db_connection', return_value=mock_conn):
            database.merge_duplicate_incidents_with_audit(1)
            # Ensure UPDATE does NOT inject port 400722 into evidence
            calls = [c[0] for c in mock_cur.execute.call_args_list]
            for call_args in calls:
                sql = call_args[0] if len(call_args) > 0 else ""
                params = call_args[1] if len(call_args) > 1 else ()
                if "UPDATE incidents" in sql and "evidence_data" in sql and len(params) > 4:
                    ev_str = str(params[4])
                    self.assertNotIn("400722", ev_str)
                    self.assertNotIn("DET-NET-010", ev_str)

    def test_audit_app_mod_and_identity_alerts_fire_properly(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "file_changes": [],
                "audit_events": [
                    {
                        "key": "app_mod",
                        "username": "mannan",
                        "auid": "1002",
                        "line": 'type=SYSCALL arch=c000003e syscall=257 success=yes exe="/usr/bin/touch" comm="touch" name="/application/Soc/config.py" auid=1002'
                    },
                    {
                        "key": "identity",
                        "username": "root",
                        "auid": "0",
                        "line": 'type=SYSCALL arch=c000003e syscall=257 success=yes exe="/usr/bin/passwd" comm="passwd" name="/etc/shadow" auid=0'
                    }
                ],
                "log_lines": [],
                "sudo_events": [],
                "commands": []
            }
            app._check_unified_fim(1, data)
            titles = [a["title"] for a in created_alerts]
            self.assertTrue(any("App Mod Alert by mannan" in t for t in titles), f"App Mod Alert by mannan missing in {titles}")
            self.assertTrue(any("Identity Alert by" in t for t in titles), f"Identity Alert missing in {titles}")

    def test_passwd_command_detection_triggers_credential_alert(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "log_lines": ["Nov 9 18:25:01 ubuntu-DEV passwd[401200]: password updated successfully"],
                "sudo_events": [],
                "commands": [{"user": "mannan", "command": "passwd"}],
                "audit_events": []
            }
            app._check_sudo_misuse(1, data)
            self.assertTrue(len(created_alerts) >= 1)
            self.assertIn("User Password Modified", created_alerts[0]["title"])
            self.assertIn("mannan", created_alerts[0]["title"])

    def test_audit_loop_does_not_abort_on_background_noise(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "file_changes": [],
                "audit_events": [
                    # First event: bash history noise (must be skipped with continue, NOT aborting the whole loop)
                    {
                        "key": "home_mod",
                        "username": "ubuntu",
                        "auid": "1000",
                        "line": 'type=SYSCALL exe="/bin/bash" comm="bash" name="/home/ubuntu/.bash_history" auid=1000'
                    },
                    # Second event: real app_mod modification
                    {
                        "key": "app_mod",
                        "username": "mannan",
                        "auid": "1002",
                        "line": 'type=SYSCALL exe="/bin/nano" comm="nano" name="/application/Soc/app.py" auid=1002'
                    }
                ],
                "log_lines": [],
                "sudo_events": [],
                "commands": []
            }
            app._check_unified_fim(1, data)
            titles = [a["title"] for a in created_alerts]
            self.assertTrue(any("App Mod Alert by mannan" in t for t in titles), f"App Mod Alert by mannan should fire despite bash_history noise: {titles}")

    def test_user_deletion_correlated_with_audit_user_in_root(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "log_lines": ["Nov 9 18:20:25 ubuntu-DEV userdel[400722]: delete user 'prajwal'"],
                "sudo_events": [],
                "commands": [],
                "audit_events": [
                    {
                        "key": "identity",
                        "username": "mannan",
                        "auid": "1002",
                        "line": 'type=SYSCALL arch=c000003e syscall=257 success=yes exe="/usr/sbin/userdel" comm="userdel" auid=1002 uid=0 name="/etc/shadow"'
                    }
                ]
            }
            app._check_sudo_misuse(1, data)
            self.assertTrue(len(created_alerts) >= 1)
            self.assertEqual(created_alerts[0]["title"], "User Account Deletion — mannan")
            self.assertIn("by user 'mannan' executed:", created_alerts[0]["message"])
            self.assertIn("delete user 'prajwal'", created_alerts[0]["message"])


    def test_passwd_modification_triggers_identity_alert_not_fim(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "file_changes": [
                    {"path": "/etc/passwd", "type": "modified", "detail": "Content or metadata changed"}
                ],
                "audit_events": [],
                "log_lines": [],
                "sudo_events": [],
                "commands": []
            }
            app._check_unified_fim(1, data)
            self.assertTrue(len(created_alerts) >= 1)
            self.assertEqual(created_alerts[0]["title"], "Identity Alert by mannan")
            self.assertTrue(created_alerts[0]["alert_type"].startswith("AUDIT_identity_"))
            self.assertIn("Detection Rule [Kernel Audit]: identity event triggered by user 'mannan'", created_alerts[0]["message"])

if __name__ == '__main__':
    unittest.main()
