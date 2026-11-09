import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, date, timedelta
import app
import database as db

class TestFourUIReportChanges(unittest.TestCase):

    def setUp(self):
        app._known_server_ports.clear()
        app._dedup_alerts_cache.clear()

    @patch("app._create_alert_dedup")
    @patch("app._is_rule_enabled", return_value=True)
    def test_ssh_x11_forwarding_classified_as_info(self, mock_rule, mock_alert):
        """Unexpected port 6010 on loopback owned by sshd must be INFO severity with owning process evidence."""
        server_id = 101
        # Baseline port 22 is already known
        app._known_server_ports[server_id] = {22}

        # New scan detects newly opened port 6010 for SSH X11 forwarding
        ports_data = {
            "open_ports": [
                {"port": 22, "process": "sshd"},
                {
                    "port": 6010,
                    "process": "sshd",
                    "user": "root",
                    "pid": 1234,
                    "address": "127.0.0.1"
                }
            ]
        }
        app._check_port_scan(server_id, ports_data)

        self.assertEqual(mock_alert.call_count, 1)
        args, kwargs = mock_alert.call_args
        # args: (server_id, alert_type, severity, title, message)
        self.assertEqual(args[0], 101)
        self.assertEqual(args[1], "PORT_SCAN_6010")
        self.assertEqual(args[2], "info")  # Severity must be INFO!
        self.assertIn("SSH X11 Forwarding", args[3])
        self.assertIn("sshd", args[4])
        self.assertIn("127.0.0.1", args[4])
        self.assertIn("1234", args[4])

    @patch("app._create_alert_dedup")
    @patch("app._is_rule_enabled", return_value=True)
    def test_unexpected_port_non_loopback_is_warning(self, mock_rule, mock_alert):
        """Unexpected port on non-loopback address must be WARNING severity."""
        server_id = 102
        # Baseline port 22 is already known
        app._known_server_ports[server_id] = {22}

        ports_data = {
            "open_ports": [
                {"port": 22, "process": "sshd"},
                {
                    "port": 9999,
                    "process": "custom_daemon",
                    "user": "appuser",
                    "pid": 5678,
                    "address": "0.0.0.0"
                }
            ]
        }
        app._check_port_scan(server_id, ports_data)

        self.assertEqual(mock_alert.call_count, 1)
        args, kwargs = mock_alert.call_args
        self.assertEqual(args[0], 102)
        self.assertEqual(args[1], "PORT_SCAN_9999")
        self.assertEqual(args[2], "warning")  # Non-loopback unexpected port must be WARNING!
        self.assertIn("Unexpected Port Opened", args[3])
        self.assertIn("custom_daemon", args[4])
        self.assertIn("5678", args[4])

    @patch("database.get_db_connection")
    def test_unread_count_never_counts_closed_incidents(self, mock_conn):
        """Verify unread count query explicitly filters out closed, resolved, and merged incidents."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {"count": 5}
        mock_conn.return_value.cursor.return_value.__enter__.return_value = mock_cursor

        count = db.get_unread_alerts_count(project_id=1)
        self.assertEqual(count, 5)

        sql_executed = mock_cursor.execute.call_args[0][0]
        # Query must filter out closed/resolved and check is_read = FALSE
        self.assertIn("NOT IN ('closed', 'resolved', 'merged')", sql_executed)
        self.assertIn("COALESCE(i.is_read, FALSE) = FALSE", sql_executed)

    @patch("database.get_db_connection")
    def test_bulk_incident_action_mark_read_and_close(self, mock_conn):
        """Verify bulk_incident_action operates in a transaction and writes audit log."""
        mock_cursor = MagicMock()
        mock_cursor.rowcount = 3
        mock_conn.return_value.__enter__.return_value = mock_conn.return_value
        mock_conn.return_value.cursor.return_value.__enter__.return_value = mock_cursor

        res = db.bulk_incident_action(
            ids=[10, 11, 12],
            action="close",
            username="analyst_bob",
            note="Verified administrative activity"
        )
        self.assertTrue(res["ok"])
        self.assertEqual(res["processed"], 3)

        # Audit log was executed
        audit_calls = [c for c in mock_cursor.execute.call_args_list if "INSERT INTO audit_logs" in c[0][0]]
        self.assertTrue(len(audit_calls) > 0)
        self.assertIn("analyst_bob", audit_calls[0][0][1])

    @patch("database.get_db_connection")
    def test_bulk_vulnerability_action_closed_with_risk_acceptance(self, mock_conn):
        """Verify closing vulnerability rows records risk approver and expiry date."""
        mock_cursor = MagicMock()
        mock_cursor.rowcount = 2
        mock_conn.return_value.__enter__.return_value = mock_conn.return_value
        mock_conn.return_value.cursor.return_value.__enter__.return_value = mock_cursor

        res = db.bulk_vulnerability_action(
            ids=[201, 202],
            action="close",
            username="lead_sec",
            reason="Accepted risk",
            note="Legacy system replacement scheduled Q4",
            expiry_date="2026-12-31",
            approver="VP of Security"
        )
        self.assertTrue(res["ok"])
        self.assertEqual(res["processed"], 2)

        update_calls = [c for c in mock_cursor.execute.call_args_list if "UPDATE server_vulnerabilities" in c[0][0]]
        self.assertTrue(len(update_calls) > 0)
        self.assertIn("close_reason", update_calls[0][0][0])
        self.assertIn("risk_expiry_date", update_calls[0][0][0])
        self.assertIn("risk_approver", update_calls[0][0][0])

if __name__ == '__main__':
    unittest.main()
