import unittest
import json
from unittest.mock import MagicMock, patch
import database as db
import app as app_module

class TestAlertDistributionAndUserMgmt(unittest.TestCase):
    def test_eval_password_strength_python(self):
        is_strong, msg = app_module.validate_password_strength("weak")
        self.assertFalse(is_strong)

        is_strong, msg = app_module.validate_password_strength("ValidPassword123!")
        self.assertTrue(is_strong)

    def test_alert_distribution_proportions(self):
        """Verify that 100 alerts feed returns ~50% critical, ~40% warning/medium, ~10% info."""
        mock_cur = MagicMock()
        crit_rows = [{"id": i, "severity": "critical", "created_at": f"2026-11-20T10:{i:02d}:00Z"} for i in range(50)]
        med_rows = [{"id": i+100, "severity": "warning", "created_at": f"2026-11-20T09:{i:02d}:00Z"} for i in range(40)]
        info_rows = [{"id": i+200, "severity": "info", "created_at": f"2026-11-20T08:{i:02d}:00Z"} for i in range(10)]

        mock_cur.fetchall.side_effect = [crit_rows, med_rows, info_rows]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur

        with patch("database.get_db_connection", return_value=mock_conn):
            alerts = db.get_alerts(limit=100)
            self.assertEqual(len(alerts), 100)
            n_crit = sum(1 for a in alerts if a["severity"] == "critical")
            n_med = sum(1 for a in alerts if a["severity"] == "warning")
            n_info = sum(1 for a in alerts if a["severity"] == "info")
            self.assertEqual(n_crit, 50)
            self.assertEqual(n_med, 40)
            self.assertEqual(n_info, 10)

    def test_asset_normalization_when_alerts_closed(self):
        """When all alerts are closed, server alert count is 0 and severity is info."""
        mock_cur = MagicMock()
        mock_cur.fetchall.return_value = [{
            "id": 40,
            "hostname": "soc-server",
            "ip": "192.168.10.201",
            "status": "online",
            "approved_by": "admin",
            "cpu_percent": 15.0,
            "memory_percent": 30.0,
            "disk_percent": 40.0,
            "alert_count": 0,
            "critical_alert_count": 0,
            "trouble_alert_count": 0,
            "computed_severity": "info"
        }]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur

        with patch("database.get_db_connection", return_value=mock_conn):
            servers = db.get_servers()
            self.assertEqual(len(servers), 1)
            srv = servers[0]
            self.assertEqual(srv["critical_alert_count"], 0)
            self.assertEqual(srv["alert_count"], 0)
            self.assertEqual(srv["severity"], "info")

if __name__ == "__main__":
    unittest.main()
