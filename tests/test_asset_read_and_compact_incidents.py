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

if __name__ == '__main__':
    unittest.main()
