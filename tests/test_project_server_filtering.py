import os
import unittest
from unittest.mock import MagicMock, patch

os.environ["TESTING"] = "1"
os.environ["SECRET_KEY"] = "test-secret-key-32-chars-long-abc"
os.environ["DB_PASSWORD"] = "testpassword"

import database
import app

class TestProjectServerFiltering(unittest.TestCase):
    def setUp(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_vulnerabilities_template_elements(self):
        vuln_path = os.path.join(self.base_dir, "templates", "vulnerabilities.html")
        with open(vuln_path, "r", encoding="utf-8") as f:
            content = f.read()

        # 1. Project select dropdown exists
        self.assertIn('id="vuln-project-select"', content)
        self.assertIn('onchange="onVulnProjectChange(this.value)"', content)

        # 2. Server search input and suggestions dropdown exist
        self.assertIn('id="server-search-input"', content)
        self.assertIn('id="server-suggest-dropdown"', content)
        self.assertIn('id="selected-servers-bar"', content)

        # 3. JS functions for project & server cascading
        self.assertIn('function populateVulnProjectSelect()', content)
        self.assertIn('function onVulnProjectChange(', content)
        self.assertIn('function resetVulnProject()', content)
        self.assertIn('function selectAllServersInVulnScope()', content)

        # 4. Suggestions dropdown shows All Servers option
        self.assertIn('★ All Servers', content)
        self.assertIn('scopedServers', content)

        # 5. applyFilters filters by selectedProjectId
        self.assertIn('selectedProjectId', content)
        self.assertIn('fPid', content)

        # 6. Chips bar supports Project alone and Project + Server
        self.assertIn('📁 Project:', content)

    def test_alerts_template_elements(self):
        alerts_path = os.path.join(self.base_dir, "templates", "alerts.html")
        with open(alerts_path, "r", encoding="utf-8") as f:
            content = f.read()

        # 1. Project select dropdown exists
        self.assertIn('id="filter-project"', content)
        self.assertIn('onchange="onAlertsProjectChange(this.value)"', content)

        # 2. Cascading Server select exists
        self.assertIn('id="filter-server"', content)

        # 3. JS functions for project & server cascading
        self.assertIn('async function initAlertFilters()', content)
        self.assertIn('function populateAlertProjectDropdown(', content)
        self.assertIn('function populateAlertServerDropdown(', content)
        self.assertIn('function onAlertsProjectChange(', content)

        # 4. loadIncidents passes project_id and server_id
        self.assertIn('project_id=', content)
        self.assertIn('server_id=', content)

        # 5. DOMContentLoaded initializes alert filters
        self.assertIn('await initAlertFilters()', content)

    def test_backend_api_incidents_signature_and_params(self):
        import inspect
        sig = inspect.signature(app.api_get_incidents)
        self.assertIn("project_id", sig.parameters)
        self.assertIn("server_id", sig.parameters)

    def test_backend_api_fleet_cves_signature_and_params(self):
        import inspect
        sig = inspect.signature(app.api_get_fleet_cves)
        self.assertIn("project_id", sig.parameters)
        self.assertIn("server_id", sig.parameters)

    @patch("database.get_db_connection")
    def test_database_get_incidents_project_and_server_filtering(self, mock_conn):
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = {"cnt": 2, "count": 2}
        mock_cursor.fetchall.return_value = [
            {
                "id": 1,
                "title": "Test Incident 1",
                "severity": "critical",
                "status": "open",
                "server_id": 25,
                "project_id": 1,
                "project_name": "JVVNL",
                "hostname": "Jvvnl -Mitra 1",
                "server_ip": "192.168.150.15",
                "created_at": "2026-11-17 12:00:00",
                "updated_at": "2026-11-17 12:00:00"
            }
        ]
        mock_conn.return_value.cursor.return_value.__enter__.return_value = mock_cursor

        # Test project_id filter alone (Use Case 1 & 2)
        res = database.get_incidents(project_id=1)
        self.assertEqual(res["total"], 2)
        queries = [call[0][0] for call in mock_cursor.execute.call_args_list]
        self.assertTrue(any("s.project_id = %s" in q for q in queries))

        # Test project_id + server_id filter (Use Case 3)
        mock_cursor.reset_mock()
        mock_cursor.fetchone.return_value = {"cnt": 1, "count": 1}
        mock_cursor.fetchall.return_value = [
            {
                "id": 1,
                "title": "Test Incident 1",
                "severity": "critical",
                "status": "open",
                "server_id": 25,
                "project_id": 1,
                "project_name": "JVVNL",
                "hostname": "Jvvnl -Mitra 1",
                "server_ip": "192.168.150.15",
                "created_at": "2026-11-17 12:00:00",
                "updated_at": "2026-11-17 12:00:00"
            }
        ]
        res2 = database.get_incidents(project_id=1, server_id=25)
        self.assertEqual(res2["total"], 1)
        queries2 = [call[0][0] for call in mock_cursor.execute.call_args_list]
        self.assertTrue(any("s.project_id = %s" in q and "i.server_id = %s" in q for q in queries2))
        
        all_params = []
        for call in mock_cursor.execute.call_args_list:
            if len(call[0]) > 1:
                all_params.extend(call[0][1])
        self.assertIn(1, all_params)
        self.assertIn(25, all_params)

if __name__ == "__main__":
    unittest.main()
