import unittest
from unittest.mock import MagicMock, patch
import app

class TestPortIncidentDedup(unittest.TestCase):

    def setUp(self):
        app._known_server_ports.clear()
        app._dedup_alerts_cache.clear()

    @patch("app._create_alert_dedup")
    @patch("app._is_rule_enabled", return_value=True)
    def test_dangerous_port_only_alerts_on_newly_opened(self, mock_rule, mock_alert):
        server_id = 99
        # 1. Initial report with port 5432
        data1 = {"open_ports": [{"port": 5432, "process": "postgres"}, {"port": 22, "process": "sshd"}]}
        app._check_port_scan(server_id, data1)

        # Should alert once on initial discovery of dangerous port
        self.assertEqual(mock_alert.call_count, 1)
        alert_type_arg = mock_alert.call_args[0][1]
        self.assertEqual(alert_type_arg, "DANGEROUS_PORT_5432")

        # 2. Subsequent report with exact same ports (port 5432 is still listening)
        mock_alert.reset_mock()
        data2 = {"open_ports": [{"port": 5432, "process": "postgres"}, {"port": 22, "process": "sshd"}]}
        app._check_port_scan(server_id, data2)

        # MUST NOT alert again since port 5432 was NOT newly opened!
        mock_alert.assert_not_called()

        # 3. Third report: port 5432 closes
        data3 = {"open_ports": [{"port": 22, "process": "sshd"}]}
        app._check_port_scan(server_id, data3)
        mock_alert.assert_not_called()

        # 4. Fourth report: port 5432 is newly re-opened!
        data4 = {"open_ports": [{"port": 5432, "process": "postgres"}, {"port": 22, "process": "sshd"}]}
        app._check_port_scan(server_id, data4)

        # Should alert because port 5432 was newly opened!
        self.assertEqual(mock_alert.call_count, 1)

if __name__ == '__main__':
    unittest.main()
