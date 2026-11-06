import unittest
from unittest.mock import MagicMock, patch
from app import api_add_app_component, api_update_app_component

class TestComponentAddEdit(unittest.TestCase):

    @patch("app.get_session_user")
    @patch("app.db.get_application_by_id")
    @patch("app.db.add_application_component")
    @patch("app.db.log_audit")
    def test_add_database_component(self, mock_audit, mock_add_comp, mock_get_app, mock_get_user):
        mock_get_user.return_value = {"username": "admin", "role": "admin"}
        mock_get_app.return_value = {"id": 7, "name": "JVVNL-MITRA 1"}
        mock_add_comp.return_value = {
            "id": 101,
            "application_id": 7,
            "role": "database",
            "node_name": "Jvvnl-Mitra DB 1",
            "node_ip": "192.168.150.16",
            "target_port": "5432",
            "target_db_name": "bijlimitra",
            "enrollment_token": "abcdef0123456789",
            "status": "PENDING_APPROVAL"
        }

        mock_request = MagicMock()
        payload = {
            "role": "database",
            "node_name": "Jvvnl-Mitra DB 1",
            "node_ip": "192.168.150.16",
            "port": "5432",
            "db_name": "bijlimitra"
        }

        data = api_add_app_component(mock_request, 7, payload)

        self.assertEqual(data["id"], 101)
        self.assertEqual(data["role"], "database")
        self.assertEqual(data["node_ip"], "192.168.150.16")
        self.assertEqual(data["target_port"], "5432")
        self.assertEqual(data["target_db_name"], "bijlimitra")
        mock_add_comp.assert_called_once()
        mock_audit.assert_called_once()

    @patch("app.get_session_user")
    @patch("app.db.get_application_by_id")
    @patch("app.db.update_application_component")
    @patch("app.db.log_audit")
    def test_update_component(self, mock_audit, mock_update_comp, mock_get_app, mock_get_user):
        mock_get_user.return_value = {"username": "admin", "role": "admin"}
        mock_get_app.return_value = {"id": 7, "name": "JVVNL-MITRA 1"}
        mock_update_comp.return_value = {
            "id": 101,
            "application_id": 7,
            "role": "database",
            "node_name": "Jvvnl-Mitra DB 1 Updated",
            "node_ip": "192.168.150.16",
            "target_port": "5432",
            "target_db_name": "bijlimitra",
            "enrollment_token": "abcdef0123456789",
            "status": "RECEIVING"
        }

        mock_request = MagicMock()
        payload = {
            "role": "database",
            "node_name": "Jvvnl-Mitra DB 1 Updated",
            "node_ip": "192.168.150.16",
            "port": "5432",
            "db_name": "bijlimitra"
        }

        data = api_update_app_component(mock_request, 7, 101, payload)

        self.assertEqual(data["id"], 101)
        self.assertEqual(data["node_name"], "Jvvnl-Mitra DB 1 Updated")
        mock_update_comp.assert_called_once()
        mock_audit.assert_called_once()

if __name__ == "__main__":
    unittest.main()
