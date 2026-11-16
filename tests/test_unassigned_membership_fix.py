import unittest
from unittest.mock import MagicMock, patch
import database as db

class TestUnassignedFixes(unittest.TestCase):
    def test_build_pid_filter_unassigned_matches_null(self):
        with patch.object(db, 'is_unassigned_project', return_value=True):
            with patch.object(db, 'get_unassigned_project_id', return_value=99):
                sql, params = db._build_pid_filter("s.project_id", 99)
                self.assertIn("s.project_id = %s OR s.project_id IS NULL OR s.project_id = 0", sql)
                self.assertEqual(params, [99])

    def test_build_pid_filter_unassigned_no_id(self):
        with patch.object(db, 'is_unassigned_project', return_value=True):
            with patch.object(db, 'get_unassigned_project_id', return_value=None):
                sql, params = db._build_pid_filter("s.project_id", "unassigned")
                self.assertIn("s.project_id IS NULL OR s.project_id = 0", sql)
                self.assertEqual(params, [])

    def test_get_projects_counts_null_for_unassigned(self):
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur

        mock_cur.fetchall.side_effect = [
            # 1. projects main query
            [{'id': 1, 'name': 'Unassigned', 'is_default': True, 'is_system': True}],
            # 2. assigned_groups
            [],
            # 3. assigned_users
            [],
            # 4. assigned_servers (should query WHERE project_id = %s OR project_id IS NULL OR project_id = 0)
            [{'id': 101, 'hostname': 'soc-server', 'severity': 'critical'}],
            # 5. assigned_apps
            [{'id': 201, 'name': 'JVVNL-MITRA 1', 'status': 'NORMAL'}]
        ]

        with patch.object(db, 'get_db_connection', return_value=mock_conn):
            with patch.object(db, 'get_unassigned_project_id', return_value=1):
                projs = db.get_projects()
                self.assertEqual(len(projs), 1)
                p = projs[0]
                self.assertEqual(p['server_count'], 1)
                self.assertEqual(p['app_count'], 1)
                self.assertEqual(p['assigned_servers'][0]['hostname'], 'soc-server')

if __name__ == '__main__':
    unittest.main()
