import unittest
from datetime import datetime, timezone, timedelta
import os
import sys

# Set test environment credentials for app imports
os.environ["SECRET_KEY"] = "test-secret-key-32-chars-long-security-validation"
os.environ["DB_PASSWORD"] = "test-db-password"
os.environ["POSTGRES_PASSWORD"] = "test-db-password"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestReportTimeframesAndRetention(unittest.TestCase):
    def test_parse_timeframe_range(self):
        """Verify parse_timeframe_range correctly resolves 1m, 2m, 3m, 15d, etc."""
        import app

        now = datetime.now(timezone.utc)

        # Test 1 Month (30 days)
        start, end, label = app.parse_timeframe_range("1m")
        self.assertEqual(label, "Last 1 Month")
        self.assertAlmostEqual((end - start).total_seconds(), timedelta(days=30).total_seconds(), delta=5)

        # Test 2 Months (60 days)
        start, end, label = app.parse_timeframe_range("2m")
        self.assertEqual(label, "Last 2 Months")
        self.assertAlmostEqual((end - start).total_seconds(), timedelta(days=60).total_seconds(), delta=5)

        # Test 3 Months (90 days)
        start, end, label = app.parse_timeframe_range("3m")
        self.assertEqual(label, "Last 3 Months")
        self.assertAlmostEqual((end - start).total_seconds(), timedelta(days=90).total_seconds(), delta=5)

        # Test 15 Days
        start, end, label = app.parse_timeframe_range("15d")
        self.assertEqual(label, "Last 15 Days")
        self.assertAlmostEqual((end - start).total_seconds(), timedelta(days=15).total_seconds(), delta=5)

        # Test 5 Hours
        start, end, label = app.parse_timeframe_range("5h")
        self.assertEqual(label, "Last 5 Hours")
        self.assertAlmostEqual((end - start).total_seconds(), timedelta(hours=5).total_seconds(), delta=5)

        # Test 10 Hours
        start, end, label = app.parse_timeframe_range("10h")
        self.assertEqual(label, "Last 10 Hours")
        self.assertAlmostEqual((end - start).total_seconds(), timedelta(hours=10).total_seconds(), delta=5)

        # Test 2 Days
        start, end, label = app.parse_timeframe_range("2d")
        self.assertEqual(label, "Last 2 Days")
        self.assertAlmostEqual((end - start).total_seconds(), timedelta(days=2).total_seconds(), delta=5)

        # Test 3 Days
        start, end, label = app.parse_timeframe_range("3d")
        self.assertEqual(label, "Last 3 Days")
        self.assertAlmostEqual((end - start).total_seconds(), timedelta(days=3).total_seconds(), delta=5)

    def test_default_retention_parameters(self):
        """Verify default retention in app_siem_db is 90 days (3 months)."""
        import inspect
        import app_siem_db

        # purge_expired_app_events_partitions default retention_days
        sig_purge = inspect.signature(app_siem_db.purge_expired_app_events_partitions)
        self.assertEqual(sig_purge.parameters["retention_days"].default, 90)

        # delete_old_app_events default retention_days
        sig_delete = inspect.signature(app_siem_db.delete_old_app_events)
        self.assertEqual(sig_delete.parameters["retention_days"].default, 90)

    def test_reports_html_options_and_rename(self):
        """Verify templates/reports.html has 1m, 2m, 3m in both dropdowns and uses Website Level Report."""
        reports_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates', 'reports.html'))
        with open(reports_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check options in srv-timeframe
        self.assertIn('<select id="srv-timeframe"', content)
        self.assertIn('<option value="1m">Last 1 Month</option>', content)
        self.assertIn('<option value="2m">Last 2 Months</option>', content)
        self.assertIn('<option value="3m">Last 3 Months</option>', content)

        # Check options in app-timeframe
        self.assertIn('<select id="app-timeframe"', content)
        self.assertIn('<option value="1m">Last 1 Month</option>', content)
        self.assertIn('<option value="2m">Last 2 Months</option>', content)
        self.assertIn('<option value="3m">Last 3 Months</option>', content)

        # Check Website Level Report naming
        self.assertIn("Website Level Report", content)
        self.assertNotIn("App Level Report", content)
        self.assertIn("Search Website (Name, URL, or ID)", content)
        self.assertNotIn("Search Application (Name, URL, or ID)", content)
        self.assertIn("Enter Website Name or URL e.g. hp-1", content)
        self.assertNotIn("Enter App Name or URL e.g. hp-1", content)
        self.assertIn("Website Security Posture & Metrics", content)
        self.assertNotIn("Application Security Posture & Metrics", content)

if __name__ == '__main__':
    unittest.main()
