import unittest
from unittest.mock import MagicMock, patch
import json
import gzip
import s3_archiver

class TestS3StreamingAndFiltering(unittest.TestCase):

    def test_routine_access_log_detection(self):
        # Standard routine 200/304 access logs -> True
        clf_200 = '192.168.1.10 - - [09/Nov/2026:10:00:00 +0000] "GET /dashboard HTTP/1.1" 200 4521'
        is_routine, status, path = s3_archiver.is_routine_access_log(clf_200)
        self.assertTrue(is_routine)
        self.assertEqual(status, 200)

        clf_304 = '10.0.0.5 - - [09/Nov/2026:10:00:00 +0000] "GET /static/css/style.css HTTP/1.1" 304 0'
        is_routine, status, path = s3_archiver.is_routine_access_log(clf_304)
        self.assertTrue(is_routine)
        self.assertEqual(status, 304)

        # Attacks must NOT be treated as routine even if status is 200
        sqli_200 = '10.0.0.5 - - [09/Nov/2026:10:00:00 +0000] "GET /search?q=1%27+UNION+SELECT+null HTTP/1.1" 200 1200'
        is_routine, status, path = s3_archiver.is_routine_access_log(sqli_200)
        self.assertFalse(is_routine)

        traversal_200 = '10.0.0.5 - - [09/Nov/2026:10:00:00 +0000] "GET /view?file=../../etc/passwd HTTP/1.1" 200 500'
        is_routine, status, path = s3_archiver.is_routine_access_log(traversal_200)
        self.assertFalse(is_routine)

        # 4xx and 5xx errors must NOT be treated as routine (they are security/probe candidates)
        err_404 = '10.0.0.5 - - [09/Nov/2026:10:00:00 +0000] "GET /wp-admin HTTP/1.1" 404 150'
        is_routine, status, path = s3_archiver.is_routine_access_log(err_404)
        self.assertFalse(is_routine)

        err_401 = '10.0.0.5 - - [09/Nov/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 401 200'
        is_routine, status, path = s3_archiver.is_routine_access_log(err_401)
        self.assertFalse(is_routine)

    def test_repetitive_app_warning_filtering(self):
        # Repetitive background warning without user/IP -> True (filter out of DB)
        warn_log = "2026-11-09 10:15:00 WARN [org.springframework.cache] Cache evict threshold reached, refreshing background cache"
        self.assertTrue(s3_archiver.is_repetitive_app_warning(warn_log, source="catalina.out", log_type="tomcat"))

        # Repetitive generic framework exception without user/IP -> True
        exc_log = "2026-11-09 10:15:00 EXCEPTION java.lang.NullPointerException at com.example.service.HealthCheckService.check(HealthCheckService.java:42)"
        self.assertTrue(s3_archiver.is_repetitive_app_warning(exc_log, source="catalina.out", log_type="tomcat"))

        # Warning WITH user -> False (must stay in DB for security audit)
        user_warn = "2026-11-09 10:15:00 WARN [AuthService] user: admin password retry exceeded"
        self.assertFalse(s3_archiver.is_repetitive_app_warning(user_warn, source="catalina.out", log_type="tomcat"))

        # Warning WITH remote client IP -> False (must stay in DB for threat tracing)
        ip_warn = "2026-11-09 10:15:00 WARN [SecurityFilter] Rate limit exceeded from 198.51.100.25"
        self.assertFalse(s3_archiver.is_repetitive_app_warning(ip_warn, source="catalina.out", log_type="tomcat"))

        # Security-critical attacks (SQLException, Auth failure) -> False
        sql_err = "2026-11-09 10:15:00 SEVERE org.postgresql.util.PSQLException: ERROR: syntax error at or near 'SELECT'"
        self.assertFalse(s3_archiver.is_repetitive_app_warning(sql_err, source="catalina.out", log_type="tomcat"))

        auth_fail = "2026-11-09 10:15:00 WARN Authentication failed for invalid credentials"
        self.assertFalse(s3_archiver.is_repetitive_app_warning(auth_fail, source="catalina.out", log_type="tomcat"))

    def test_s3_streaming_strictly_for_asset_level_logs(self):
        # Verify that S3 is ONLY for asset-level logs (server_id present) and ignores non-asset calls
        mock_s3 = MagicMock()
        with patch.object(s3_archiver, 'get_s3_client', return_value=mock_s3), \
             patch.object(s3_archiver, 'ensure_bucket_exists'):

            with s3_archiver._s3_stream_lock:
                s3_archiver._s3_stream_buffer.clear()

            # 1. Attempt to enqueue non-asset / app node log (server_id=None) -> Must be dropped
            s3_archiver.enqueue_direct_log_to_s3(
                server_id=None,
                log_type="catalina",
                source="app/catalina.out",
                message="2026-11-09 INFO app log",
                hostname="app-node-1"
            )
            self.assertEqual(len(s3_archiver._s3_stream_buffer), 0)

            # 2. Enqueue asset-level log from Log Monitor (server_id=10) -> Must be accepted
            s3_archiver.enqueue_direct_log_to_s3(
                server_id=10,
                log_type="access",
                source="access.log",
                message='10.0.0.1 - - [09/Nov/2026:10:00:00] "GET /home HTTP/1.1" 200 100',
                server_ip="192.168.1.100",
                hostname="soc-server"
            )
            self.assertEqual(len(s3_archiver._s3_stream_buffer), 1)

            s3_archiver.flush_direct_s3_stream()

            self.assertTrue(mock_s3.put_object.called)
            call_kwargs = mock_s3.put_object.call_args[1]
            key = call_kwargs['Key']
            body_gz = call_kwargs['Body']

            # S3 is strictly for asset logs: key must be {machine_id}/{server_ip}/logs/...
            self.assertIn("/logs/", key)
            self.assertTrue(key.startswith("soc-server/192.168.1.100/logs/access/access.log/"))
            self.assertTrue(key.endswith(".jsonl.gz"))

            # Verify uncompressed content is valid JSON
            uncompressed = gzip.decompress(body_gz).decode('utf-8')
            entries = json.loads(uncompressed)
            self.assertEqual(len(entries), 1)
            self.assertIn("GET /home HTTP/1.1", entries[0]["message"])

    def test_database_push_log_entries_filters_asset_logs_to_s3(self):
        import database as db

        # Mock database connection and cursor
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

        lines = [
            # Routine 200 OK access line -> should stream asset log to S3, NOT execute INSERT INTO pushed_logs
            '10.0.0.1 - - [09/Nov/2026:12:00:00 +0000] "GET /api/status HTTP/1.1" 200 500',
            # Attack payload -> MUST execute INSERT INTO pushed_logs
            '10.0.0.1 - - [09/Nov/2026:12:00:00 +0000] "GET /login?id=1\' UNION SELECT password FROM users-- HTTP/1.1" 200 500',
            # Generic warning without user/ip -> should stream asset log to S3, NOT execute INSERT INTO pushed_logs
            '2026-11-09 12:00:00 WARN [org.apache.catalina.session] Expiring expired sessions',
            # Critical auth failure -> MUST execute INSERT INTO pushed_logs
            '2026-11-09 12:00:00 WARN Authentication failed for user admin'
        ]

        with patch.object(db, 'get_db_connection', return_value=mock_conn), \
             patch('s3_archiver.enqueue_direct_log_to_s3') as mock_enqueue:

            saved = db.push_log_entries(config_id=1, server_id=1, lines=lines)
            
            # All 4 items were processed
            self.assertEqual(saved, 4)

            # Asset-level routine items (routine 200 and generic warning) were enqueued to S3 directly
            self.assertEqual(mock_enqueue.call_count, 2)

            # Only the 2 non-routine / attack items were inserted into pushed_logs table
            inserted_messages = []
            for call in mock_cursor.execute.call_args_list:
                args = call[0]
                sql = args[0]
                if "INSERT INTO pushed_logs" in sql:
                    params = args[1]
                    inserted_messages.append(params[5])

            self.assertEqual(len(inserted_messages), 2)
            self.assertIn("UNION SELECT", inserted_messages[0])
            self.assertIn("Authentication failed", inserted_messages[1])

if __name__ == '__main__':
    unittest.main()
