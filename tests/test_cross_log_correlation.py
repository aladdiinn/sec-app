import unittest
import time
from starlette.requests import Request
import app as app_module

class TestCrossLogCorrelation(unittest.TestCase):
    """
    Integration test for Item 4: Cross-log correlation
    Feeds two separate log streams (Tomcat access log + catalina.out exception)
    and verifies that the database exception correlates with the web event
    and escalates the incident severity to CRITICAL.
    """

    def setUp(self):
        with app_module._cross_log_lock:
            app_module._recent_cross_log_db_errors.clear()
            app_module._recent_cross_log_web_events.clear()
        app_module._sqli_tracker.clear()

    def test_cross_log_correlation_escalates_sqli_to_critical(self):
        # Event 1: Tomcat access log line with SQL injection payload (HTTP 500)
        web_access_line = '198.51.100.88 - - [05/Nov/2026:11:00:00 +0530] "GET /products?id=1\' UNION SELECT username, password FROM users-- HTTP/1.1" 500 1024'
        
        # Event 2: Application stdout / catalina.out log line with PostgreSQL exception
        catalina_err_line = '05-Nov-2026 11:00:00.120 SEVERE [http-nio-8080-exec-3] org.postgresql.util.PSQLException: ERROR: syntax error at or near "UNION"'

        # Feed Event 2 (catalina DB exception) first or concurrently into cross-log correlation engine
        with app_module._cross_log_lock:
            app_module._recent_cross_log_db_errors.append((time.time(), catalina_err_line, 1))

        # Feed Event 1 (web access log)
        res = app_module.evaluate_web_security_event(
            "GET",
            "/products?id=1' UNION SELECT username, password FROM users--",
            500,
            "-",
            "198.51.100.88",
            raw_line=web_access_line,
            bytes_sent=1024
        )

        ev_type, sev, title, mitre, evidence = res

        # Verification: The web event correlated with the DB exception and escalated to CRITICAL!
        self.assertEqual(ev_type, "SQL_INJECTION")
        self.assertEqual(sev, "critical", "SQLi correlated with server DB exception MUST escalate to CRITICAL")
        self.assertTrue(any("Correlated database syntax/runtime error" in s for s in evidence.get("signals", [])))

    def test_uncorrelated_500_remains_medium(self):
        # A 500 error with NO database error in logs remains MEDIUM (unconfirmed execution)
        web_access_line = '198.51.100.89 - - [05/Nov/2026:11:00:00 +0530] "GET /items?id=1\' OR 1=1-- HTTP/1.1" 500 512'
        res = app_module.evaluate_web_security_event(
            "GET",
            "/items?id=1' OR 1=1--",
            500,
            "-",
            "198.51.100.89",
            raw_line=web_access_line,
            bytes_sent=512
        )
        self.assertEqual(res[1], "medium", "SQLi 500 without correlated DB error must remain MEDIUM")


    def test_snapd_log_does_not_correlate_or_trigger_postgres_alert(self):
        # Negative test for Evidence Case: snapd OS error line must NOT correlate with database alerts
        snapd_line = 'Nov 10 13:26:41 jaidcplcpncms02 snapd[1120]: mkdir /no: permission denied'
        
        # 1. evaluate_postgres_security_event must reject snapd line
        pg_res = app_module.evaluate_postgres_security_event(snapd_line)
        self.assertEqual(pg_res[0], 'NON_PG_LOG', 'snapd syslog line must be identified as NON_PG_LOG')
        self.assertEqual(pg_res[1], 'info', 'snapd syslog line must evaluate to INFO, never critical')

        # 2. Even if snapd error is present in cross_log_db_errors buffer, it must NOT escalate web SQLi
        with app_module._cross_log_lock:
            app_module._recent_cross_log_db_errors.append((time.time(), snapd_line, 1))

        web_access_line = '198.51.100.90 - - [05/Nov/2026:11:00:00 +0530] "GET /items?id=1\' OR 1=1-- HTTP/1.1" 500 512'
        res = app_module.evaluate_web_security_event(
            "GET",
            "/items?id=1' OR 1=1--",
            500,
            "-",
            "198.51.100.90",
            raw_line=web_access_line,
            bytes_sent=512,
            app_id=1
        )
        self.assertEqual(res[1], "medium", "snapd error must NOT escalate web SQLi to critical")

if __name__ == '__main__':
    unittest.main()
