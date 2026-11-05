import unittest
import time
from app import evaluate_web_security_event, is_ip_internal

class TestSIEMAccuracyCorpus(unittest.TestCase):
    """
    Comprehensive Accuracy Overhaul Unit Test Corpus:
    Tests 5 Benign and 5 Malicious cases per rule category including near-miss names,
    multi-signal requirements, status code correlation, and network zone awareness.
    """

    # =========================================================================
    # 1. DATA EXFILTRATION & BACKUP ARCHIVE EXPOSURE
    # =========================================================================
    def test_exfiltration_benign_cases(self):
        benign_cases = [
            ("GET", "/backupForPureSwapping?kno1=118144102&kno2=118196502", 200, 1024),
            ("GET", "/backupForDataCorrectionByKno?ticketNo=37288&oldMeterNo=5K100042", 200, 2048),
            ("GET", "/exportToExcel?report=consumer_summary&date=2026-11-04", 200, 45000),
            ("GET", "/backup_status_check?node=hp-1", 200, 512),
            ("GET", "/getstocksummary?subdivision=solan", 200, 1500)
        ]
        for method, path, status, b_sent in benign_cases:
            ev_type, sev, title, _, ev_dict = evaluate_web_security_event(
                method, path, status, "operator1", "172.23.40.53", bytes_sent=b_sent
            )
            self.assertEqual(sev, "info", f"Benign path {path} must NOT alert! Fired: {sev} ({title})")
            self.assertEqual(ev_type, "HTTP_ACCESS")

    def test_exfiltration_malicious_cases(self):
        malicious_cases = [
            ("GET", "/backup.sql", 200, 500000),
            ("GET", "/db_dump.tar.gz", 200, 2000000),
            ("GET", "/database_backup.sql.gz", 200, 1500000),
            ("GET", "/api/export/bulk_download", 200, 25 * 1024 * 1024),  # 25MB export
            ("GET", "/full_backup/pg_dump.dmp", 200, 800000)
        ]
        for method, path, status, b_sent in malicious_cases:
            ev_type, sev, title, _, ev_dict = evaluate_web_security_event(
                method, path, status, "attacker", "185.220.101.42", bytes_sent=b_sent
            )
            self.assertIn(sev, ("high", "critical"), f"Malicious path {path} MUST alert! Got: {sev}")
            self.assertEqual(ev_type, "DATA_EXFILTRATION")
            self.assertIn("rule_id", ev_dict)
            self.assertEqual(ev_dict.get("rule_version"), "2.4")

    # =========================================================================
    # 2. SQL INJECTION (Corroborated vs Probes)
    # =========================================================================
    def test_sqli_benign_cases(self):
        benign_cases = [
            ("GET", "/VerifyKnoMeterNumber?knum=2000188981", 200),
            ("GET", "/search?q=select+shoes+for+sale", 200),
            ("GET", "/updateVerifyStatus/860505?kno=860505", 200),
            ("GET", "/order?by=drop_off_point", 200),
            ("GET", "/articles?category=sql_tutorial_part1", 200)
        ]
        for method, path, status in benign_cases:
            ev_type, sev, title, _, _ = evaluate_web_security_event(
                method, path, status, "user1", "172.23.10.86"
            )
            self.assertIn(sev, ("info", "low"), f"Benign SQL route {path} alerted as: {sev}")

    def test_sqli_malicious_cases(self):
        malicious_cases = [
            ("GET", "/products?id=1' UNION SELECT username, password FROM users--", 500, "org.postgresql.util.PSQLException: syntax error"),
            ("GET", "/api/users?name=' OR 1=1--", 200, ""),
            ("GET", "/login?user=admin' AND 1=(SELECT 1)--", 403, ""),
            ("GET", "/catalog?cat=1; WAITFOR DELAY '0:0:5'--", 200, ""),
            ("GET", "/search?term=1' AND pg_sleep(5)--", 200, "")
        ]
        for item in malicious_cases:
            method, path, status = item[0], item[1], item[2]
            raw_log = item[3] if len(item) > 3 else ""
            ev_type, sev, title, _, ev_dict = evaluate_web_security_event(
                method, path, status, "attacker", "45.142.195.12", raw_line=raw_log
            )
            self.assertIn(ev_type, ("SQL_INJECTION", "SQL_INJECTION_PROBE"))
            if status == 500 and "syntax error" in raw_log:
                self.assertEqual(sev, "critical", "SQLi with confirmed DB error MUST be CRITICAL")
            else:
                self.assertIn(sev, ("low", "medium"))

    # =========================================================================
    # 3. CROSS-SITE SCRIPTING (XSS)
    # =========================================================================
    def test_xss_benign_cases(self):
        benign_cases = [
            ("GET", "/getSectionDetailsConsumerSurveyHPP?section=north", 200),
            ("GET", "/help?topic=javascript_frameworks", 200),
            ("GET", "/docs?tag=math_equation", 200),
            ("GET", "/comment?text=score+1+to+2", 200),
            ("GET", "/feed?xml=item_news", 200)
        ]
        for method, path, status in benign_cases:
            ev_type, sev, _, _, _ = evaluate_web_security_event(
                method, path, status, "user2", "10.0.0.27"
            )
            self.assertEqual(sev, "info", f"Benign XSS route {path} alerted: {sev}")

    def test_xss_malicious_cases(self):
        malicious_cases = [
            ("GET", "/search?q=<script>alert('xss')</script>", 200),
            ("GET", "/profile?img=\" onerror=\"alert(1)", 200),
            ("GET", "/redirect?url=javascript:alert(document.cookie)", 200),
            ("GET", "/view?page=<svg/onload=alert(1)>", 200),
            ("GET", "/index?name=<iframe src=\"javascript:alert(1)\">", 200)
        ]
        for method, path, status in malicious_cases:
            ev_type, sev, _, _, ev_dict = evaluate_web_security_event(
                method, path, status, "attacker", "185.220.101.42"
            )
            self.assertEqual(ev_type, "XSS_ATTACK")
            self.assertIn(sev, ("low", "medium"))
            self.assertEqual(ev_dict.get("matched_fields", {}).get("network_zone"), "EXTERNAL")

    # =========================================================================
    # 4. PATH TRAVERSAL / LFI
    # =========================================================================
    def test_path_traversal_benign_cases(self):
        benign_cases = [
            ("GET", "/static/css/theme..dark.css", 200),
            ("GET", "/reports/2026/11/monthly..summary.pdf", 200),
            ("GET", "/files?name=project_notes.txt", 200),
            ("GET", "/docs/v1/api..overview.html", 200),
            ("GET", "/image/logo..brand.png", 200)
        ]
        for method, path, status in benign_cases:
            ev_type, sev, _, _, _ = evaluate_web_security_event(
                method, path, status, "user3", "172.23.40.53"
            )
            self.assertEqual(sev, "info", f"Benign path traversal near-miss {path} alerted: {sev}")

    def test_path_traversal_malicious_cases(self):
        malicious_cases = [
            ("GET", "/download?file=../../../../etc/passwd", 200),
            ("GET", "/view?doc=../../../../etc/shadow", 200),
            ("GET", "/load?path=../../../../windows/win.ini", 200),
            ("GET", "/read?f=../../../../etc/sudoers", 200),
            ("GET", "/get?file=....//....//....//etc/hosts", 200)
        ]
        for method, path, status in malicious_cases:
            ev_type, sev, _, _, ev_dict = evaluate_web_security_event(
                method, path, status, "attacker", "185.220.101.42"
            )
            self.assertEqual(ev_type, "PATH_TRAVERSAL_BREACH")
            self.assertIn(sev, ("high", "critical"))
            self.assertEqual(ev_dict.get("confidence"), "HIGH")

    # =========================================================================
    # 5. SCANNER PROBES & SENSITIVE FILE 200 LEAKS (Requirement 9)
    # =========================================================================
    def test_scanner_and_exposure_cases(self):
        # 1. Single 404 probe must evaluate to INFO (No alert)
        ev_type, sev, _, _, _ = evaluate_web_security_event(
            "GET", "/wp-login.php", 404, "-", "198.51.100.5"
        )
        self.assertEqual(sev, "info", "Single 404 probe MUST evaluate to INFO, never alert")
        self.assertEqual(ev_type, "SCANNER_PROBE")

        # 2. HTTP 200 on .env is a CRITICAL credential leak
        ev_type, sev, title, _, ev_dict = evaluate_web_security_event(
            "GET", "/.env", 200, "-", "198.51.100.5"
        )
        self.assertEqual(sev, "critical", "HTTP 200 on .env MUST be CRITICAL")
        self.assertEqual(ev_type, "SENSITIVE_DATA_EXPOSURE")

        # 3. HTTP 200 on .git/config is a CRITICAL leak
        ev_type, sev, title, _, ev_dict = evaluate_web_security_event(
            "GET", "/.git/config", 200, "-", "198.51.100.5"
        )
        self.assertEqual(sev, "critical", "HTTP 200 on .git/config MUST be CRITICAL")
        self.assertEqual(ev_type, "SENSITIVE_DATA_EXPOSURE")

        # 4. Rapid 5 probes from same IP in 60s triggers SCANNER_RECON (LOW)
        ip = "198.51.100.99"
        for i in range(5):
            res = evaluate_web_security_event("GET", f"/probe-{i}/wp-login.php", 404, "-", ip)
        self.assertEqual(res[1], "low")
        self.assertEqual(res[0], "SCANNER_RECON")

if __name__ == '__main__':
    unittest.main()
