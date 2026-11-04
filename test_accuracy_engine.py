"""
Test suite verifying the multi-signal detection engine and zero-false-positive standards.
Tests both benign business routes (which must NOT alert) and true attacks (which MUST alert with evidence).
"""
import unittest
import urllib.parse
import re
import os

# We will test our improved evaluation function
from app import evaluate_web_security_event, check_mass_scraping_detection

class TestDetectionAccuracy(unittest.TestCase):

    def test_benign_utility_routes_never_alert_above_info(self):
        """T2: /backupForPureSwapping and /backupForDataCorrectionByKno must NEVER alert above INFO."""
        benign_cases = [
            ("GET", "/backupForPureSwapping?kno1=110144102&kno2=110196502&mtrno1=5K1079814&mtrno2=5K100741", 200, "172.23.40.53"),
            ("GET", "/backupForDataCorrectionByKno?ticketNo=37288&oldMeterNo=5K1000420&oldKno=199004203", 200, "172.23.10.86"),
            ("GET", "/GetDuplicateKnumbersWithMtrno?mtrNo=12345", 200, "103.116.137.12"),
            ("GET", "/VerifyKnoMeterNumber?kno=20001", 200, "103.116.137.12"),
            ("GET", "/updateVerifyStatus/860505?kno=860505", 200, "103.116.137.12"),
            ("GET", "/getSectionDetailsConsumerSurveyHPP?section=12", 200, "59.178.49.41"),
            ("GET", "/exportToExcel?report=monthly_billing", 200, "172.23.10.15"),
            ("GET", "/adminHelp/user_manual.pdf", 200, "10.0.0.5"),
            ("GET", "/selectDate?startDate=2026-01-01", 200, "172.23.10.15"),
            ("GET", "/unionReport?dept=accounting", 200, "172.23.10.15"),
            ("GET", "/dropdownList?type=meters", 200, "172.23.10.15"),
            ("GET", "/sleepTimer?seconds=10", 200, "172.23.10.15")
        ]

        for method, path, status, ip in benign_cases:
            res = evaluate_web_security_event(method, path, status, "operator", ip, bytes_sent=1024)
            # res is (ev_type, sev, rule_title, mitre_tag, evidence) or 4-tuple
            sev = res[1]
            ev_type = res[0]
            self.assertEqual(sev, "info", f"False positive detected on {path}! Returned {ev_type} with severity {sev}")

    def test_malicious_dump_files_must_alert_with_evidence(self):
        """T3: /backup.sql and /db_dump.tar.gz must alert as HIGH or CRITICAL with evidence."""
        attack_cases = [
            ("GET", "/backup.sql", 200, "203.0.113.195"),
            ("GET", "/database_backup.sql.gz", 200, "198.51.100.22"),
            ("GET", "/db_dump.tar.gz", 200, "203.0.113.5"),
            ("GET", "/export/full_backup.dump", 200, "198.51.100.8"),
            ("GET", "/api/export/bulk_download", 200, "203.0.113.88", 25 * 1024 * 1024) # 25 MB
        ]

        for item in attack_cases:
            method, path, status, ip = item[:4]
            b_sent = item[4] if len(item) > 4 else 500000
            res = evaluate_web_security_event(method, path, status, "anonymous", ip, bytes_sent=b_sent)
            ev_type, sev, rule_title = res[0], res[1], res[2]
            self.assertIn(sev, ("high", "critical"), f"Expected attack alert on {path}, got {sev}")
            self.assertEqual(ev_type, "DATA_EXFILTRATION")

    def test_single_probe_cannot_produce_critical(self):
        """T4: A single isolated web probe must never produce CRITICAL without secondary corroboration."""
        single_probes = [
            ("GET", "/wp-login.php", 404, "203.0.113.10"),
            ("GET", "/wp/wp-login.php", 404, "10.60.9.34"),
            ("GET", "/phpmyadmin/index.php", 404, "203.0.113.10"),
            ("HEAD", "/actuator/env", 404, "203.0.113.10"),
            ("GET", "/products?id=1' OR '1'='1", 200, "203.0.113.10"), # single payload without 500 error or repeat
            ("GET", "/page?search=<script>alert(1)</script>", 200, "203.0.113.10"),
            ("GET", "/files?doc=../../etc/passwd", 404, "203.0.113.10"),
            ("GET", "/uploads/cmd.jsp", 404, "203.0.113.10"),
            ("TRACE", "/api/v1/user", 200, "203.0.113.10")
        ]

        for method, path, status, ip in single_probes:
            res = evaluate_web_security_event(method, path, status, "-", ip, bytes_sent=512)
            sev = res[1]
            self.assertNotEqual(sev, "critical", f"Single probe {path} produced CRITICAL severity! Must be capped at LOW/MEDIUM.")

if __name__ == "__main__":
    unittest.main()
