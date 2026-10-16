import unittest
import os
import json
import time
from unittest.mock import patch, MagicMock

import scanner_engine as se
import database as db

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

class TestScannerSSRFAndValidation(unittest.TestCase):
    def test_ssrf_blocks_loopback(self):
        url, host, port, err = se.validate_and_sanitize_target("127.0.0.1")
        self.assertIsNotNone(err)
        self.assertIn("SSRF Blocked", err)

    def test_ssrf_blocks_private_networks(self):
        for ip in ["10.10.10.10", "192.168.1.1", "172.16.5.5"]:
            url, host, port, err = se.validate_and_sanitize_target(ip)
            self.assertIsNotNone(err, f"Should block private IP {ip}")
            self.assertIn("SSRF Blocked", err)

    def test_ssrf_blocks_cloud_metadata(self):
        url, host, port, err = se.validate_and_sanitize_target("169.254.169.254")
        self.assertIsNotNone(err)
        self.assertIn("SSRF Blocked", err)

    def test_valid_public_domain(self):
        url, host, port, err = se.validate_and_sanitize_target("example.com")
        self.assertIsNone(err)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)
        self.assertEqual(url, "https://example.com")

    def test_custom_port_parsing(self):
        url, host, port, err = se.validate_and_sanitize_target("example.com:8443")
        self.assertIsNone(err)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 8443)
        self.assertEqual(url, "https://example.com:8443")

class TestScannerCache(unittest.TestCase):
    def setUp(self):
        se._SCAN_CACHE.clear()

    def test_cache_put_and_get(self):
        se._put_in_cache("headers", "test-domain.com", {"score": 95, "grade": "A"})
        cached = se._get_from_cache("headers", "test-domain.com", force_refresh=False)
        self.assertIsNotNone(cached)
        self.assertEqual(cached["grade"], "A")
        self.assertTrue(cached["cached"])

    def test_cache_force_refresh_bypasses(self):
        se._put_in_cache("headers", "test-domain.com", {"score": 95, "grade": "A"})
        bypassed = se._get_from_cache("headers", "test-domain.com", force_refresh=True)
        self.assertIsNone(bypassed)

class TestScannerHeadersLogic(unittest.TestCase):
    def test_github_fixture_audit(self):
        with open(os.path.join(FIXTURES_DIR, "http_fixtures.json"), "r") as f:
            fixtures = json.load(f)
        gh = fixtures["github_headers"]
        self.assertTrue(gh["hsts_valid"])
        self.assertIn("max-age=31536000", gh["headers"]["Strict-Transport-Security"])
        self.assertIn("preload", gh["headers"]["Strict-Transport-Security"])

    def test_insecure_headers_penalized(self):
        with open(os.path.join(FIXTURES_DIR, "http_fixtures.json"), "r") as f:
            fixtures = json.load(f)
        insecure = fixtures["insecure_headers"]
        self.assertEqual(insecure["expected_grade"], "F")
        self.assertGreater(len(insecure["cookie_issues"]), 0)

class TestScannerTLSLogic(unittest.TestCase):
    def test_tls_fixtures_present(self):
        with open(os.path.join(FIXTURES_DIR, "tls_fixtures.json"), "r") as f:
            fixtures = json.load(f)
        self.assertIn("expired_cert", fixtures)
        self.assertFalse(fixtures["expired_cert"]["expected_valid"])
        self.assertIn("wrong_host_cert", fixtures)
        self.assertFalse(fixtures["wrong_host_cert"]["expected_valid"])
        self.assertIn("self_signed_cert", fixtures)
        self.assertFalse(fixtures["self_signed_cert"]["expected_valid"])

class TestScannerPortsAuthorization(unittest.TestCase):
    def test_unapproved_target_rejected(self):
        res = se.scan_common_ports("example.org")
        self.assertEqual(res.get("status"), "NOT CHECKED")
        self.assertIn("Authorization required", res.get("reason", ""))

    def test_ssrf_blocked_in_port_scan(self):
        res = se.scan_common_ports("127.0.0.1")
        self.assertEqual(res.get("status"), "NOT CHECKED")
        self.assertIn("SSRF Blocked", res.get("reason", ""))

class TestScannerDNSLogic(unittest.TestCase):
    def test_dns_fixtures_present(self):
        with open(os.path.join(FIXTURES_DIR, "dns_fixtures.json"), "r") as f:
            fixtures = json.load(f)
        self.assertIn("example_com", fixtures)
        self.assertEqual(fixtures["example_com"]["dnssec_status"], "SECURE / VALIDATED")

class TestScannerWHOISLogic(unittest.TestCase):
    def test_rdap_parsing_fixture(self):
        with open(os.path.join(FIXTURES_DIR, "whois_fixtures.json"), "r") as f:
            fixtures = json.load(f)
        sample = fixtures["rdap_iana_sample"]
        self.assertEqual(sample["handle"], "EXAMPLE-COM")
        self.assertEqual(len(sample["events"]), 3)
        self.assertEqual(sample["events"][0]["eventAction"], "registration")
        self.assertEqual(sample["events"][1]["eventAction"], "expiration")

class TestScannerTechLogic(unittest.TestCase):
    def test_tech_fixtures_shield(self):
        with open(os.path.join(FIXTURES_DIR, "tech_fixtures.json"), "r") as f:
            fixtures = json.load(f)
        cf = fixtures["cloudflare_sample"]
        self.assertTrue(cf["expected_technologies"][0]["is_shield"])
        self.assertEqual(cf["expected_technologies"][0]["name"], "Cloudflare")

class TestScannerVAPTLogic(unittest.TestCase):
    def test_git_head_signature_check(self):
        with open(os.path.join(FIXTURES_DIR, "vapt_fixtures.json"), "r") as f:
            fixtures = json.load(f)
        real_git = fixtures["real_git_head"]
        fake_git = fixtures["false_git_custom_404"]
        self.assertTrue(real_git["is_vulnerability"])
        self.assertFalse(fake_git["is_vulnerability"])

class TestDatabaseFalsePositives(unittest.TestCase):
    def setUp(self):
        db.init_db()

    def test_add_and_get_false_positive(self):
        db.add_domain_false_positive(
            target="example-test-unit.com",
            finding_hash="test_cors_hash_01",
            finding_title="CORS Misconfiguration",
            reason="Verified public API intended to allow wildcard origin",
            user_email="unittester@bsmartsoc.local"
        )
        fps = db.get_domain_false_positives("example-test-unit.com")
        self.assertIn("test_cors_hash_01", fps)
        self.assertEqual(fps["test_cors_hash_01"]["finding_title"], "CORS Misconfiguration")
        
        # Cleanup
        db.delete_domain_false_positive("example-test-unit.com", "test_cors_hash_01")
        fps_after = db.get_domain_false_positives("example-test-unit.com")
        self.assertNotIn("test_cors_hash_01", fps_after)

if __name__ == "__main__":
    unittest.main()
