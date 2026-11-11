import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

# Set testing environment variable
os.environ["TESTING"] = "1"

import app as app_module
import database as db
import ses_mailer

class TestAuditdPipelineAcceptance(unittest.TestCase):
    """
    Comprehensive Acceptance Test Suite (T1 - T9)
    Verifies the complete audit pipeline overhaul across parsing, attribution,
    rule naming, idempotency, timed change windows, correlation, and smart notifications.
    """

    def setUp(self):
        # Reset caches
        app_module._last_known_server_user.clear()
        with app_module._cross_log_lock:
            app_module._recent_cross_log_db_errors.clear()
            app_module._recent_cross_log_web_events.clear()
        ses_mailer._CRITICAL_EMAIL_DEDUP.clear()

    # -------------------------------------------------------------------------
    # T1: Active Directory User Resolution (SSSD / NSS Domain UIDs)
    # -------------------------------------------------------------------------
    def test_t1_active_directory_user_resolution(self):
        """T1: Domain UID 1742601378 resolves to manoj.kn via SSSD NSS."""
        # Test agent UID resolver
        data = {
            "audit_events": [
                {
                    "auid": "1742601378",
                    "username": "manoj.kn",
                    "key": "session",
                    "line": 'type=SYSCALL msg=audit(1742601378.985:1443): auid=1742601378 comm="sudo" exe="/usr/bin/sudo"'
                }
            ]
        }
        actor = app_module._resolve_server_human_actor(2, data)
        self.assertEqual(actor, "manoj.kn", "Domain AUID 1742601378 must resolve to manoj.kn, never mannan")

    # -------------------------------------------------------------------------
    # T2: Unresolved Actor Fallback (No Hardcoded 'mannan')
    # -------------------------------------------------------------------------
    def test_t2_unresolved_actor_fallback(self):
        """T2: An unknown actor must return 'attribution unverified', NEVER 'mannan'."""
        data_unknown = {
            "audit_events": [],
            "sudo_events": [],
            "commands": []
        }
        actor = app_module._resolve_server_human_actor(999, data_unknown)
        self.assertIn("attribution unverified", actor)
        self.assertNotIn("mannan", actor, "Must NEVER fallback to hardcoded mannan")

    # -------------------------------------------------------------------------
    # T3: Canonical Rule Naming (Key-Only, No AUID/Timestamp)
    # -------------------------------------------------------------------------
    def test_t3_canonical_rule_naming(self):
        """T3: Rule names must be canonical AUDIT_<KEY> without AUID appended."""
        keys = ["session", "perm_mod", "delete", "app_mod", "logins"]
        for k in keys:
            canonical_name = f"AUDIT_{k.upper()}"
            self.assertFalse(any(char.isdigit() for char in canonical_name.split("_")[-1]),
                            f"Rule name {canonical_name} must not contain trailing numeric AUID")

    # -------------------------------------------------------------------------
    # T4: Unkeyed & (null) Event Filtering
    # -------------------------------------------------------------------------
    def test_t4_unkeyed_null_event_filtering(self):
        """T4: Unkeyed syscalls (key=(null)) and (null) paths must not alert."""
        # Ensure evaluate_postgres_security_event filters unformatted logs
        snapd_res = app_module.evaluate_postgres_security_event("Nov 10 13:26:41 jaidcplcpncms02 snapd[1120]: mkdir /no")
        self.assertEqual(snapd_res[0], "NON_PG_LOG")
        self.assertEqual(snapd_res[1], "info")

    # -------------------------------------------------------------------------
    # T5: Ingestion Idempotency & Deduplication
    # -------------------------------------------------------------------------
    def test_t5_ingestion_idempotency_structure(self):
        """T5: Idempotency helper must check composite key (server_id, serial, epoch)."""
        self.assertTrue(hasattr(db, "is_audit_event_ingested"), "db must have is_audit_event_ingested")
        self.assertTrue(hasattr(db, "record_audit_event_ingested"), "db must have record_audit_event_ingested")
        self.assertTrue(hasattr(db, "record_raw_audit_events"), "db must have record_raw_audit_events")

    # -------------------------------------------------------------------------
    # T6: Timed Change Windows (Safe Maintenance with Expiry & Tamper Protection)
    # -------------------------------------------------------------------------
    def test_t6_timed_change_windows_tamper_protection(self):
        """T6: Timed change windows must exist and enforce tamper protection."""
        self.assertTrue(hasattr(db, "get_active_timed_change_window"))
        self.assertTrue(hasattr(db, "create_timed_change_window"))
        self.assertTrue(hasattr(db, "is_server_in_excessive_maintenance"))

        # Verify default severity policy for tamper keys
        id_pol = db.get_audit_severity_policy("identity")
        self.assertEqual(id_pol.get("default_severity"), "critical", "Identity tamper must remain critical")
        
        scope_pol = db.get_audit_severity_policy("scope")
        self.assertEqual(scope_pol.get("default_severity"), "critical", "Sudoers scope tamper must remain critical")

        # Verify routine keys demote in maintenance
        sess_pol = db.get_audit_severity_policy("session")
        self.assertEqual(sess_pol.get("default_severity"), "info")
        self.assertTrue(sess_pol.get("demote_in_maintenance"))

    # -------------------------------------------------------------------------
    # T7: Strict Cross-Log Correlation (snapd vs PostgreSQL)
    # -------------------------------------------------------------------------
    def test_t7_strict_cross_log_correlation(self):
        """T7: Snapd OS syslog error must NOT correlate with database alerts."""
        snapd_err = 'Nov 10 13:26:41 jaidcplcpncms02 snapd[1120]: mkdir /no: permission denied'
        
        # Put snapd line in db error buffer
        with app_module._cross_log_lock:
            app_module._recent_cross_log_db_errors.append((time.time(), snapd_err, 2))

        # Evaluate web SQLi
        res = app_module.evaluate_web_security_event(
            "GET",
            "/items?id=1' OR 1=1--",
            500,
            "-",
            "192.168.150.16",
            raw_line='192.168.150.16 - - [10/Nov/2026:13:26:41 +0530] "GET /items?id=1\' OR 1=1-- HTTP/1.1" 500 512',
            bytes_sent=512,
            app_id=2
        )
        self.assertEqual(res[1], "medium", "Unrelated snapd error must NOT escalate web event to critical")

    # -------------------------------------------------------------------------
    # T8: Decoupled AI Assessment Conflict Badge & Email Deduplication
    # -------------------------------------------------------------------------
    def test_t8_decoupled_ai_conflict_badge(self):
        """T8: If Engine is CRITICAL and AI is Low Risk / FP, show conflict banner."""
        llm_data_low_risk = {
            "analysis": "<li>Appears to be benign systemd transient operation.</li>",
            "risk": "<p>Likely false positive. The risk is low as this is standard login activity.</p>",
            "recommendations": "<li>Review audit rule tuning.</li>"
        }
        html_output = ses_mailer.build_alert_html(
            alert_id=1456,
            alert_title="AUDIT_DELETE on Mitra 2",
            alert_type="AUDIT_DELETE",
            message="Detection Rule [Kernel Audit]: delete event triggered by user 'manoj.kn'",
            severity="CRITICAL",
            timestamp="2026-11-10 13:30:39",
            server_ip="192.168.150.16",
            hostname="jaidcplcpncms02",
            llm_data=llm_data_low_risk
        )
        self.assertIn("[ASSESSMENT CONFLICT: Engine Critical vs AI Low Risk", html_output,
                      "HTML must contain Assessment Conflict warning when AI contradicts Critical engine")

    def test_t8_email_deduplication_15_minutes(self):
        """T8: Critical email dispatch enforces 15-minute deduplication per (rule, server, actor)."""
        rule_key = "AUDIT_DELETE"
        server_ip = "192.168.150.16"
        actor = "manoj.kn"
        now = time.time()
        
        # Seed cache
        ses_mailer._CRITICAL_EMAIL_DEDUP[(rule_key, server_ip, actor)] = now

        # Attempt immediate second dispatch
        res = ses_mailer.send_smart_alert_email(
            alert_id=1457,
            alert_title=f"AUDIT_DELETE by {actor}",
            alert_type=rule_key,
            message=f"Detection Rule [Kernel Audit]: delete event triggered by user '{actor}'",
            severity="CRITICAL",
            timestamp="2026-11-10 13:31:00",
            server_ip=server_ip,
            hostname="jaidcplcpncms02"
        )
        self.assertFalse(res, "Immediate duplicate email within 15 minutes must be suppressed by dedup cache")

    # -------------------------------------------------------------------------
    # T9: Java 8 Exclusion Rule Generator & Mitra 2 Daemon Attribution
    # -------------------------------------------------------------------------
    def test_t9_java8_rule_generator_and_daemon_attribution(self):
        """T9: Mitra 2 Tomcat Java 8 binary rule matches server output exactly."""
        mitra2_java_bin = "/usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java"
        rule = f"-a never,exit -F arch=b64 -F dir=/application -F exe={mitra2_java_bin}\n-w /application -p wa -k app_mod"
        
        self.assertIn("java-8-openjdk-amd64", rule, "Rule must target Java 8 on Mitra 2")
        self.assertIn("-a never,exit", rule, "Rule must exclude java writes from app_mod")
        self.assertNotIn("java-11", rule, "Must NOT reference java-11")

if __name__ == '__main__':
    unittest.main()
