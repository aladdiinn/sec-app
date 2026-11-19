#!/usr/bin/env python3
"""
tests/test_reinstall_id_stability.py — Automated verification for agent reinstall stability,
identity isolation (Mitra 1 & 2 cloned VMs), orphan scan aliasing, agent 404 backoff,
and reversible history relinking.
"""

import os
import sys
import unittest
import tempfile
import json
import time
import urllib.error

os.environ["TESTING"] = "1"
os.environ["SECRET_KEY"] = "test-secret-key-reinstall-stability"
os.environ["DB_PASSWORD"] = "test-db-pass"

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import database as db
import agent_extracted
from scripts.relink_asset_history import dry_run, execute_relink, rollback

class TestReinstallIdStability(unittest.TestCase):
    def setUp(self):
        db.init_db()
        self.conn = db.get_db_connection()

    def tearDown(self):
        if self.conn:
            self.conn.close()

    def test_1_installer_reinstall_reuses_server_id(self):
        """1. Approving or re-enrolling an existing machine preserves server ID and keeps history."""
        hostname = "soc-server"
        ip = "192.168.10.201"
        machine_id = "432766a649f64b9aade0677153621fee"
        initial_token = "sp-token-valid-auth-token-12345"

        with self.conn.cursor() as cur:
            # Clean up prior test rows
            cur.execute("DELETE FROM servers WHERE ip = %s OR machine_id = %s;", (ip, machine_id))
            cur.execute("DELETE FROM approvals WHERE ip_address = %s OR machine_id = %s;", (ip, machine_id))
            cur.execute("""
                INSERT INTO servers (id, name, hostname, ip, ip_address, machine_id, agent_token, status, approved_by, last_seen)
                VALUES (39, %s, %s, %s, %s, %s, %s, 'online', 'admin', CURRENT_TIMESTAMP);
            """, (hostname, hostname, ip, ip, machine_id, initial_token))
            if hasattr(self.conn, "commit"): self.conn.commit()

        # Reinstall simulation 1: node submits onboarding approval request
        res1 = db.add_approval_request(
            hostname=hostname,
            ip_address=ip,
            machine_id=machine_id,
            token="sp-token-new-random-token-99999",
            node_type="server"
        )
        self.assertEqual(res1["status"], "approved", "Reinstall of known approved server must be auto-approved")
        self.assertEqual(res1["server_id"], 39, "Reinstall must preserve original Server ID 39")

        # Verify no duplicate row was created in servers table
        with self.conn.cursor() as cur:
            cur.execute("SELECT id FROM servers WHERE ip = %s OR machine_id = %s;", (ip, machine_id))
            rows = cur.fetchall()
            self.assertEqual(len(rows), 1, "Must never insert duplicate server row on reinstall")
            self.assertEqual(rows[0]["id"] if isinstance(rows[0], dict) else rows[0][0], 39)

    def test_2_insecure_token_elimination(self):
        """2. New tokens must be cryptographically random and never equal sp-token-{hostname}."""
        hostname = "soc-server"
        ip = "192.168.10.244"
        res = db.add_approval_request(hostname, ip, token=None, node_type="server")
        generated_token = res["token"]
        self.assertTrue(generated_token.startswith("sp-token-"))
        self.assertNotEqual(generated_token, f"sp-token-{hostname}", "Token must never be guessable hostname string")
        self.assertGreater(len(generated_token), 25, "Token must have high entropy")

    def test_3_cloned_vm_mitra_isolation(self):
        """3. Cloned VMs sharing identical machine_id but different IPs must remain strictly isolated."""
        cloned_mid = "45be1000e43f472ea168d3256dc2983c"
        mitra1_ip = "192.168.150.15"
        mitra2_ip = "192.168.150.16"

        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM servers WHERE id IN (10, 11);")
            cur.execute("""
                INSERT INTO servers (id, name, hostname, ip, ip_address, machine_id, agent_token, status, approved_by)
                VALUES (10, 'Jvvnl -Mitra 1', 'Jvvnl -Mitra 1', %s, %s, %s, 'tok-m1', 'online', 'admin'),
                       (11, 'Jvvnl -Mitra 2', 'Jvvnl -Mitra 2', %s, %s, %s, 'tok-m2', 'online', 'admin');
            """, (mitra1_ip, mitra1_ip, cloned_mid, mitra2_ip, mitra2_ip, cloned_mid))
            if hasattr(self.conn, "commit"): self.conn.commit()

        linked_m1 = db.get_linked_server_ids(10)
        linked_m2 = db.get_linked_server_ids(11)

        self.assertEqual(linked_m1, [10], "Mitra 1 must ONLY link to ID 10")
        self.assertEqual(linked_m2, [11], "Mitra 2 must ONLY link to ID 11")
        self.assertNotIn(11, linked_m1, "Mitra 2 must never bleed into Mitra 1")
        self.assertNotIn(10, linked_m2, "Mitra 1 must never bleed into Mitra 2")

    def test_4_scan_aliasing_and_summary_consistency(self):
        """4. Scans for historical alias IDs (e.g. 36) are queryable by target ID 39."""
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM file_scans WHERE server_id IN (36, 39);")
            cur.execute("DELETE FROM file_scan_results WHERE server_id IN (36, 39);")
            cur.execute("""
                INSERT INTO file_scans (id, server_id, trigger_type, status, total_files_scanned, threats_found, started_at, server_name, server_ip)
                VALUES (1001, 36, 'scheduled', 'clean', 150, 0, CURRENT_TIMESTAMP, 'soc-server', '192.168.10.201'),
                       (1002, 36, 'manual', 'threats_found', 200, 2, CURRENT_TIMESTAMP, 'soc-server', '192.168.10.201');
            """)
            cur.execute("""
                INSERT INTO file_scan_results (id, scan_id, server_id, file_path, file_name, sha256, status)
                VALUES (2001, 1002, 36, '/tmp/malware.sh', 'malware.sh', 'hash123', 'threat_detected'),
                       (2002, 1002, 36, '/tmp/webshell.php', 'webshell.php', 'hash456', 'threat_detected');
            """)
            if hasattr(self.conn, "commit"): self.conn.commit()

        # Query by active ID 39
        scans = db.get_latest_file_scans(server_id="39")
        scan_ids = [s["id"] for s in scans]
        self.assertIn(1001, scan_ids, "Scan 1001 from alias ID 36 must be returned for ID 39")
        self.assertIn(1002, scan_ids, "Scan 1002 from alias ID 36 must be returned for ID 39")

        summary = db.get_malware_defense_summary(server_id="39")
        self.assertGreaterEqual(summary["total_scans"], 2, "Summary must include historical scans for ID 39")
        self.assertGreaterEqual(summary["active_threats"], 2, "Summary must reflect active threats")

        # Query unlinked scans
        unlinked = db.get_latest_file_scans(server_id="unlinked")
        unlinked_ids = [s["id"] for s in unlinked]
        self.assertIn(1001, unlinked_ids, "Scan with orphan server_id 36 must show in unlinked scans")

    def test_5_agent_404_backoff_and_no_degraded_state(self):
        """5. Agent handles missing/404 endpoints with 300s backoff and does not mark heartbeat degraded."""
        endpoint = "/api/agent/nonexistent-test-endpoint"
        # Reset cache
        agent_extracted._unsupported_endpoints.clear()

        # Simulate 404
        agent_extracted._unsupported_endpoints[endpoint] = time.time() + 300
        res = agent_extracted.send_agent_request(endpoint)
        self.assertIsNone(res, "Endpoint in backoff must immediately return None without network calls")

        # Simulate 404 for heartbeat endpoint
        agent_extracted._unsupported_endpoints["/api/agent/heartbeat"] = time.time() + 300

        # HeartbeatThread handling
        hb = agent_extracted.HeartbeatThread()
        agent_extracted.error_collapser.record_error("heartbeat_thread", Exception("Old failure"))
        self.assertIn("heartbeat_thread", agent_extracted.error_collapser.get_failing_collectors())

        # When endpoint returns None (or 404), error is cleared
        hb.send_heartbeat_once()
        self.assertNotIn("heartbeat_thread", agent_extracted.error_collapser.get_failing_collectors(), "Heartbeat thread error must be cleared")

    def test_6_relink_script_dry_run_and_execution(self):
        """6. Reversible relink backfill script executes atomically and rolls back cleanly."""
        target = {"id": 39, "name": "soc-server", "hostname": "soc-server", "ip": "192.168.10.201"}
        orphan_ids = [36]

        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM pushed_logs WHERE server_id IN (36, 39);")
            cur.execute("""
                INSERT INTO pushed_logs (id, server_id, source, message, created_at)
                VALUES (5001, 36, '/var/log/syslog', 'Test log from server 36', CURRENT_TIMESTAMP);
            """)
            if hasattr(self.conn, "commit"): self.conn.commit()

        # 1. Dry run
        dry_ok = dry_run(self.conn, "sqlite", target, orphan_ids)
        self.assertTrue(dry_ok)

        # Helper to get val
        def _get_sid(c):
            r = c.fetchone()
            return (r["server_id"] if isinstance(r, dict) or hasattr(r, "keys") else r[0]) if r else None

        # Verify not modified by dry run
        with self.conn.cursor() as cur:
            cur.execute("SELECT server_id FROM pushed_logs WHERE id = 5001;")
            self.assertEqual(_get_sid(cur), 36)

        # 2. Execute relink
        exec_ok = execute_relink(self.conn, "sqlite", target, orphan_ids)
        self.assertTrue(exec_ok)

        # Verify updated to target ID 39
        with self.conn.cursor() as cur:
            cur.execute("SELECT server_id FROM pushed_logs WHERE id = 5001;")
            self.assertEqual(_get_sid(cur), 39)

        # 3. Rollback
        rb_ok = rollback(self.conn, "sqlite")
        self.assertTrue(rb_ok)

        # Verify restored to original ID 36
        with self.conn.cursor() as cur:
            cur.execute("SELECT server_id FROM pushed_logs WHERE id = 5001;")
            self.assertEqual(_get_sid(cur), 36)

if __name__ == "__main__":
    unittest.main()
