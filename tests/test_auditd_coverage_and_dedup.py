import os
import json
import time
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

os.environ["TESTING"] = "1"
os.environ["SECRET_KEY"] = "test-secret-key-32-chars-long-abc"
os.environ["DB_PASSWORD"] = "testpassword"

import app as app_module
import database as db
import ses_mailer


class TestAuditdCoverageAndDedup(unittest.TestCase):
    """
    Acceptance & Integration Test Suite (T1 - T5 + Multi-Pair Correlation Safety + Shadow Mode)
    Uses a real temporary SQLite database via SQLiteConnectionWrapper (not mocked SQL returns)
    to verify actual SQL execution, schema compatibility, merge updates, reversible audit trails,
    event-timestamp correlation windows, and Option B zero-downtime rollout.
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="bsmart_corr_test_")
        self.db_path = os.path.join(self.tmp_dir, "test_soc.db")
        self._orig_connect = sqlite3.connect

        def _temp_get_conn():
            conn = self._orig_connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return db.SQLiteConnectionWrapper(conn)

        self._conn_patcher = patch.object(db, "get_db_connection", side_effect=_temp_get_conn)
        self._conn_patcher.start()

        # Disable live email dispatch threads during tests
        self._mail_patcher = patch.object(ses_mailer, "send_smart_alert_email", return_value=True)
        self._mail_patcher.start()

        db.init_db()
        db.set_correlation_shadow_mode(False)
        app_module._dedup_alerts_cache.clear()
        app_module._last_known_server_user.clear()
        app_module._known_server_ports.clear()
        app_module._recent_admin_actions.clear()
        ses_mailer._CRITICAL_EMAIL_DEDUP.clear()

        # Seed two isolated test assets (#14 JVVNL-Ticket Resolve and #15 Mitra 1)
        with db.get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO servers (id, name, hostname, ip, ip_address, status, is_maintenance) "
                    "VALUES (14, 'JVVNL- Ticket Resolve', 'jvvnl-ticket', '192.168.150.14', '192.168.150.14', 'online', 0);"
                )
                cur.execute(
                    "INSERT INTO servers (id, name, hostname, ip, ip_address, status, is_maintenance) "
                    "VALUES (15, 'Mitra 1', 'mitra-1', '192.168.150.15', '192.168.150.15', 'online', 0);"
                )
                cur.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES ('email_notifications_enabled', 'true');"
                )

    def tearDown(self):
        db.set_correlation_shadow_mode(False)
        self._mail_patcher.stop()
        self._conn_patcher.stop()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _fetch_open_incidents(self, server_id=None):
        with db.get_db_connection() as conn:
            with conn.cursor() as cur:
                if server_id is not None:
                    cur.execute("SELECT * FROM incidents WHERE server_id = %s AND status = 'open' ORDER BY id ASC;", (server_id,))
                else:
                    cur.execute("SELECT * FROM incidents WHERE status = 'open' ORDER BY id ASC;")
                return cur.fetchall()

    def _fetch_corr_logs(self, server_id):
        with db.get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM incident_correlation_log WHERE server_id = %s ORDER BY id ASC;", (server_id,))
                return cur.fetchall()

    # -------------------------------------------------------------------------
    # T1: pkill -9 against Tomcat by named user -> ONE attributed CRITICAL incident
    # -------------------------------------------------------------------------
    def test_t1_pkill_merges_with_service_stopped_both_orders_real_sql(self):
        """
        T1 (Order A & Order B on real DB):
        When user 'manoj.kn' runs `pkill -9 java` AND Tomcat/Java app transitions to stopped:
        - Order A (audit + regex command arrive first, then service_stopped):
          Produces ONLY ONE incident row (merged across MASS_PROCESS_KILL, AUDIT_PROCESS_KILL, service_stopped).
        - Order B (service_stopped arrives first as WARNING, then pkill arrives 4s later):
          Updates the existing open incident into ONE CRITICAL attributed incident.
        """
        base_ts = time.time() - 5.0
        # --- Order A: run detection engine with BOTH auditd event (proctitle) & command log + service_stopped ---
        pkill_hex = "pkill\x00-9\x00java".encode("utf-8").hex()
        payload = {
            "event_ts": base_ts + 2.0,
            "audit_events": [{
                "serial": 9001,
                "epoch": base_ts,
                "key": "process_kill",
                "auid": "1742601378",
                "username": "manoj.kn",
                "effective_user": "root",
                "comm": "pkill",
                "exe": "/usr/bin/pkill",
                "pid": "24100",
                "line": f'type=SYSCALL msg=audit({base_ts:.3f}:9001): syscall=59 auid=1742601378 pid=24100 comm="pkill" exe="/usr/bin/pkill" key="process_kill" type=PROCTITLE proctitle={pkill_hex}'
            }],
            "commands": [{"command": "pkill -9 java", "user": "manoj.kn"}],
            "sudo_events": [],
            "log_lines": [],
            "file_changes": [],
        }

        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module.run_detection_engine(14, payload)

        # Before service stops: single signal must remain WARNING (no single-signal CRITICAL!)
        pre_incs = self._fetch_open_incidents(14)
        self.assertEqual(len(pre_incs), 1, f"Overlapping pkill detections must merge into 1 incident, got: {pre_incs}")
        self.assertEqual(pre_incs[0]["severity"], "warning", "process_kill alone must NOT escalate to CRITICAL")

        # Now seed running Java service in prev telemetry, then transition to stopped in current push
        with db.get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE servers SET detected_services = %s WHERE id = 14;",
                    (json.dumps([{"id": "java_app", "name": "Java app", "unit_name": "tomcat.service", "pid": 1488, "status": "running"}]),)
                )
        db.save_detected_services(
            server_id=14,
            services_list=[{"id": "java_app", "name": "Java app", "unit_name": "tomcat.service", "pid": None, "status": "stopped"}],
            event_ts=base_ts + 2.0,
        )

        post_incs = self._fetch_open_incidents(14)
        self.assertEqual(len(post_incs), 1, f"pkill + service_stopped must merge into EXACTLY ONE incident, got: {post_incs}")
        merged = post_incs[0]
        self.assertEqual(merged["severity"], "critical", "Confirmed service_stopped + process_kill MUST escalate to CRITICAL")
        self.assertIn("Service Terminated — Java app", merged["title"])
        self.assertIn("manoj.kn", merged["title"])
        self.assertIn("pkill -9 java", merged["title"])

        ev = json.loads(merged["evidence_data"])
        self.assertEqual(ev.get("login_user"), "manoj.kn")
        self.assertEqual(ev.get("command"), "pkill -9 java")
        self.assertTrue(len(ev.get("merged_events", [])) >= 2, "Evidence must preserve merged raw event chain")

        corr_logs = self._fetch_corr_logs(14)
        self.assertTrue(any(c["pair_type"] == "SERVICE_STOPPED_PROCESS_KILL" and c["shadow_only"] == 0 for c in corr_logs))

        # --- Order B on Server #15: service_stopped arrives FIRST, audit process_kill arrives 4s later ---
        with db.get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE servers SET detected_services = %s WHERE id = 15;",
                    (json.dumps([{"id": "tomcat", "name": "Tomcat", "unit_name": "tomcat.service", "pid": 8812, "status": "running"}]),)
                )
        db.save_detected_services(
            server_id=15,
            services_list=[{"id": "tomcat", "name": "Tomcat", "unit_name": "tomcat.service", "pid": None, "status": "stopped"}],
            event_ts=base_ts,
        )
        mid_incs = self._fetch_open_incidents(15)
        self.assertEqual(len(mid_incs), 1)
        self.assertEqual(mid_incs[0]["severity"], "warning")

        kill_hex = "kill\x00-9\x008812".encode("utf-8").hex()
        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module._check_unified_fim(15, {
                "audit_events": [{
                    "serial": 9055,
                    "epoch": base_ts + 4.0,
                    "key": "process_kill",
                    "auid": "1742601378",
                    "username": "manoj.kn",
                    "effective_user": "root",
                    "comm": "kill",
                    "exe": "/usr/bin/kill",
                    "pid": "24999",
                    "line": f'type=SYSCALL msg=audit({base_ts + 4.0:.3f}:9055): syscall=59 auid=1742601378 comm="kill" exe="/usr/bin/kill" key="process_kill" proctitle={kill_hex}'
                }],
                "file_changes": [],
            })

        order_b_incs = self._fetch_open_incidents(15)
        self.assertEqual(len(order_b_incs), 1, "Order B must merge by PID match into the single existing incident")
        self.assertEqual(order_b_incs[0]["severity"], "critical")
        self.assertIn("Service Terminated — Tomcat", order_b_incs[0]["title"])
        self.assertIn("manoj.kn", order_b_incs[0]["title"])

    # -------------------------------------------------------------------------
    # T2: Tomcat OOM-killed / crashed (no user) -> ONE anonymous WARNING incident
    # -------------------------------------------------------------------------
    def test_t2_oom_crash_service_stop_stays_single_anonymous_warning(self):
        """
        T2: Service crashes/OOM-killed with no process_kill audit event:
        - ONE incident created.
        - Remains WARNING (never CRITICAL without confirmed user kill).
        - Badge clearly states 'No interactive session found — possible crash/OOM'.
        - NEVER falsely attributed to any user.
        """
        with db.get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE servers SET detected_services = %s WHERE id = 14;",
                    (json.dumps([{"id": "java_app", "name": "Java app", "unit_name": "tomcat.service", "pid": 5510, "status": "running"}]),)
                )
        db.save_detected_services(
            server_id=14,
            services_list=[{"id": "java_app", "name": "Java app", "unit_name": "tomcat.service", "pid": None, "status": "stopped"}],
            event_ts=time.time(),
        )

        incs = self._fetch_open_incidents(14)
        self.assertEqual(len(incs), 1)
        inc = incs[0]
        self.assertEqual(inc["title"], "Service Stopped — Java app")
        self.assertEqual(inc["severity"], "warning")
        self.assertIn("No interactive session found — possible crash/OOM", inc["description"])
        self.assertNotIn("manoj.kn", inc["title"])
        self.assertNotIn("manoj.kn", inc["description"])
        ev = json.loads(inc["evidence_data"])
        self.assertEqual(ev.get("attribution_status"), "unattributed")

    # -------------------------------------------------------------------------
    # Correlation Safety: Host, Target, Event-Time Window, & Reversible Shadow Mode
    # -------------------------------------------------------------------------
    def test_correlation_safety_negative_controls_and_shadow_reversibility(self):
        """
        Proves all 3 correlation safety invariants + shadow mode + revert:
        1. Cross-host isolation: pkill on server #15 must NOT merge with service_stopped on server #14.
        2. Target isolation: pkill nginx on server #14 must NOT merge with Java app stopped on server #14.
        3. Event timestamp enforcement: stale replayed pkill from 1 hour ago arriving now (NOW()) must NOT correlate.
        4. Shadow mode logs planned merges in incident_correlation_log without mutating incidents.
        5. Revert restores pre-merge title/severity cleanly.
        """
        now_ts = time.time()

        # 1. Cross-host isolation (#15 pkill java vs #14 Java app stopped)
        db.log_alert(15, "AUDIT_PROCESS_KILL", "User 'manoj.kn' executed `pkill -9 java`", severity="warning", title="Process Kill (pkill -9 java) by manoj.kn", event_ts=now_ts)
        db.log_alert(14, "service_stopped", "Service 'Java app' on srv14 stopped. (No interactive session found — possible crash/OOM)", severity="warning", title="Service Stopped — Java app", event_ts=now_ts, evidence_data={"target_service": "Java app"})
        self.assertEqual(len(self._fetch_open_incidents(14)), 1)
        self.assertEqual(self._fetch_open_incidents(14)[0]["severity"], "warning", "Cross-host kill must NOT correlate")

        # 2. Target isolation (pkill -9 nginx on #14 must NOT merge with Java app stopped on #14)
        db.log_alert(14, "AUDIT_PROCESS_KILL", "User 'manoj.kn' executed `pkill -9 nginx`", severity="warning", title="Process Kill (pkill -9 nginx) by manoj.kn", event_ts=now_ts + 1.0)
        self.assertEqual(len(self._fetch_open_incidents(14)), 2, "Unrelated service target must NOT merge")

        # 3. Stale replayed timestamp (arrives right now, but event_ts was 3600s ago -> MUST NOT merge)
        stale_ts = now_ts - 3600.0
        db.log_alert(14, "AUDIT_PROCESS_KILL", "User 'attacker' executed `pkill -9 java`", severity="warning", title="Process Kill (pkill -9 java) by attacker", event_ts=stale_ts)
        self.assertEqual(len(self._fetch_open_incidents(14)), 3, "Stale replayed event_ts (3600s delta) must NOT correlate even though created_at is NOW()")

        # 4. Shadow mode test on server #15
        db.set_correlation_shadow_mode(True)
        db.log_alert(15, "service_stopped", "Service 'Java app' on srv15 stopped. (No interactive session found — possible crash/OOM)", severity="warning", title="Service Stopped — Java app", event_ts=now_ts + 2.0, evidence_data={"target_service": "Java app"})
        shadow_incs = self._fetch_open_incidents(15)
        self.assertEqual(len(shadow_incs), 2, "Shadow mode must log correlation candidate WITHOUT merging open incidents")
        shadow_logs = self._fetch_corr_logs(15)
        self.assertTrue(any(l["shadow_only"] == 1 and l["pair_type"] == "SERVICE_STOPPED_PROCESS_KILL" for l in shadow_logs))

        # 5. Live merge + reversible restore test
        db.set_correlation_shadow_mode(False)
        db.log_alert(15, "service_stopped", "Service 'Java app' on srv15 stopped again.", severity="warning", title="Service Stopped — Java app", event_ts=now_ts + 3.0, evidence_data={"target_service": "Java app"})
        merged_logs = [l for l in self._fetch_corr_logs(15) if l["shadow_only"] == 0]
        self.assertTrue(len(merged_logs) >= 1)
        merge_id = merged_logs[-1]["id"]
        self.assertTrue(db.revert_correlated_incident_merge(merge_id))
        reverted_inc = [i for i in self._fetch_open_incidents(15) if i["id"] == merged_logs[-1]["primary_incident_id"]][0]
        self.assertEqual(reverted_inc["severity"], "warning")
        self.assertNotIn("Service Terminated", reverted_inc["title"])

    # -------------------------------------------------------------------------
    # Pairs 2 & 3: Port Scan + c2_tools AND Firewall Disabled + firewall_change
    # -------------------------------------------------------------------------
    def test_pairs_2_and_3_port_c2_and_firewall_merge(self):
        """
        Verifies Pair 2 (nc -lvnp 4444 + PORT_SCAN_4444) and Pair 3 (iptables -F + FIREWALL_DISABLED)
        each merge into ONE attributed incident.
        """
        ts = time.time()
        nc_hex = "nc\x00-lvnp\x004444".encode("utf-8").hex()
        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module._known_server_ports[14] = {22, 80, 443}
            app_module.run_detection_engine(14, {
                "event_ts": ts,
                "audit_events": [{
                    "serial": 9101, "epoch": ts, "key": "c2_tools", "auid": "1742601378",
                    "username": "manoj.kn", "effective_user": "root", "comm": "nc", "exe": "/usr/bin/nc.openbsd",
                    "pid": "5111",
                    "line": f'type=SYSCALL msg=audit({ts:.3f}:9101): syscall=59 auid=1742601378 pid=5111 comm="nc" exe="/usr/bin/nc.openbsd" key="c2_tools" proctitle={nc_hex}'
                }],
                "open_ports": [{"port": 4444, "process": "nc", "user": "root", "pid": 5111, "ip": "0.0.0.0"}],
            })

        incs = self._fetch_open_incidents(14)
        self.assertEqual(len(incs), 1, f"nc -lvnp 4444 + PORT_SCAN_4444 must merge into 1 incident, got: {incs}")
        self.assertIn("4444", incs[0]["title"])
        self.assertIn("manoj.kn", incs[0]["title"])

        # Pair 3: firewall_change audit + FIREWALL_DISABLED command regex on server #15
        ipt_hex = "iptables\x00-F".encode("utf-8").hex()
        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module.run_detection_engine(15, {
                "event_ts": ts,
                "audit_events": [{
                    "serial": 9102, "epoch": ts, "key": "firewall_change", "auid": "1742601378",
                    "username": "manoj.kn", "effective_user": "root", "comm": "iptables", "exe": "/usr/sbin/iptables",
                    "line": f'type=SYSCALL msg=audit({ts:.3f}:9102): syscall=59 auid=1742601378 comm="iptables" exe="/usr/sbin/iptables" key="firewall_change" proctitle={ipt_hex}'
                }],
                "commands": [{"command": "iptables -F", "user": "manoj.kn"}],
            })
        fw_incs = self._fetch_open_incidents(15)
        self.assertEqual(len(fw_incs), 1, f"iptables -F audit + regex must merge into 1 incident, got: {fw_incs}")
        self.assertIn("manoj.kn", fw_incs[0]["title"])
        self.assertIn("iptables -F", fw_incs[0]["description"])

    # -------------------------------------------------------------------------
    # T3: Command Keys (wget, curl, scp, ssh-keygen, iptables) Default to WARNING
    # -------------------------------------------------------------------------
    def test_t3_new_command_tracking_policies_and_proctitle_alerts(self):
        """
        T3: All new command keys produce properly keyed events with full decoded cmdline
        and default to WARNING (no single-signal CRITICAL).
        Also verifies wget + curl in the same push are BOTH recorded (not collapsed into 1 by key).
        """
        ts = time.time()
        wget_hex = "wget\x00https://example.invalid/a.sh".encode("utf-8").hex()
        curl_hex = "curl\x00-s\x00https://example.invalid/b.sh".encode("utf-8").hex()
        scp_hex = "scp\x00/etc/hosts\x00root@10.0.0.2:/tmp/".encode("utf-8").hex()
        keygen_hex = "ssh-keygen\x00-t\x00ed25519".encode("utf-8").hex()

        keys_expected = [
            "recon_tools", "data_transfer", "c2_tools", "process_kill",
            "ssh_persistence", "firewall_change", "archive_staging",
            "obfuscated_exec", "scheduled_tasks_cmd", "history_tamper"
        ]
        for k in keys_expected:
            self.assertIn(k, app_module._AUDIT_KEY_DESCRIPTIONS)
            self.assertEqual(db.get_audit_severity_policy(k)["default_severity"], "warning")

        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module._check_unified_fim(14, {
                "audit_events": [
                    {"serial": 1, "epoch": ts, "key": "recon_tools", "auid": "1742601378", "username": "manoj.kn", "comm": "wget", "exe": "/usr/bin/wget", "line": f'type=SYSCALL msg=audit({ts:.3f}:1): auid=1742601378 comm="wget" exe="/usr/bin/wget" key="recon_tools" proctitle={wget_hex}'},
                    {"serial": 2, "epoch": ts + 1, "key": "recon_tools", "auid": "1742601378", "username": "manoj.kn", "comm": "curl", "exe": "/usr/bin/curl", "line": f'type=SYSCALL msg=audit({ts+1:.3f}:2): auid=1742601378 comm="curl" exe="/usr/bin/curl" key="recon_tools" proctitle={curl_hex}'},
                    {"serial": 3, "epoch": ts + 2, "key": "data_transfer", "auid": "1742601378", "username": "manoj.kn", "comm": "scp", "exe": "/usr/bin/scp", "line": f'type=SYSCALL msg=audit({ts+2:.3f}:3): auid=1742601378 comm="scp" exe="/usr/bin/scp" key="data_transfer" proctitle={scp_hex}'},
                    {"serial": 4, "epoch": ts + 3, "key": "ssh_persistence", "auid": "1742601378", "username": "manoj.kn", "comm": "ssh-keygen", "exe": "/usr/bin/ssh-keygen", "line": f'type=SYSCALL msg=audit({ts+3:.3f}:4): auid=1742601378 comm="ssh-keygen" exe="/usr/bin/ssh-keygen" key="ssh_persistence" proctitle={keygen_hex}'},
                ],
                "file_changes": [],
            })

        incs = self._fetch_open_incidents(14)
        self.assertEqual(len(incs), 4, f"All 4 distinct commands must produce individual attributed incidents, got {len(incs)}")
        for inc in incs:
            self.assertEqual(inc["severity"], "warning", f"Single-signal command incident must be WARNING, not critical: {inc}")
            self.assertIn("manoj.kn", inc["title"])

    # -------------------------------------------------------------------------
    # T4 & T5: Builtin Gaps, Rule Deduplication, Zero-Downtime Option B Script
    # -------------------------------------------------------------------------
    def test_t4_and_t5_shell_builtin_gaps_and_zero_downtime_rollout_script(self):
        """
        T4 & T5:
        - /update_audit_rules.sh documents kill & history -c builtin gaps cleanly.
        - Uses `type -P` + `readlink -f` + `grep -qxF` deduplication (no `Rule exists` duplicates).
        - Covers all 19 missing commands + killall cleanly without unrestrained `-S kill` spam.
        - Monitors .bash_history truncation while ignoring normal O_APPEND logout writes.
        - Verifies zero agent modifications / restarts.
        """
        class MockRequest:
            method = "GET"
            base_url = "https://soc.vcloudengine.com/"
            query_params = {}
            headers = {}

        coro = app_module.update_audit_rules_script(MockRequest())
        try:
            coro.send(None)
            resp = None
        except StopIteration as e:
            resp = e.value

        self.assertEqual(resp.media_type, "text/x-shellscript")
        script = resp.body.decode("utf-8")

        # T4: Builtin gaps documented & alternatives implemented
        self.assertIn("kill` in interactive bash/sh is a shell builtin", script)
        self.assertIn("history -c", script)
        self.assertIn("-w /root/.bash_history -p wa -k history_tamper", script)
        self.assertIn("type -P", script, "Must use `type -P` so bash builtin kill resolves external binary")
        self.assertNotIn("-S kill ", script, "Must NOT use noisy global -S kill syscall watch that floods kill(pid, 0)")

        # All commands covered
        for cmd in ("wget", "curl", "scp", "rsync", "sftp", "nc", "ncat", "pkill", "killall",
                    "kill", "ssh-keygen", "iptables", "ufw", "tar", "zip", "base64", "crontab", "useradd", "passwd"):
            self.assertIn(f"add_exec_rule {cmd} ", script)
        self.assertIn("-w /root/.ssh/authorized_keys -p wa -k ssh_persistence", script)

        # Benign O_APPEND bash history logout ignored, while O_TRUNC / truncate tool triggers
        benign_line = 'type=SYSCALL msg=audit(1795:1): syscall=257 a2=441 exe="/usr/bin/bash" comm="bash" name="/root/.bash_history"'
        trunc_line = 'type=SYSCALL msg=audit(1795:2): syscall=257 a2=241 exe="/usr/bin/bash" comm="bash" name="/root/.bash_history"'
        tool_line = 'type=SYSCALL msg=audit(1795:3): syscall=76 exe="/usr/bin/truncate" comm="truncate" name="/root/.bash_history"'
        self.assertTrue(app_module._is_benign_bash_history_append("history_tamper", benign_line, "/usr/bin/bash", "/root/.bash_history"))
        self.assertFalse(app_module._is_benign_bash_history_append("history_tamper", trunc_line, "/usr/bin/bash", "/root/.bash_history"))
        self.assertFalse(app_module._is_benign_bash_history_append("history_tamper", tool_line, "/usr/bin/truncate", "/root/.bash_history"))

        # T5: Zero agent downtime guarantees
        self.assertIn("AGENT_PID=$(pgrep -f \"node_push_agent.py\" || true)", script)
        self.assertIn("BEFORE_COUNT=$(auditctl -l", script)
        self.assertIn("AFTER_COUNT=$(auditctl -l", script)
        self.assertIn("[VERIFIED] securepulse-agent is UNTOUCHED", script)
        self.assertNotIn("systemctl restart securepulse", script)
        self.assertNotIn("systemctl stop securepulse", script)
        self.assertNotIn("node_push_agent.py >", script)

    # -------------------------------------------------------------------------
    # Email Template Attribution & Crash Badge Verification
    # -------------------------------------------------------------------------
    def test_email_template_renders_attribution_and_crash_badge(self):
        html_merged = ses_mailer.build_alert_html(
            alert_id=59426,
            alert_title="Service Terminated — Java app (by user 'manoj.kn' via pkill -9 java)",
            alert_type="service_stopped",
            message="Service 'Java app' on JVVNL- Ticket Resolve terminated after user 'manoj.kn' executed `pkill -9 java`.",
            severity="CRITICAL",
            timestamp="2026-11-26 10:30:00",
            server_ip="192.168.150.14",
            hostname="JVVNL- Ticket Resolve",
            llm_data={"analysis": "User terminated Tomcat via pkill.", "risk": "Service outage.", "recommendations": "Investigate."}
        )
        self.assertIn("Attributed Actor", html_merged)
        self.assertIn("manoj.kn", html_merged)
        self.assertIn('<code style="color:#f87171">pkill -9 java</code>', html_merged)
        self.assertNotIn('color:#f87171">pkill -9 java)', html_merged, "Trailing closing parenthesis must not leak into cmd code span")

        html_anon = ses_mailer.build_alert_html(
            alert_id=59427,
            alert_title="Service Stopped — Java app",
            alert_type="service_stopped",
            message="Service 'Java app' on JVVNL- Ticket Resolve transitioned from running to stopped unexpectedly. (No interactive session found — possible crash/OOM)",
            severity="WARNING",
            timestamp="2026-11-26 10:35:00",
            server_ip="192.168.150.14",
            hostname="JVVNL- Ticket Resolve",
            llm_data={"analysis": "Service stopped.", "risk": "Crash.", "recommendations": "Restart."}
        )
        self.assertIn("Attribution Status", html_anon)
        self.assertIn("No interactive session found — possible crash/OOM", html_anon)
        self.assertNotIn("manoj.kn", html_anon)

    def test_symlink_shared_inode_noise_filters(self):
        """
        Verify read-only pgrep, iptables -L/-S/iptables-save, ufw status, and
        /update_audit_rules.sh fetches do NOT false-positive on shared binary inodes.
        """
        ts = time.time()
        pgrep_hex = "pgrep\x00-f\x00java".encode("utf-8").hex()
        ipt_list_hex = "iptables\x00-L\x00-n".encode("utf-8").hex()
        ufw_st_hex = "ufw\x00status".encode("utf-8").hex()
        self_curl_hex = "curl\x00-fsSL\x00https://soc.bsmartone.com:3443/update_audit_rules.sh".encode("utf-8").hex()

        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module._check_unified_fim(14, {
                "audit_events": [
                    {"serial": 801, "epoch": ts, "key": "process_kill", "auid": "1742601378", "username": "manoj.kn", "comm": "pgrep", "exe": "/usr/bin/pgrep", "line": f'type=SYSCALL msg=audit({ts:.3f}:801): auid=1742601378 comm="pgrep" exe="/usr/bin/pgrep" key="process_kill" proctitle={pgrep_hex}'},
                    {"serial": 802, "epoch": ts, "key": "firewall_change", "auid": "1742601378", "username": "manoj.kn", "comm": "iptables", "exe": "/usr/sbin/xtables-nft-multi", "line": f'type=SYSCALL msg=audit({ts:.3f}:802): auid=1742601378 comm="iptables" exe="/usr/sbin/xtables-nft-multi" key="firewall_change" proctitle={ipt_list_hex}'},
                    {"serial": 803, "epoch": ts, "key": "firewall_change", "auid": "1742601378", "username": "manoj.kn", "comm": "ufw", "exe": "/usr/sbin/ufw", "line": f'type=SYSCALL msg=audit({ts:.3f}:803): auid=1742601378 comm="ufw" exe="/usr/sbin/ufw" key="firewall_change" proctitle={ufw_st_hex}'},
                    {"serial": 804, "epoch": ts, "key": "recon_tools", "auid": "1742601378", "username": "manoj.kn", "comm": "curl", "exe": "/usr/bin/curl", "line": f'type=SYSCALL msg=audit({ts:.3f}:804): auid=1742601378 comm="curl" exe="/usr/bin/curl" key="recon_tools" proctitle={self_curl_hex}'},
                ],
                "file_changes": [],
            })

        self.assertEqual(len(self._fetch_open_incidents(14)), 0, "Benign shared-inode reads and self-rollout curls must produce 0 incidents")

        # HEAD route registered on /update_audit_rules.sh
        head_routes = [r for r in app_module.app.routes if getattr(r, "path", "") == "/update_audit_rules.sh" and "HEAD" in (getattr(r, "methods", set()) or set())]
        self.assertTrue(len(head_routes) >= 1, "HEAD /update_audit_rules.sh must be registered so curl -I succeeds")


if __name__ == "__main__":
    unittest.main()
