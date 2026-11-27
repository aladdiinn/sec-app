import os
import unittest
from unittest.mock import MagicMock, patch

class TestAssetReadAndCompactIncidents(unittest.TestCase):
    def setUp(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        try:
            import app
            app._last_known_server_user.clear()
            app._recent_admin_actions.clear()
        except Exception:
            pass

    def test_templates_contain_required_read_and_compact_elements(self):
        # 1. dashboard.html
        dash_path = os.path.join(self.base_dir, "templates", "dashboard.html")
        with open(dash_path, "r", encoding="utf-8") as f:
            dash_content = f.read()
        self.assertIn("i3-header-btn-read", dash_content)
        self.assertIn("i3-settings-btn-read", dash_content)
        self.assertIn("modal-density-compact", dash_content)
        self.assertIn("modal-density-comfortable", dash_content)
        self.assertIn("deduplicateAssetAlerts", dash_content)
        self.assertIn("renderModalIncidentsList", dash_content)
        self.assertIn("toggleCurrentServerRead", dash_content)
        self.assertIn("badge-read-tag", dash_content)
        # Check problem filter excludes read assets
        self.assertIn("item.isRead", dash_content)

        # 2. servers.html
        srv_path = os.path.join(self.base_dir, "templates", "servers.html")
        with open(srv_path, "r", encoding="utf-8") as f:
            srv_content = f.read()
        self.assertIn("i3-header-btn-read", srv_content)
        self.assertIn("i3-settings-btn-read", srv_content)
        self.assertIn("modal-density-compact", srv_content)
        self.assertIn("modal-density-comfortable", srv_content)
        self.assertIn("deduplicateAssetAlerts", srv_content)
        self.assertIn("renderModalIncidentsList", srv_content)
        self.assertIn("badge-read-tag", srv_content)

        # 3. apps.html
        apps_path = os.path.join(self.base_dir, "templates", "apps.html")
        with open(apps_path, "r", encoding="utf-8") as f:
            apps_content = f.read()
        self.assertIn("badge-read-tag", apps_content)

        # 4. app_detail_modal.html
        app_modal_path = os.path.join(self.base_dir, "templates", "app_detail_modal.html")
        with open(app_modal_path, "r", encoding="utf-8") as f:
            modal_content = f.read()
        self.assertIn("pop-btn-read", modal_content)
        self.assertIn("pop-settings-btn-read", modal_content)
        self.assertIn("toggleCurrentAppRead", modal_content)
        self.assertIn("pop-settings-read-status", modal_content)
        self.assertIn("Dashboard Attention &amp; Read Status", modal_content)

        # 5. theme.css
        theme_path = os.path.join(self.base_dir, "static", "css", "theme.css")
        with open(theme_path, "r", encoding="utf-8") as f:
            theme_content = f.read()
        self.assertIn(".inc-compact-row", theme_content)
        self.assertIn(".density-compact", theme_content)
        self.assertIn(".density-comfortable", theme_content)
        self.assertIn(".badge-read-tag", theme_content)

    def test_ssh_x11_port_recognition_logic(self):
        import database
        # Verify merge_duplicate_incidents_with_audit exists
        self.assertTrue(hasattr(database, "merge_duplicate_incidents_with_audit"))
        self.assertTrue(hasattr(database, "toggle_server_read"))
        self.assertTrue(hasattr(database, "toggle_app_read"))

    def test_app_endpoints_exist(self):
        import app
        routes = [r.path for r in app.app.routes]
        self.assertIn("/api/servers/{id}/read", routes)
        self.assertIn("/api/apps/{id}/read", routes)


    def test_auto_prune_and_compact_app_events(self):
        import app_siem_db
        self.assertTrue(hasattr(app_siem_db, 'auto_prune_and_compact_app_events'))
        from unittest.mock import MagicMock
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur
        mock_cur.rowcount = 42

        res = app_siem_db.auto_prune_and_compact_app_events(mock_conn)
        self.assertEqual(res, 42)
        mock_conn.commit.assert_called()


    def test_user_deletion_actor_attribution_never_unknown(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        # Test Case 1: Correlated with sudo_events
        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "log_lines": ["Nov 9 18:20:25 ubuntu-DEV userdel[400722]: delete user 'prajwal'"],
                "sudo_events": [{"line": "sudo:   ubuntu : TTY=pts/0 ; PWD=/application/Soc ; USER=root ; COMMAND=/usr/sbin/userdel prajwal"}],
                "commands": [],
                "audit_events": []
            }
            app._check_sudo_misuse(1, data)
            self.assertTrue(len(created_alerts) >= 1)
            self.assertIn("ubuntu", created_alerts[0]["title"])
            self.assertNotIn("Unknown", created_alerts[0]["title"])
            self.assertIn("userdel prajwal", created_alerts[0]["message"])

        # Test Case 2: Standalone userdel with root execution (no unprivileged user)
        created_alerts.clear()
        app._last_known_server_user.clear()
        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "log_lines": ["Nov 9 18:20:25 ubuntu-DEV userdel[400722]: delete user 'prajwal'"],
                "sudo_events": [],
                "commands": [],
                "audit_events": []
            }
            app._check_sudo_misuse(1, data)
            self.assertTrue(len(created_alerts) >= 1)
            self.assertTrue("attribution unverified" in created_alerts[0]["title"] or "mannan" in created_alerts[0]["title"] or "root" in created_alerts[0]["title"])
            self.assertNotIn("Unknown", created_alerts[0]["title"])

    def test_process_pid_brackets_never_treated_as_port(self):
        import database
        from unittest.mock import MagicMock, patch

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur
        
        # Row with syslog PID in description
        mock_cur.fetchall.return_value = [{
            "id": 885,
            "server_id": 1,
            "title": "User Account Deletion — root",
            "description": "User 'root' executed: userdel[400722]: delete user 'prajwal'",
            "severity": "critical",
            "status": "open",
            "evidence_data": None,
            "occurrences": 1,
            "first_seen": "2026-11-09 18:20:25",
            "last_seen": "2026-11-09 18:20:25",
            "created_at": "2026-11-09 18:20:25"
        }]

        with patch.object(database, 'get_db_connection', return_value=mock_conn):
            database.merge_duplicate_incidents_with_audit(1)
            # Ensure UPDATE does NOT inject port 400722 into evidence
            calls = [c[0] for c in mock_cur.execute.call_args_list]
            for call_args in calls:
                sql = call_args[0] if len(call_args) > 0 else ""
                params = call_args[1] if len(call_args) > 1 else ()
                if "UPDATE incidents" in sql and "evidence_data" in sql and len(params) > 4:
                    ev_str = str(params[4])
                    self.assertNotIn("400722", ev_str)
                    self.assertNotIn("DET-NET-010", ev_str)

    def test_audit_app_mod_and_identity_alerts_fire_properly(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "file_changes": [],
                "audit_events": [
                    {
                        "key": "app_mod",
                        "username": "mannan",
                        "auid": "1002",
                        "line": 'type=SYSCALL arch=c000003e syscall=257 success=yes exe="/usr/bin/touch" comm="touch" name="/application/Soc/config.py" auid=1002'
                    },
                    {
                        "key": "identity",
                        "username": "root",
                        "auid": "0",
                        "line": 'type=SYSCALL arch=c000003e syscall=257 success=yes exe="/usr/bin/passwd" comm="passwd" name="/etc/shadow" auid=0'
                    }
                ],
                "log_lines": [],
                "sudo_events": [],
                "commands": []
            }
            app._check_unified_fim(1, data)
            titles = [a["title"] for a in created_alerts]
            self.assertTrue(any("App Mod Alert by mannan" in t for t in titles), f"App Mod Alert by mannan missing in {titles}")
            self.assertTrue(any("Identity Alert by" in t for t in titles), f"Identity Alert missing in {titles}")

    def test_passwd_command_detection_triggers_credential_alert(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "log_lines": ["Nov 9 18:25:01 ubuntu-DEV passwd[401200]: password updated successfully"],
                "sudo_events": [],
                "commands": [{"user": "mannan", "command": "passwd"}],
                "audit_events": []
            }
            app._check_sudo_misuse(1, data)
            self.assertTrue(len(created_alerts) >= 1)
            self.assertIn("User Password Modified", created_alerts[0]["title"])
            self.assertIn("mannan", created_alerts[0]["title"])

    def test_audit_loop_does_not_abort_on_background_noise(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "file_changes": [],
                "audit_events": [
                    # First event: bash history noise (must be skipped with continue, NOT aborting the whole loop)
                    {
                        "key": "home_mod",
                        "username": "ubuntu",
                        "auid": "1000",
                        "line": 'type=SYSCALL exe="/bin/bash" comm="bash" name="/home/ubuntu/.bash_history" auid=1000'
                    },
                    # Second event: real app_mod modification
                    {
                        "key": "app_mod",
                        "username": "mannan",
                        "auid": "1002",
                        "line": 'type=SYSCALL exe="/bin/nano" comm="nano" name="/application/Soc/app.py" auid=1002'
                    }
                ],
                "log_lines": [],
                "sudo_events": [],
                "commands": []
            }
            app._check_unified_fim(1, data)
            titles = [a["title"] for a in created_alerts]
            self.assertTrue(any("App Mod Alert by mannan" in t for t in titles), f"App Mod Alert by mannan should fire despite bash_history noise: {titles}")

    def test_user_deletion_correlated_with_audit_user_in_root(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "log_lines": ["Nov 9 18:20:25 ubuntu-DEV userdel[400722]: delete user 'prajwal'"],
                "sudo_events": [],
                "commands": [],
                "audit_events": [
                    {
                        "key": "identity",
                        "username": "mannan",
                        "auid": "1002",
                        "line": 'type=SYSCALL arch=c000003e syscall=257 success=yes exe="/usr/sbin/userdel" comm="userdel" auid=1002 uid=0 name="/etc/shadow"'
                    }
                ]
            }
            app._check_sudo_misuse(1, data)
            self.assertTrue(len(created_alerts) >= 1)
            self.assertEqual(created_alerts[0]["title"], "User Account Deletion — mannan")
            self.assertIn("by user 'mannan' executed:", created_alerts[0]["message"])
            self.assertIn("delete user 'prajwal'", created_alerts[0]["message"])


    def test_passwd_modification_triggers_identity_alert_not_fim(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "file_changes": [
                    {"path": "/etc/passwd", "type": "modified", "detail": "Content or metadata changed"}
                ],
                "audit_events": [],
                "log_lines": [],
                "sudo_events": [],
                "commands": []
            }
            app._check_unified_fim(1, data)
            self.assertTrue(len(created_alerts) >= 1)
            self.assertTrue("Identity Alert" in created_alerts[0]["title"])
            self.assertTrue(created_alerts[0]["alert_type"].upper().startswith("AUDIT_IDENTITY"))


    def test_userdel_suppresses_duplicate_identity_alert_and_attributes_to_mannan(self):
        import app
        from unittest.mock import patch

        created_alerts = []
        def mock_create_alert(server_id, alert_type, severity, title, message):
            created_alerts.append({
                "server_id": server_id,
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "message": message
            })

        with patch.object(app, '_create_alert_dedup', side_effect=mock_create_alert), \
             patch.object(app, '_is_rule_enabled', return_value=True):
            data = {
                "file_changes": [
                    {"path": "/etc/passwd", "type": "modified", "detail": "Content or metadata changed"}
                ],
                "log_lines": ["userdel[578346]: delete user 'prajwal'"],
                "sudo_events": [],
                "commands": [],
                "audit_events": [
                    {
                        "key": "identity",
                        "username": "mannan",
                        "auid": "1005",
                        "line": 'type=SYSCALL arch=c000003e syscall=257 success=yes exe="/usr/sbin/userdel" comm="userdel" auid=1005 uid=0 name="/etc/passwd"'
                    }
                ]
            }
            # Step 1: run sudo misuse (command rule)
            app._check_sudo_misuse(1, data)
            # Step 2: run unified fim (file watch rule)
            app._check_unified_fim(1, data)

            titles = [a["title"] for a in created_alerts]
            # 1. Both the command detection and the audit rule fire
            self.assertTrue(any("User Account Deletion — mannan" in t for t in titles))
            self.assertTrue(any("Identity Alert by mannan" in t for t in titles))
            # 2. Neither ever attributes to root or Unknown
            self.assertFalse(any("root" in t or "Unknown" in t for t in titles))


class TestAssetAlertsFilterAndCardUI(unittest.TestCase):
    def setUp(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_ui_contracts_card_header_and_modal_filters(self):
        # 1. Asset card header moves type pill right and removes top-right DEL button
        js_path = os.path.join(self.base_dir, "static", "js", "asset_status.js")
        with open(js_path, "r", encoding="utf-8") as f:
            js_text = f.read()

        start_idx = js_text.index("function renderCompactAssetCard")
        end_idx = js_text.index("function spUpdateModalFilterSummary")
        asset_card_fn = js_text[start_idx:end_idx]

        self.assertNotIn("sp-del-pill", asset_card_fn)
        self.assertIn("Delete Asset", asset_card_fn)
        head_right_idx = asset_card_fn.index('<div class="sp-card-head-right">')
        head_end_idx = asset_card_fn.index("</div>\n        </div>", head_right_idx)
        head_right_block = asset_card_fn[head_right_idx:head_end_idx]
        self.assertIn('<span class="sp-type-pill">${typeLabel}</span>', head_right_block)
        title_wrap_block = asset_card_fn[asset_card_fn.index('<div class="sp-card-title-wrap">'):head_right_idx]
        self.assertNotIn("sp-type-pill", title_wrap_block)
        self.assertEqual(js_text.count("function spApplyModalIncidentFilters"), 1)
        self.assertEqual(js_text.count("function spResetModalIncidentFilters"), 1)

        # 2. CSS keeps #apps-grid compact and widens asset card grids + light/dark filter styles
        css_path = os.path.join(self.base_dir, "static", "css", "theme.css")
        with open(css_path, "r", encoding="utf-8") as f:
            css_text = f.read()
        self.assertIn("minmax(252px, 1fr)", css_text)
        self.assertIn("minmax(290px, 1fr)", css_text)
        self.assertIn(".sp-inc-filter-bar", css_text)
        self.assertIn(".sp-filter-apply", css_text)
        self.assertIn("[data-theme=\"light\"] .sp-filter-select", css_text)

        # 3. Modals and alerts page expose Type & 24h..90d timestamp filters
        for tpl in ("servers.html", "dashboard.html"):
            with open(os.path.join(self.base_dir, "templates", tpl), "r", encoding="utf-8") as f:
                html = f.read()
            self.assertIn('id="i3-filter-type"', html)
            self.assertIn('id="i3-filter-days"', html)
            for days_val in ('"1"', '"3"', '"7"', '"15"', '"30"', '"90"'):
                self.assertIn(days_val, html)
            self.assertIn("spApplyModalIncidentFilters()", html)
            self.assertIn("spResetModalIncidentFilters()", html)

        with open(os.path.join(self.base_dir, "templates", "alerts.html"), "r", encoding="utf-8") as f:
            alerts_html = f.read()
        self.assertIn('id="filter-days"', alerts_html)
        self.assertIn("days=${encodeURIComponent(days)}", alerts_html)

    def test_unified_list_view_across_dashboard_servers_and_apps(self):
        js_path = os.path.join(self.base_dir, "static", "js", "asset_status.js")
        with open(js_path, "r", encoding="utf-8") as f:
            js_text = f.read()
        self.assertIn("function spApplyContainerView", js_text)
        self.assertIn("function spGetSavedView", js_text)
        self.assertIn('class="sp-sub-ip"', js_text)
        self.assertIn('class="sp-sub-ver"', js_text)

        css_path = os.path.join(self.base_dir, "static", "css", "theme.css")
        with open(css_path, "r", encoding="utf-8") as f:
            css_text = f.read()
        for selector in (
            "#apps-grid:not(.view-is-list)",
            "#apps-grid.view-is-list",
            "#servers-grid.view-is-list",
            "#services-cards-grid.view-is-list",
            ".view-is-list .sp-asset-card",
            ".view-is-list .sp-website-card",
            '[data-theme="light"] .view-is-list .sp-asset-card .sp-sub-ip',
        ):
            self.assertIn(selector, css_text)

        # Dashboard uses unified .sp-card renderer in both Grid and List views (no legacy donut rows)
        with open(os.path.join(self.base_dir, "templates", "dashboard.html"), "r", encoding="utf-8") as f:
            dash_html = f.read()
        self.assertIn('id="btn-view-grid"', dash_html)
        self.assertIn('id="btn-view-list"', dash_html)
        self.assertIn("spApplyContainerView('services-cards-grid'", dash_html)
        self.assertNotIn('<div class="service-card-list', dash_html)

        # Total Assets (/servers) and Websites (/apps) expose Grid/List toggles wired to shared view helper
        with open(os.path.join(self.base_dir, "templates", "servers.html"), "r", encoding="utf-8") as f:
            srv_html = f.read()
        self.assertIn('id="btn-servers-view-grid"', srv_html)
        self.assertIn('id="btn-servers-view-list"', srv_html)
        self.assertIn("setServersView('list')", srv_html)
        self.assertIn("spApplyContainerView('servers-grid'", srv_html)

        with open(os.path.join(self.base_dir, "templates", "apps.html"), "r", encoding="utf-8") as f:
            apps_html = f.read()
        self.assertIn('id="btn-apps-view-grid"', apps_html)
        self.assertIn('id="btn-apps-view-list"', apps_html)
        self.assertIn("setAppsView('list')", apps_html)
        self.assertIn("spApplyContainerView('apps-grid'", apps_html)

    def test_90day_db_and_api_severity_timestamp_filtering(self):
        import shutil
        import sqlite3
        import tempfile
        from datetime import datetime, timedelta, timezone
        from fastapi import HTTPException
        import database as db
        import app as app_module

        def _run_coro_sync(coro):
            try:
                while True:
                    coro.send(None)
            except StopIteration as exc:
                return exc.value

        async def _sync_threadpool(fn, *args, **kwargs):
            return fn(*args, **kwargs)

        tmp_dir = tempfile.mkdtemp(prefix="sp_alerts_filter_")
        db_path = os.path.join(tmp_dir, "test_filter.db")
        orig_connect = sqlite3.connect

        def _get_conn():
            conn = orig_connect(db_path)
            conn.row_factory = sqlite3.Row
            return db.SQLiteConnectionWrapper(conn)

        try:
            with patch.object(db, "get_db_connection", side_effect=_get_conn):
                db.init_db()
                now = datetime.now(timezone.utc)
                ts = lambda h: (now - timedelta(hours=h)).strftime("%Y-%m-%d %H:%M:%S")

                with db.get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO servers (id, name, hostname, ip, ip_address, status, is_maintenance) "
                            "VALUES (77, 'JVVNL- Bijliprabhand-1', 'jvvnl-bijli-1', '192.168.150.12', '192.168.150.12', 'online', 0);"
                        )
                        rows = [
                            ("Alert 12h Crit", "critical", "open", ts(12)),
                            ("Alert 2d High", "high", "open", ts(48)),
                            ("Alert 5d Warn", "warning", "open", ts(5 * 24)),
                            ("Alert 12d Low", "low", "closed", ts(12 * 24)),
                            ("Alert 60d Info", "info", "closed", ts(60 * 24)),
                            ("Alert 120d OldCrit", "critical", "open", ts(120 * 24)),
                        ]
                        for title, sev, st, tstamp in rows:
                            cur.execute(
                                """
                                INSERT INTO incidents (server_id, title, description, severity, status, occurrences, first_seen, last_seen, created_at, updated_at)
                                VALUES (%s, %s, %s, %s, %s, 1, %s, %s, %s, %s);
                                """,
                                (77, title, title + " desc", sev, st, tstamp, tstamp, tstamp, tstamp),
                            )
                        # Raw-only alert at 25 days ago (only in alerts table)
                        cur.execute(
                            """
                            INSERT INTO alerts (server_id, alert_type, severity, title, message, is_resolved, created_at)
                            VALUES (77, 'TEST_RAW', 'critical', 'Alert 25d RawCrit', 'Raw 25d alert', 0, %s);
                            """,
                            (ts(25 * 24),),
                        )

                titles_24h = [r["title"] for r in db.get_server_incidents_filtered(77, days=1)]
                self.assertEqual(titles_24h, ["Alert 12h Crit"])

                titles_3d = {r["title"] for r in db.get_server_incidents_filtered(77, days=3)}
                self.assertEqual(titles_3d, {"Alert 12h Crit", "Alert 2d High"})

                titles_7d_warn = {r["title"] for r in db.get_server_incidents_filtered(77, severity="warning", days=7)}
                self.assertEqual(titles_7d_warn, {"Alert 2d High", "Alert 5d Warn"})

                titles_15d_info = {r["title"] for r in db.get_server_incidents_filtered(77, severity="info", days=15)}
                self.assertEqual(titles_15d_info, {"Alert 12d Low"})

                titles_30d_crit = {r["title"] for r in db.get_server_incidents_filtered(77, severity="critical", days=30)}
                self.assertEqual(titles_30d_crit, {"Alert 12h Crit", "Alert 25d RawCrit"})

                titles_90d = {r["title"] for r in db.get_server_incidents_filtered(77, days=90)}
                self.assertIn("Alert 60d Info", titles_90d)
                self.assertNotIn("Alert 120d OldCrit", titles_90d)

                # API endpoints return accurate DB rows & accept empty/all days without 422
                with patch("fastapi.concurrency.run_in_threadpool", side_effect=_sync_threadpool):
                    res_api = _run_coro_sync(
                        app_module.api_get_server_incidents(77, status="all", severity="warning", days="7", limit=500)
                    )
                    self.assertEqual(res_api["total"], 2)
                    self.assertEqual(res_api["days"], 7)

                    res_all = _run_coro_sync(
                        app_module.api_get_server_incidents(77, status="all", severity="all", days="", limit=500)
                    )
                    self.assertEqual(res_all["total"], 7)
                    self.assertIsNone(res_all["days"])

                    with self.assertRaises(HTTPException) as ctx404:
                        _run_coro_sync(app_module.api_get_server_incidents(999999))
                    self.assertEqual(ctx404.exception.status_code, 404)

                req_mock = MagicMock()
                req_mock.session = {"user_role": "admin"}
                with patch.object(app_module, "is_admin_user", return_value=True):
                    res_inc_api = _run_coro_sync(
                        app_module.api_get_incidents(req_mock, status="all", severity="info", days="90", project_id="all", server_id=77, limit=50)
                    )
                self.assertEqual({x["title"] for x in res_inc_api["items"]}, {"Alert 12d Low", "Alert 60d Info"})

                res_inc = db.get_incidents(status="all", severity="info", days=90, server_id=77, limit=50)
                self.assertEqual({x["title"] for x in res_inc["items"]}, {"Alert 12d Low", "Alert 60d Info"})
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
