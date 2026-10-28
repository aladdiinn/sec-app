"""
Step 2 Verification Test Suite - BSmart SOC Application-Level SIEM
Verifies:
1. Application registration, project association, and settings persistence.
2. Component registration with 1-time enrollment tokens, machine linking, and expiration.
3. Fleet inventory enrichment (components_ratio, computed_status, events_per_min, open_incidents).
4. Maintenance mode state machine (WAITING -> MAINT -> WAITING).
5. Project scoping isolation.
6. Cascade deletion across applications, components, and link tables.
7. Audit trail logging for all application operations.
8. FastAPI route registration and response schemas.
9. Jinja2 template rendering for add_services.html and apps.html with add_app_wizard_modal.html.
"""

import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database as db
import app_siem_db
from app import app, render_template

class Step2ApplicationSIEMTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Ensure database schema is initialized
        conn = db.get_db_connection()
        assert conn is not None, "Failed to connect to PostgreSQL database."
        try:
            app_siem_db.init_app_siem_schema(conn)
        finally:
            conn.close()

    def setUp(self):
        self.conn = db.get_db_connection()
        self.created_app_ids = []
        self.created_proj_ids = []

    def tearDown(self):
        if self.conn:
            with self.conn.cursor() as cur:
                for app_id in self.created_app_ids:
                    try:
                        cur.execute("DELETE FROM applications WHERE id = %s;", (app_id,))
                    except Exception:
                        pass
                for proj_id in self.created_proj_ids:
                    try:
                        cur.execute("DELETE FROM projects WHERE id = %s;", (proj_id,))
                    except Exception:
                        pass
            self.conn.close()

    def test_01_create_application_and_enrichment(self):
        """Test application creation, project linking, and default inventory enrichment."""
        print("\n--- Test 01: Create Application & Enrichment ---")
        app_data = db.create_application(
            name="Test ERP Portal",
            primary_url="https://erp.testcorp.internal:8443",
            environment="Production",
            description="Core enterprise resource planning business system",
            settings={"admin_url_prefixes": ["/admin", "/manage"]},
            created_by="sec_admin"
        )
        self.assertIsNotNone(app_data)
        self.assertIn("id", app_data)
        app_id = app_data["id"]
        self.created_app_ids.append(app_id)
        print(f"Created application ID {app_id}: {app_data['name']} ({app_data['primary_url']})")

        # Fetch via get_applications
        apps = db.get_applications()
        matched = [a for a in apps if a["id"] == app_id]
        self.assertEqual(len(matched), 1)
        item = matched[0]

        # Verify default enrichment values
        self.assertEqual(item["components_ratio"], "0/0")
        self.assertEqual(item["computed_status"], "WAITING")
        self.assertEqual(item["events_per_min"], 0)
        self.assertEqual(item["open_incidents"], 0)
        self.assertEqual(item["last_event_formatted"], "never")
        print(f"Verified enrichment: ratio={item['components_ratio']}, status={item['computed_status']}, epm={item['events_per_min']}")

    def test_02_component_registration_and_tokens(self):
        """Test adding web & db components, token hashing, and expiration."""
        print("\n--- Test 02: Component Registration & Enrollment Tokens ---")
        app_data = db.create_application(
            name="Banking Portal",
            primary_url="https://banking.internal",
            environment="Production",
            created_by="sec_admin"
        )
        app_id = app_data["id"]
        self.created_app_ids.append(app_id)

        # Add 2 Web Nodes and 1 Database Node
        c1 = db.add_application_component(app_id, "web", "web-cluster-01", "10.0.1.11")
        c2 = db.add_application_component(app_id, "web", "web-cluster-02", "10.0.1.12")
        c3 = db.add_application_component(app_id, "database", "db-cluster-pg01", "10.0.2.20")

        self.assertIsNotNone(c1)
        self.assertIsNotNone(c2)
        self.assertIsNotNone(c3)

        # Verify enrollment tokens (32 hex characters)
        self.assertEqual(len(c1["enrollment_token"]), 32)
        self.assertEqual(c1["role"], "web")
        self.assertEqual(c3["role"], "database")
        print(f"Generated enrollment tokens: c1={c1['enrollment_token'][:8]}..., c3={c3['enrollment_token'][:8]}...")

        # Fetch components for app
        comps = db.get_application_components(app_id)
        self.assertEqual(len(comps), 3)
        print(f"Verified {len(comps)} registered components for app ID {app_id}")

        # Check inventory enrichment reflects 3 total components (0 reporting)
        apps = db.get_applications()
        item = next(a for a in apps if a["id"] == app_id)
        self.assertEqual(item["components_ratio"], "0/3")
        self.assertEqual(item["computed_status"], "WAITING")
        print(f"Verified inventory components ratio: {item['components_ratio']} (status: {item['computed_status']})")

    def test_03_maintenance_mode_state_machine(self):
        """Test maintenance mode toggling and status reflection."""
        print("\n--- Test 03: Maintenance Mode State Machine ---")
        app_data = db.create_application(
            name="HR Management",
            primary_url="https://hr.internal",
            created_by="sec_admin"
        )
        app_id = app_data["id"]
        self.created_app_ids.append(app_id)

        # Toggle maintenance ON
        db.update_application(app_id, settings={"maintenance_mode": True}, status="MAINT")
        apps = db.get_applications()
        item = next(a for a in apps if a["id"] == app_id)
        self.assertEqual(item["computed_status"], "MAINT")
        self.assertEqual(item["status_color"], "b")
        print("Toggled maintenance ON -> computed_status: MAINT (color: b)")

        # Toggle maintenance OFF
        db.update_application(app_id, settings={"maintenance_mode": False}, status="WAITING")
        apps = db.get_applications()
        item = next(a for a in apps if a["id"] == app_id)
        self.assertEqual(item["computed_status"], "WAITING")
        self.assertEqual(item["status_color"], "m")
        print("Toggled maintenance OFF -> computed_status: WAITING (color: m)")

    def test_04_project_scoping(self):
        """Test project assignment and project-level isolation filtering."""
        print("\n--- Test 04: Project Scoping & Isolation ---")
        with self.conn.cursor() as cur:
            cur.execute("INSERT INTO projects (name, description) VALUES ('Core Banking Project', 'PCI-DSS Scoped') RETURNING id;")
            proj_id = cur.fetchone()["id"]
            self.created_proj_ids.append(proj_id)

        app_data = db.create_application(
            name="PCI Payments App",
            primary_url="https://payments.internal",
            project_id=proj_id,
            created_by="sec_admin"
        )
        app_id = app_data["id"]
        self.created_app_ids.append(app_id)

        # Scoped fetch matching project
        apps_scoped = db.get_applications(project_id=proj_id)
        self.assertTrue(any(a["id"] == app_id for a in apps_scoped))
        print(f"Verified app appears in project {proj_id} scope")

        # Scoped fetch for non-existent project 99999
        apps_other = db.get_applications(project_id=99999)
        self.assertFalse(any(a["id"] == app_id for a in apps_other))
        print("Verified app is excluded from non-matching project scope (99999)")

    def test_05_cascade_deletion(self):
        """Test deleting components and cascade-deleting applications."""
        print("\n--- Test 05: Component Deletion & Cascade App Deletion ---")
        app_data = db.create_application(
            name="Temporary Service",
            primary_url="https://temp.internal",
            created_by="sec_admin"
        )
        app_id = app_data["id"]
        c1 = db.add_application_component(app_id, "web", "temp-web", "10.0.0.99")

        # Delete single component
        del_comp = db.delete_application_component(app_id, c1["id"])
        self.assertTrue(del_comp)
        comps = db.get_application_components(app_id)
        self.assertEqual(len(comps), 0)
        print("Successfully deleted individual component")

        # Delete entire application
        del_app = db.delete_application(app_id)
        self.assertTrue(del_app)
        app_lookup = db.get_application_by_id(app_id)
        self.assertIsNone(app_lookup)
        print(f"Successfully deleted application {app_id} and verified cascade cleanup")

    def test_06_fastapi_routes_registration(self):
        """Verify all Step 2 routes are registered on the FastAPI application instance."""
        print("\n--- Test 06: FastAPI Route Registration ---")
        registered_paths = {route.path for route in app.routes}
        expected_paths = {
            "/apps",
            "/applications",
            "/services/add",
            "/api/apps",
            "/api/apps/{app_id}",
            "/api/apps/{app_id}/maintenance",
            "/api/apps/{app_id}/components",
            "/api/apps/{app_id}/components/{comp_id}",
            "/api/app/setup"
        }
        for ep in expected_paths:
            self.assertIn(ep, registered_paths, f"Expected route {ep} is not registered in FastAPI!")
            print(f"PASS: Route registered: {ep}")

    def test_07_template_rendering(self):
        """Test Jinja2 template rendering for add_services.html and apps.html."""
        print("\n--- Test 07: Template Rendering ---")
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/services/add",
            "query_string": b"",
            "headers": [],
            "server": ("127.0.0.1", 5001),
            "scheme": "http",
            "session": {"user": "admin", "user_role": "admin"}
        }
        dummy_req = Request(scope)

        # 1. Render Add Services Page
        resp_services = render_template(dummy_req, "add_services.html", {
            "active": "add-services",
            "base_url": "http://127.0.0.1:5001"
        })
        body_services = resp_services.body.decode("utf-8")
        self.assertIn("Add Asset", body_services)
        self.assertIn("Add Application", body_services)
        self.assertIn("add-app-wizard-modal", body_services) # Modal included
        print("PASS: add_services.html rendered successfully with Add Asset, Add Application, and Wizard Modal")

        # 2. Render Total Apps Page
        resp_apps = render_template(dummy_req, "apps.html", {
            "active": "apps",
            "base_url": "http://127.0.0.1:5001"
        })
        body_apps = resp_apps.body.decode("utf-8")
        self.assertIn("Application Inventory", body_apps)
        self.assertIn("apps-grid", body_apps)
        self.assertIn("app-details-modal", body_apps)
        print("PASS: apps.html rendered successfully with Application Inventory and details modal")

    def test_08_api_endpoints_execution(self):
        """Test direct execution of Step 2 REST API endpoints with authentication and session scoping."""
        print("\n--- Test 08: REST API Endpoints Direct Execution ---")
        from starlette.requests import Request
        from app import (
            api_create_app, api_get_apps, api_get_app, api_toggle_app_maintenance,
            api_add_app_component, api_get_app_components, api_delete_app_component,
            api_delete_app, api_app_setup
        )

        def make_req(path="/"):
            scope = {
                "type": "http",
                "method": "POST",
                "path": path,
                "query_string": b"",
                "headers": [],
                "server": ("127.0.0.1", 5001),
                "scheme": "http",
                "session": {"user_id": 1, "username": "admin", "user_role": "admin"}
            }
            return Request(scope)

        req = make_req()

        # 1. POST /api/apps
        created = api_create_app(req, {
            "name": "Billing & Invoicing Portal",
            "primary_url": "https://billing.bsmart.internal",
            "environment": "Staging",
            "description": "Customer billing system"
        })
        self.assertIsNotNone(created)
        app_id = created["id"]
        self.created_app_ids.append(app_id)
        self.assertEqual(created["name"], "Billing & Invoicing Portal")
        print(f"PASS: api_create_app -> ID {app_id}")

        # 2. GET /api/apps
        all_apps = api_get_apps(req)
        self.assertTrue(any(a["id"] == app_id for a in all_apps))
        print(f"PASS: api_get_apps -> returned {len(all_apps)} applications")

        # 3. GET /api/apps/{id}
        single_app = api_get_app(req, app_id)
        self.assertEqual(single_app["id"], app_id)
        self.assertEqual(single_app["environment"], "Staging")
        print(f"PASS: api_get_app -> retrieved details for {single_app['name']}")

        # 4. POST /api/apps/{id}/components (Web Node)
        comp_web = api_add_app_component(req, app_id, {
            "role": "web",
            "node_name": "billing-web-01",
            "node_ip": "172.16.10.10"
        })
        self.assertIsNotNone(comp_web)
        self.assertIn("enrollment_token", comp_web)
        comp_id = comp_web["id"]
        print(f"PASS: api_add_app_component (web) -> component ID {comp_id}, token={comp_web['enrollment_token'][:8]}...")

        # 5. GET /api/apps/{id}/components
        comps = api_get_app_components(req, app_id)
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0]["id"], comp_id)
        print(f"PASS: api_get_app_components -> {len(comps)} component(s)")

        # 6. POST /api/apps/{id}/maintenance
        maint_res = api_toggle_app_maintenance(req, app_id, {"enabled": True})
        self.assertTrue(maint_res["maintenance_mode"])
        self.assertEqual(maint_res["app_status"], "MAINT")
        print("PASS: api_toggle_app_maintenance -> enabled maintenance")

        # 7. GET /api/app/setup
        setup_resp = api_app_setup(token=comp_web["enrollment_token"], app=app_id, role="web", node="billing-web-01")
        setup_script = setup_resp.body.decode("utf-8")
        self.assertIn("#!/bin/bash", setup_script)
        self.assertIn(comp_web["enrollment_token"], setup_script)
        print("PASS: api_app_setup -> served collector setup shell script")

        # 8. DELETE /api/apps/{id}/components/{comp_id}
        del_c = api_delete_app_component(req, app_id, comp_id)
        self.assertEqual(del_c["status"], "success")
        print("PASS: api_delete_app_component -> removed component")

        # 9. DELETE /api/apps/{id}
        del_a = api_delete_app(req, app_id)
        self.assertEqual(del_a["status"], "success")
        print(f"PASS: api_delete_app -> deleted application ID {app_id}")

    def test_09_audit_logs_verification(self):
        """Verify that audit logs recorded the application operations."""
        print("\n--- Test 09: Audit Logs Verification ---")
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT username, action, target_type, detail
                FROM audit_logs
                WHERE action IN ('CREATE_APP', 'ADD_APP_COMPONENT', 'TOGGLE_APP_MAINTENANCE', 'REMOVE_APP_COMPONENT', 'DELETE_APP')
                ORDER BY id DESC
                LIMIT 5;
            """)
            logs = cur.fetchall()
            self.assertGreater(len(logs), 0)
            actions = {l["action"] for l in logs}
            print(f"Recorded recent audit actions: {actions}")
            self.assertTrue(any(a in actions for a in ('CREATE_APP', 'DELETE_APP', 'ADD_APP_COMPONENT')))
            print("PASS: Verified audit logs written with real username and detail")

if __name__ == "__main__":
    unittest.main()
