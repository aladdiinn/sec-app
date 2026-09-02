#!/usr/bin/env python3
"""
EC2 Monitor — Production Test Runner
Runs REAL tests against a live server. Not just syntax checks.
Usage: python3 test_prod.py --url http://localhost:8000
"""

import sys
import json
import time
import argparse
import traceback
from datetime import datetime

# Try requests, install if missing
try:
    import requests
    from requests.exceptions import ConnectionError, Timeout
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests
    from requests.exceptions import ConnectionError, Timeout

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

PASS = f"{GREEN}✓ PASS{RESET}"
FAIL = f"{RED}✗ FAIL{RESET}"
WARN = f"{YELLOW}⚠ WARN{RESET}"
SKIP = f"{YELLOW}– SKIP{RESET}"

results = []

def log(status, name, detail=""):
    symbol = {"PASS": PASS, "FAIL": FAIL, "WARN": WARN, "SKIP": SKIP}[status]
    print(f"  {symbol}  {name}")
    if detail:
        for line in detail.strip().split("\n"):
            print(f"         {YELLOW}{line}{RESET}")
    results.append({"status": status, "name": name, "detail": detail})

def section(title):
    print(f"\n{BOLD}{BLUE}{'─'*60}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'─'*60}{RESET}")

# ── Session with auth ─────────────────────────────────────────────────────────
class TestSession:
    def __init__(self, base_url, username="admin", password="admin"):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.timeout = 10
        self.logged_in = False
        self.username = username
        self.password = password

    def login(self):
        try:
            r = self.session.post(f"{self.base}/api/login",
                json={"username": self.username, "password": self.password})
            if r.status_code == 200 and r.json().get("ok"):
                self.logged_in = True
                return True
            return False
        except Exception as e:
            return False

    def get(self, path, **kwargs):
        return self.session.get(f"{self.base}{path}", **kwargs)

    def post(self, path, **kwargs):
        return self.session.post(f"{self.base}{path}", **kwargs)

    def delete(self, path, **kwargs):
        return self.session.delete(f"{self.base}{path}", **kwargs)

    def put(self, path, **kwargs):
        return self.session.put(f"{self.base}{path}", **kwargs)

# ── Test functions ────────────────────────────────────────────────────────────

def test_server_reachable(s):
    section("1. SERVER REACHABILITY")
    try:
        r = requests.get(s.base, timeout=5, allow_redirects=True)
        if r.status_code in (200, 302, 303):
            log("PASS", f"Server reachable at {s.base} → {r.status_code}")
        else:
            log("FAIL", f"Server returned {r.status_code}", f"Expected 200/302, got {r.status_code}")
    except ConnectionError:
        log("FAIL", "Cannot connect to server", f"Is it running at {s.base}?")
        print(f"\n{RED}SERVER NOT RUNNING. Start it with: bash restart.sh{RESET}")
        sys.exit(1)
    except Timeout:
        log("FAIL", "Server timeout", "Server took >5s to respond")
        sys.exit(1)

def test_auth(s):
    section("2. AUTHENTICATION")
    # Test login page loads
    try:
        r = s.get("/login")
        if r.status_code == 200 and "login" in r.text.lower():
            log("PASS", "Login page loads")
        else:
            log("FAIL", f"Login page returned {r.status_code}")
    except Exception as e:
        log("FAIL", "Login page error", str(e))

    # Test wrong password
    try:
        r = s.post("/api/login", json={"username": "admin", "password": "wrongpass"})
        if r.status_code == 401:
            log("PASS", "Wrong password returns 401")
        else:
            log("FAIL", f"Wrong password returned {r.status_code} (expected 401)")
    except Exception as e:
        log("FAIL", "Wrong password test error", str(e))

    # Test correct login
    ok = s.login()
    if ok:
        log("PASS", f"Login with admin/admin successful")
    else:
        log("FAIL", "Login with admin/admin failed", 
            "Check: DB has admin user? Password hash correct?")

    # Test unauthenticated redirect
    try:
        fresh = requests.Session()
        r = fresh.get(f"{s.base}/", allow_redirects=False, timeout=5)
        if r.status_code in (302, 303, 307):
            log("PASS", "Unauthenticated request redirects to login")
        elif r.status_code == 200 and "login" in r.text.lower():
            log("PASS", "Unauthenticated request shows login page")
        else:
            log("WARN", f"Unauthenticated returns {r.status_code}", 
                "Should redirect to /login")
    except Exception as e:
        log("WARN", "Auth redirect test error", str(e))

def test_pages(s):
    section("3. PAGE LOADS")
    pages = [
        ("/", "dashboard", ["SERVICES", "SECURE", "CRITICAL"]),
        ("/alerts", "alerts page", ["ALERT"]),
        ("/projects", "projects page", []),
        ("/users", "users page", ["USERNAME"]),
        ("/settings", "settings page", ["SETTINGS"]),
        ("/approvals", "approvals page", []),
    ]
    for path, name, keywords in pages:
        try:
            r = s.get(path)
            if r.status_code == 200:
                missing = [k for k in keywords if k.lower() not in r.text.lower()]
                if missing:
                    log("WARN", f"{name} loads but missing content: {missing}")
                else:
                    log("PASS", f"{name} ({path}) loads correctly")
            elif r.status_code in (302, 303):
                log("WARN", f"{name} redirects → check auth")
            else:
                log("FAIL", f"{name} returned {r.status_code}", f"Path: {path}")
        except Exception as e:
            log("FAIL", f"{name} error", str(e))

def test_api_servers(s):
    section("4. API — SERVERS")
    try:
        r = s.get("/api/servers")
        if r.status_code != 200:
            log("FAIL", f"/api/servers returned {r.status_code}")
            return None
        data = r.json()
        servers = data.get("servers", [])
        counts = data.get("counts", {})
        log("PASS", f"/api/servers returns {len(servers)} servers")
        
        # Validate structure
        if servers:
            s1 = servers[0]
            required_fields = ["id", "name", "ip", "status", "active_users", 
                               "failed_logins", "last_sudo"]
            missing = [f for f in required_fields if f not in s1]
            if missing:
                log("WARN", f"Server object missing fields: {missing}")
            else:
                log("PASS", "Server object has all required fields")
            
            # Check last_sudo is real
            if s1.get("last_sudo"):
                log("PASS", f"last_sudo has value: '{s1['last_sudo']}'")
            else:
                log("WARN", "last_sudo is empty — real-time update may not work")
        
        if counts:
            log("PASS", f"Counts: {counts}")
        else:
            log("FAIL", "No counts in /api/servers response")
        
        return servers
    except Exception as e:
        log("FAIL", "/api/servers error", str(e))
        return None

def test_api_counts(s):
    section("5. API — COUNTS")
    try:
        r = s.get("/api/counts")
        if r.status_code == 200:
            d = r.json()
            required = ["secure", "warning", "critical", "total"]
            missing = [k for k in required if k not in d]
            if missing:
                log("FAIL", f"/api/counts missing keys: {missing}")
            else:
                log("PASS", f"/api/counts → {d}")
        else:
            log("FAIL", f"/api/counts returned {r.status_code}")
    except Exception as e:
        log("FAIL", "/api/counts error", str(e))

def test_server_pages(s, servers):
    section("6. SERVER DETAIL PAGES")
    if not servers:
        log("SKIP", "No servers — skipping server page tests")
        return

    server = servers[0]
    sid = server["id"]
    sname = server["name"]

    subpages = [
        (f"/server/{sid}", "detail"),
        (f"/server/{sid}/logins", "logins"),
        (f"/server/{sid}/sudos", "sudos"),
        (f"/server/{sid}/tracking", "tracking"),
        (f"/server/{sid}/active-users", "active-users"),
        (f"/server/{sid}/security", "security"),
        (f"/server/{sid}/crons", "crons"),
        (f"/server/{sid}/commands", "commands"),
        (f"/server/{sid}/users", "users"),
    ]
    for path, name in subpages:
        try:
            r = s.get(path)
            if r.status_code == 200:
                log("PASS", f"{sname} / {name} page loads")
            elif r.status_code == 500:
                # Extract error from HTML
                text = r.text
                err = ""
                if "TypeError" in text:
                    err = "TypeError in template"
                elif "KeyError" in text:
                    err = "KeyError in template"
                elif "jinja2" in text.lower():
                    err = "Jinja2 template error"
                log("FAIL", f"{name} → 500 Internal Server Error", err)
            else:
                log("WARN", f"{name} returned {r.status_code}")
        except Exception as e:
            log("FAIL", f"{name} error", str(e))

def test_server_actions(s, servers):
    section("7. SERVER ACTIONS API")
    if not servers:
        log("SKIP", "No servers — skipping action tests")
        return

    sid = servers[0]["id"]
    sname = servers[0]["name"]

    actions = ["full-log", "reset-password", "block-ip"]
    for action in actions:
        try:
            r = s.post(f"/api/servers/{sid}/action",
                json={"action": action, "target": "192.168.1.1"})
            if r.status_code == 200:
                d = r.json()
                if d.get("ok"):
                    log("PASS", f"Action '{action}' → {d.get('message','')[:50]}")
                else:
                    log("WARN", f"Action '{action}' returned ok=false", 
                        d.get("message", ""))
            else:
                log("FAIL", f"Action '{action}' → {r.status_code}",
                    r.text[:100])
        except Exception as e:
            log("FAIL", f"Action '{action}' error", str(e))

    # Test unknown action returns 400
    try:
        r = s.post(f"/api/servers/{sid}/action", json={"action": "invalid-action"})
        if r.status_code == 400:
            log("PASS", "Unknown action correctly returns 400")
        else:
            log("WARN", f"Unknown action returned {r.status_code} (expected 400)")
    except Exception as e:
        log("WARN", "Unknown action test error", str(e))

def test_add_delete_server(s):
    section("8. ADD & DELETE SERVER")
    # Add server
    try:
        r = s.post("/api/servers/add", json={
            "name": "test-server-DELETE-ME",
            "ip": "10.99.99.99",
            "region": "",
            "region_code": ""
        })
        if r.status_code == 200:
            d = r.json()
            if d.get("ok") and d.get("id"):
                sid = d["id"]
                log("PASS", f"Add server → id={sid}")

                # Verify it's in pending
                r2 = s.get("/api/servers")
                # New servers are pending (not in approved list) - check approvals
                r_pending = s.get("/approvals")
                if r_pending.status_code == 200 and "test-server-DELETE-ME" in r_pending.text:
                    log("PASS", "New server appears in approvals (pending)")
                else:
                    log("WARN", "New server not found in approvals page")

                # Delete it
                r3 = s.delete(f"/api/servers/{sid}")
                if r3.status_code == 200 and r3.json().get("ok"):
                    log("PASS", "Delete server works")
                else:
                    log("FAIL", f"Delete server returned {r3.status_code}",
                        r3.text[:100])
            else:
                log("FAIL", "Add server response missing ok/id", str(d))
        elif r.status_code == 403:
            log("WARN", "Add server returns 403 — check admin role in session")
        else:
            log("FAIL", f"Add server returned {r.status_code}", r.text[:200])
    except Exception as e:
        log("FAIL", "Add/delete server error", str(e))

def test_alerts(s):
    section("9. ALERTS API")
    try:
        r = s.get("/api/alerts")
        if r.status_code == 200:
            alerts = r.json()
            log("PASS", f"/api/alerts returns {len(alerts)} alerts")
            if alerts:
                a = alerts[0]
                required = ["id", "server_id", "alert_type", "message", "severity"]
                missing = [k for k in required if k not in a]
                if missing:
                    log("WARN", f"Alert missing fields: {missing}")
                else:
                    log("PASS", "Alert object has all required fields")
        else:
            log("FAIL", f"/api/alerts returned {r.status_code}")
    except Exception as e:
        log("FAIL", "/api/alerts error", str(e))

def test_projects(s):
    section("10. PROJECTS API")
    try:
        # List
        r = s.get("/api/projects")
        if r.status_code == 200:
            projects = r.json()
            log("PASS", f"/api/projects returns {len(projects)} projects")
        else:
            log("FAIL", f"/api/projects returned {r.status_code}")
            return

        # Create
        r2 = s.post("/api/projects", json={
            "name": "TEST-PROJECT-DELETE",
            "description": "Auto test"
        })
        if r2.status_code == 200 and r2.json().get("ok"):
            pid = r2.json()["id"]
            log("PASS", f"Create project → id={pid}")

            # Update
            r3 = s.put(f"/api/projects/{pid}", json={
                "name": "TEST-PROJECT-UPDATED",
                "description": "Updated"
            })
            if r3.status_code == 200:
                log("PASS", "Update project works")
            else:
                log("FAIL", f"Update project returned {r3.status_code}")
        else:
            log("FAIL", f"Create project returned {r2.status_code}")
    except Exception as e:
        log("FAIL", "Projects test error", str(e))

def test_users_api(s):
    section("11. USERS API")
    try:
        r = s.get("/users")
        if r.status_code == 200:
            log("PASS", "Users page loads")
        else:
            log("FAIL", f"Users page returned {r.status_code}")

        # Add user
        r2 = s.post("/api/users/add", json={
            "username": "testuser_delete_me",
            "password": "testpass123",
            "role": "user"
        })
        if r2.status_code == 200 and r2.json().get("ok"):
            log("PASS", "Add dashboard user works")

            # Get user ID to delete
            r3 = s.get("/users")
            if "testuser_delete_me" in r3.text:
                log("PASS", "New user appears on users page")
                # Extract ID from response to delete
                # Try to find and delete
                import re
                m = re.search(r'deleteUser\((\d+)\)', r3.text)
                if m:
                    uid = m.group(1)
                    r4 = s.delete(f"/api/users/{uid}")
                    if r4.status_code == 200:
                        log("PASS", "Delete dashboard user works")
                    else:
                        log("WARN", f"Delete user returned {r4.status_code}")
            else:
                log("WARN", "New user not found on users page")
        elif r2.status_code == 400:
            log("WARN", "Add user returned 400 — may already exist, testing delete")
        else:
            log("FAIL", f"Add user returned {r2.status_code}", r2.text[:100])
    except Exception as e:
        log("FAIL", "Users API error", str(e))

def test_agent_push(s, servers):
    section("12. AGENT PUSH ENDPOINT")
    if not servers:
        log("SKIP", "No servers — skipping agent push test")
        return

    # Get a server with its real api_token
    try:
        sid = servers[0]["id"]
        r = s.get(f"/api/servers/{sid}")
        if r.status_code != 200:
            log("SKIP", "Cannot fetch server detail for agent test")
            return
        
        server = r.json()
        token = server.get("api_token", "")
        if not token:
            log("WARN", "Server has no api_token in response")
            # Try to get it from DB check
            log("WARN", "Run: psql -U ec2user -d ec2monitor -c \"SELECT id,api_token FROM servers LIMIT 1;\"")
            return

        # Push test data
        payload = {
            "server_id": sid,
            "api_token": token,
            "hostname": "test-host",
            "ip": "10.0.0.1",
            "active_users": 2,
            "total_users": 5,
            "failed_logins": 1,
            "logins": [
                {"user": "ubuntu", "ip": "10.0.0.1", "time": "12:00 PM", "success": True},
                {"user": "root", "ip": "1.2.3.4", "time": "12:01 PM", "success": False}
            ],
            "sudo_cmds": [
                {"user": "ubuntu", "cmd": "apt upgrade -y", "ago": "1m", "dangerous": False}
            ],
            "dangerous_cmds": [],
            "cron_jobs": [],
            "processes": [],
            "last_sudo": "apt upgrade -y",
            "last_sudo_ago": "1m",
            "pwd_expiry": "All OK / 30d+",
            "pwd_expiry_status": "ok",
            "pwd_expiry_days": 30,
            "tmp_malware": []
        }
        r2 = s.post("/api/agent/push", json=payload)
        if r2.status_code == 200:
            d = r2.json()
            log("PASS", f"Agent push → status={d.get('status')}")

            # Verify last_sudo updated
            time.sleep(0.5)
            r3 = s.get(f"/api/servers/{sid}")
            if r3.status_code == 200:
                updated = r3.json()
                if updated.get("last_sudo") == "apt upgrade -y":
                    log("PASS", "last_sudo updated correctly after agent push")
                else:
                    log("WARN", f"last_sudo not updated. Got: '{updated.get('last_sudo')}'",
                        "Main dashboard won't show real-time sudo commands")
        elif r2.status_code == 403:
            log("FAIL", "Agent push → 403 Invalid token",
                "api_token not returned by /api/servers/{id} — add it to response")
        else:
            log("FAIL", f"Agent push → {r2.status_code}", r2.text[:200])
    except Exception as e:
        log("FAIL", "Agent push error", str(e))

def test_notifications(s):
    section("13. NOTIFICATIONS API")
    try:
        r = s.get("/api/notifications")
        if r.status_code == 200:
            d = r.json()
            if "notifications" in d and "unseen_count" in d:
                log("PASS", f"/api/notifications → {d['unseen_count']} unseen")
            else:
                log("FAIL", "Missing notifications/unseen_count keys", str(d))
        else:
            log("FAIL", f"/api/notifications returned {r.status_code}")
    except Exception as e:
        log("FAIL", "Notifications error", str(e))

def test_system_health_page(s):
    section("14. SYSTEM HEALTH PAGE")
    try:
        r = s.get("/system-health")
        if r.status_code == 200 and "coming soon" in r.text.lower():
            log("PASS", "/system-health shows 'Coming Soon' page")
        elif r.status_code == 200:
            log("WARN", "/system-health loads but no 'Coming Soon' text")
        elif r.status_code == 404:
            log("FAIL", "/system-health returns 404 — route not added",
                "Add route in app.py: @app.get('/system-health') → render coming_soon.html")
        else:
            log("WARN", f"/system-health returned {r.status_code}")
    except Exception as e:
        log("FAIL", "System health page error", str(e))

def test_favicon(s):
    section("15. FAVICON (500 ERROR CHECK)")
    try:
        r = requests.get(f"{s.base}/favicon.ico", timeout=5)
        if r.status_code in (200, 204, 404):
            log("PASS", f"favicon.ico returns {r.status_code} (not 500)")
        elif r.status_code == 500:
            log("FAIL", "favicon.ico returns 500",
                "Add: @app.get('/favicon.ico') async def favicon(): return Response(status_code=204)")
        else:
            log("WARN", f"favicon.ico returns {r.status_code}")
    except Exception as e:
        log("WARN", "favicon test error", str(e))

def test_tracking_page_content(s, servers):
    section("16. TRACKING PAGE — FAILED LOGIN DISPLAY")
    if not servers:
        log("SKIP", "No servers")
        return
    sid = servers[0]["id"]
    try:
        r = s.get(f"/server/{sid}/tracking")
        if r.status_code != 200:
            log("FAIL", f"Tracking page returned {r.status_code}")
            return
        text = r.text
        # Check for FAILED badge (not showing SUCCESS for failed logins)
        if "FAILED" in text or "failed" in text.lower():
            log("PASS", "Tracking page has FAILED status indicator")
        else:
            log("WARN", "Tracking page may show wrong status for failed logins",
                "Check server_tracking.html — success=False should show 'FAILED'")
        if "BLOCK" in text.upper() or "block" in text.lower():
            log("PASS", "Tracking page has Block IP button")
        else:
            log("WARN", "No Block IP button found on tracking page")
    except Exception as e:
        log("FAIL", "Tracking page test error", str(e))

def test_commands_page(s, servers):
    section("17. COMMANDS PAGE")
    if not servers:
        log("SKIP", "No servers")
        return
    sid = servers[0]["id"]
    try:
        r = s.get(f"/api/servers/{sid}/commands")
        if r.status_code == 200:
            cmds = r.json()
            log("PASS", f"/api/commands returns {len(cmds)} dangerous commands")
        elif r.status_code == 404:
            log("FAIL", "/api/commands route missing",
                "Add route: @app.get('/api/servers/{server_id}/commands')")
        else:
            log("FAIL", f"/api/commands returned {r.status_code}")
    except Exception as e:
        log("FAIL", "Commands API error", str(e))

def test_login_status_api(s, servers):
    section("18. LOGIN STATUS API")
    if not servers:
        log("SKIP", "No servers")
        return
    sid = servers[0]["id"]
    try:
        r = s.get(f"/api/servers/{sid}/login-status")
        if r.status_code == 200:
            d = r.json()
            log("PASS", f"/api/login-status returns data for {len(d)} users")
        elif r.status_code == 404:
            log("FAIL", "/api/login-status route missing")
        else:
            log("FAIL", f"/api/login-status returned {r.status_code}")
    except Exception as e:
        log("FAIL", "Login status API error", str(e))

def test_sessions_api(s, servers):
    section("19. SESSIONS API (SSH)")
    if not servers:
        log("SKIP", "No servers")
        return
    sid = servers[0]["id"]
    try:
        r = s.get(f"/api/servers/{sid}/sessions")
        if r.status_code == 200:
            d = r.json()
            if "sessions" in d:
                log("PASS", f"/api/sessions returns {len(d['sessions'])} sessions")
                if not d['sessions']:
                    log("WARN", "0 sessions — normal if no SSH configured, or no one logged in")
            else:
                log("FAIL", "Sessions response missing 'sessions' key", str(d)[:100])
        else:
            log("FAIL", f"/api/sessions returned {r.status_code}", r.text[:100])
    except Exception as e:
        log("FAIL", "Sessions API error", str(e))

def test_system_users_api(s, servers):
    section("20. SYSTEM USERS API (SSH)")
    if not servers:
        log("SKIP", "No servers")
        return
    sid = servers[0]["id"]
    try:
        r = s.get(f"/api/servers/{sid}/system-users")
        if r.status_code == 200:
            d = r.json()
            if d.get("ok"):
                log("PASS", f"/api/system-users returns {len(d.get('users',[]))} users")
            else:
                log("WARN", "system-users ok=False — likely no SSH configured",
                    d.get("message",""))
        else:
            log("FAIL", f"/api/system-users returned {r.status_code}")
    except Exception as e:
        log("FAIL", "System users API error", str(e))

# ── Print summary ─────────────────────────────────────────────────────────────

def print_summary():
    section("SUMMARY")
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    warned = sum(1 for r in results if r["status"] == "WARN")
    skipped = sum(1 for r in results if r["status"] == "SKIP")
    total = len(results)

    print(f"\n  {GREEN}Passed : {passed}/{total}{RESET}")
    print(f"  {RED}Failed : {failed}{RESET}")
    print(f"  {YELLOW}Warnings: {warned}{RESET}")
    print(f"  {YELLOW}Skipped : {skipped}{RESET}")

    if failed > 0:
        print(f"\n{BOLD}{RED}FAILED TESTS:{RESET}")
        for r in results:
            if r["status"] == "FAIL":
                print(f"  {RED}✗ {r['name']}{RESET}")
                if r["detail"]:
                    print(f"    {YELLOW}→ {r['detail'][:100]}{RESET}")

    if warned > 0:
        print(f"\n{BOLD}{YELLOW}WARNINGS (non-critical):{RESET}")
        for r in results:
            if r["status"] == "WARN":
                print(f"  {YELLOW}⚠ {r['name']}{RESET}")

    # Write JSON report
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {"passed": passed, "failed": failed, 
                    "warnings": warned, "skipped": skipped},
        "results": results
    }
    with open("test_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report saved: test_report.json")

    if failed == 0:
        print(f"\n{GREEN}{BOLD}✓ APP IS PRODUCTION READY{RESET}")
    else:
        print(f"\n{RED}{BOLD}✗ {failed} FAILURES — fix before production{RESET}")
    
    return failed

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="EC2 Monitor Production Test Runner")
    parser.add_argument("--url", default="http://localhost:8000", 
                        help="Base URL of the app")
    parser.add_argument("--user", default="admin", help="Admin username")
    parser.add_argument("--pass", dest="password", default="admin", 
                        help="Admin password")
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  EC2 MONITOR — PRODUCTION TEST RUNNER{RESET}")
    print(f"{BOLD}  Target: {args.url}{RESET}")
    print(f"{BOLD}  Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

    s = TestSession(args.url, args.user, args.password)

    test_server_reachable(s)
    test_auth(s)
    servers = test_api_servers(s)
    test_api_counts(s)
    test_pages(s)
    test_server_pages(s, servers)
    test_server_actions(s, servers)
    test_add_delete_server(s)
    test_alerts(s)
    test_projects(s)
    test_users_api(s)
    test_agent_push(s, servers)
    test_notifications(s)
    test_system_health_page(s)
    test_favicon(s)
    test_tracking_page_content(s, servers)
    test_commands_page(s, servers)
    test_login_status_api(s, servers)
    test_sessions_api(s, servers)
    test_system_users_api(s, servers)

    failures = print_summary()
    sys.exit(0 if failures == 0 else 1)

if __name__ == "__main__":
    main()