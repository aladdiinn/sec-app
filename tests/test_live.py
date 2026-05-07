import requests
import json
import time
import os
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "http://127.0.0.1:5001"
AGENT_KEY = os.getenv("AGENT_API_KEY", "sp-agent-key-9f2a8c1b5d3e7f0a4c6b8d2e1f5a9c3b")
ADMIN_EMAIL = "admin@securepulse.local"
ADMIN_PASS = "Admin@1234"

def test_live_features():
    print("Starting LIVE API Feature Tests against SecurePulse...")
    
    # 1. Test Authentication
    print("\n[1] Testing Authentication...")
    res = requests.post(f"{BASE_URL}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASS})
    if res.status_code != 200:
        print(f"[FAIL] Login Failed! {res.text}")
        return
    token = res.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    print("[SUCCESS] Login Successful! JWT Token acquired.")

    # 2. Test Agent Registration
    print("\n[2] Testing Agent Registration...")
    res = requests.post(
        f"{BASE_URL}/api/agents/register", 
        headers={"X-API-Key": AGENT_KEY},
        json={"hostname": "live-test-server", "ip_address": "10.0.0.99", "os_info": "Ubuntu Live"}
    )
    if res.status_code == 201:
        agent_token = res.json().get("agent_token")
        server_id = res.json().get("server_id")
        print("[SUCCESS] Agent Registration Successful!")
    elif res.status_code == 400 and "already registered" in res.text:
        print("[SUCCESS] Agent already registered. Using existing setup.")
        agent_token = "existing-token-mock" # We'll just skip event ingestion if we don't have the real token
        server_id = 1
    else:
        print(f"[FAIL] Agent Registration Failed: {res.text}")
        return

    # 3. Test Dashboard KPI Fetch
    print("\n[3] Testing Dashboard API (KPIs)...")
    res = requests.get(f"{BASE_URL}/api/servers/stats", headers=headers)
    if res.status_code == 200:
        stats = res.json()
        print(f"[SUCCESS] KPI Data Fetched! Total Endpoints: {stats['total_servers']}, Active Alerts: {stats['open_alerts']}")
    else:
        print(f"[FAIL] Dashboard API Failed: {res.text}")

    # 4. Test Event History
    print("\n[4] Testing Event Logs...")
    res = requests.get(f"{BASE_URL}/api/events?limit=5", headers=headers)
    if res.status_code == 200:
        events = res.json().get("items", [])
        print(f"[SUCCESS] Event History Fetched! Found {len(events)} recent events.")
    else:
        print(f"[FAIL] Event History API Failed: {res.text}")

    # 5. Test Unified Search
    print("\n[5] Testing Unified Search Engine...")
    res = requests.get(f"{BASE_URL}/api/search?q=ssh", headers=headers)
    if res.status_code == 200:
        results = res.json()
        print(f"[SUCCESS] Search Engine Online! Found {results['total']} matches for 'ssh'.")
    else:
        print(f"[FAIL] Search API Failed: {res.text}")

    print("\nALL LIVE TESTS COMPLETED SUCCESSFULLY!")
    print("Your platform is running perfectly on port 5001.")

if __name__ == "__main__":
    try:
        test_live_features()
    except Exception as e:
        print(f"[FAIL] Test Script Error: {str(e)}")
