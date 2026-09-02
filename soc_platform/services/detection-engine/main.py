import sys
import os
import json
import redis
from fastapi import FastAPI, BackgroundTasks
import requests
import rules
from logging_config import setup_logging

# Add packages to path
sys.path.append(os.path.join(os.getcwd(), "../../packages/core-utils"))
from logging_config import setup_logging

logger = setup_logging("detection-engine")

app = FastAPI(title="SecurePulse Detection Engine")

# Redis for sliding window event history
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=6379,
    db=0,
    decode_responses=True
)

INCIDENT_MANAGER_URL = os.getenv("INCIDENT_MANAGER_URL", "http://localhost:8001")
EVENT_HISTORY_WINDOW = 300  # 5 minutes

@app.get("/health")
async def health():
    return {"status": "online"}

@app.post("/events/process")
async def process_event(event: dict, background_tasks: BackgroundTasks):
    background_tasks.add_task(analyze_event, event)
    return {"status": "queued"}

def analyze_event(event: dict):
    server_id = event.get("server_id")
    
    # 1. Fetch history from Redis
    history_key = f"event_history:{server_id}"
    raw_history = redis_client.lrange(history_key, 0, -1)
    event_history = [json.loads(e) for e in raw_history]
    
    # 2. Check rules (passing current event + history)
    triggered_rules = rules.check_rules(event, event_history)
    
    # --- TI INTEGRATION ---
    # Perform real-time IOC lookup for IP addresses
    ip_to_check = event.get("raw_data", {}).get("ip")
    if ip_to_check:
        TI_URL = os.getenv("TI_URL", "http://localhost:8007")
        try:
            ti_resp = requests.get(f"{TI_URL}/lookup/{ip_to_check}", timeout=1)
            if ti_resp.status_code == 200 and ti_resp.json().get("found"):
                ioc_details = ti_resp.json()["details"]
                logger.warning(f"IOC MATCH DETECTED: {ip_to_check} is a known threat ({ioc_details['source']})")
                
                # Add a synthetic "IOC Match" rule to trigger an alert
                triggered_rules.append({
                    "id": "ioc_match_ip",
                    "title": f"Known Malicious IP Detected: {ip_to_check}",
                    "description": f"IP found in threat feed: {ioc_details['description']}",
                    "severity": ioc_details["severity"],
                    "mitre_id": "T1589"
                })
        except Exception as e:
            logger.error(f"TI Lookup Error: {e}")
    # -----------------------

    for rule in triggered_rules:
        logger.warning(f"Rule Triggered: {rule['title']} for server {server_id}")
        
        # Create Alert in Incident Manager
        alert_data = {
            "server_id": server_id,
            "alert_type": rule["id"],
            "severity": rule["severity"],
            "title": rule["title"],
            "description": rule["description"],
            "mitre_attack_id": rule["mitre_id"]
        }
        
        try:
            requests.post(f"{INCIDENT_MANAGER_URL}/alerts", json=alert_data, timeout=2)
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")

    # 3. Store event in Redis history (sliding window)
    redis_client.lpush(history_key, json.dumps(event))
    redis_client.ltrim(history_key, 0, 100)  # Keep last 100 events
    redis_client.expire(history_key, EVENT_HISTORY_WINDOW)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
