import sys
import os
from fastapi import FastAPI, BackgroundTasks
from sqlalchemy.orm import Session
import requests

# Add packages to path
sys.path.append(os.path.join(os.getcwd(), "../../packages/shared-models"))
sys.path.append(os.path.join(os.getcwd(), "../../packages/core-utils"))

from shared_models import database, assets
from logging_config import setup_logging

logger = setup_logging("asset-discovery")

app = FastAPI(title="SecurePulse Asset Discovery")

@app.get("/health")
async def health():
    return {"status": "online"}

@app.post("/scan")
async def trigger_scan(subnet: str, background_tasks: BackgroundTasks):
    logger.info(f"Triggering network scan for subnet: {subnet}")
    background_tasks.add_task(perform_network_scan, subnet)
    return {"status": "scan_started", "subnet": subnet}

def perform_network_scan(subnet: str):
    logger.info(f"Starting Nmap-style scan on {subnet}...")
    # Mocking discovery results
    discovered_hosts = [
        {"hostname": "DEV-APP-01", "ip": "10.0.1.50", "os": "linux"},
        {"hostname": "DEV-APP-02", "ip": "10.0.1.51", "os": "linux"}
    ]
    
    # Save to Asset inventory
    db = next(database.get_db())
    for host in discovered_hosts:
        # Check if already exists
        existing = db.query(assets.Asset).filter(assets.Asset.ip_address == host["ip"]).first()
        if not existing:
            new_asset = assets.Asset(
                hostname=host["hostname"],
                ip_address=host["ip"],
                os_type=host["os"],
                status="discovered"
            )
            db.add(new_asset)
            logger.info(f"New asset discovered: {host['hostname']} ({host['ip']})")
    db.commit()
    db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8006)
