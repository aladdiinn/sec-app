from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

app = FastAPI(title="SecurePulse SOC Command Center")

# Setup templates and static files
templates = Jinja2Templates(directory="templates")
# app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def dashboard(request: Request):
    # ... (stats and alerts logic)
    stats = {
        "total_alerts": 128,
        "open_cases": 12,
        "active_threats": 5,
        "online_servers": 42
    }
    recent_alerts = [
        {"id": 1, "title": "Brute Force Attempt", "severity": "high", "time": "2m ago"},
        {"id": 2, "title": "Suspicious Process", "severity": "medium", "time": "15m ago"},
        {"id": 3, "title": "Shadow File Mod", "severity": "critical", "time": "1h ago"},
    ]
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "stats": stats,
        "recent_alerts": recent_alerts
    })

@app.get("/assets")
async def asset_inventory(request: Request):
    # Mock data for demonstration
    mock_assets = [
        {"hostname": "PROD-WEB-01", "ip_address": "10.0.1.10", "os_type": "Linux", "status": "online", "criticality": "high"},
        {"hostname": "PROD-DB-01", "ip_address": "10.0.1.20", "os_type": "Linux", "status": "online", "criticality": "mission_critical"},
        {"hostname": "DEV-APP-01", "ip_address": "10.0.1.50", "os_type": "Linux", "status": "discovered", "criticality": "low"},
    ]
    return templates.TemplateResponse("assets.html", {
        "request": request,
        "assets": mock_assets
    })

@app.get("/threat-intel")
async def threat_intelligence(request: Request):
    # Mock data for demonstration
    mock_iocs = [
        {"type": "ipv4", "value": "185.220.101.42", "source": "AlienVault", "severity": "critical"},
        {"type": "domain", "value": "malware-cnc-server.top", "source": "Internal", "severity": "high"},
        {"type": "file_hash", "value": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "source": "MISP", "severity": "medium"},
    ]
    return templates.TemplateResponse("threat_intel.html", {
        "request": request,
        "iocs": mock_iocs
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)
