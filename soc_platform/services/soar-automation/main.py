import sys
import os
from fastapi import FastAPI, BackgroundTasks
import engine
from logging_config import setup_logging

# Add packages to path
sys.path.append(os.path.join(os.getcwd(), "../../packages/core-utils"))
from logging_config import setup_logging

logger = setup_logging("soar-automation")

app = FastAPI(title="SecurePulse SOAR Automation")

@app.get("/health")
async def health():
    return {"status": "online"}

@app.post("/trigger")
async def trigger_playbook(trigger_data: dict, background_tasks: BackgroundTasks):
    """
    Called by Incident Manager when a high-severity alert is created.
    """
    logger.info(f"Trigger received for alert: {trigger_data.get('alert_title')}")
    
    # In a real scenario, we would lookup playbooks from the DB
    # that match the alert_type and trigger_type.
    
    # Mock Playbook for demonstration:
    mock_playbook = {
        "name": "Auto-Contain Brute Force",
        "actions": [
            {"name": "isolate_host"},
            {"name": "notify"}
        ]
    }
    
    background_tasks.add_task(engine.execute_playbook, mock_playbook, trigger_data)
    
    return {"status": "triggered", "playbook": mock_playbook["name"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)
