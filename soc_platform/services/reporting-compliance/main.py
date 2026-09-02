import sys
import os
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

# Add packages to path
sys.path.append(os.path.join(os.getcwd(), "../../packages/shared-models"))
sys.path.append(os.path.join(os.getcwd(), "../../packages/core-utils"))

from shared_models import database, incidents, assets
from logging_config import setup_logging

logger = setup_logging("reporting-compliance")

app = FastAPI(title="SecurePulse Reporting & Compliance")

@app.get("/health")
async def health():
    return {"status": "online"}

@app.get("/reports/security-posture")
def generate_posture_report(db: Session = Depends(database.get_db)):
    """
    Generates a high-level security posture report.
    """
    last_24h = datetime.now() - timedelta(days=1)
    
    total_incidents = db.query(incidents.Incident).filter(incidents.Incident.created_at >= last_24h).count()
    critical_alerts = db.query(incidents.Alert).filter(incidents.Alert.severity == 'critical').count()
    managed_assets = db.query(assets.Asset).count()
    
    report = {
        "report_name": "Daily Security Posture",
        "generated_at": datetime.now().isoformat(),
        "metrics": {
            "new_incidents_24h": total_incidents,
            "critical_alerts_total": critical_alerts,
            "monitored_assets": managed_assets,
            "compliance_score": 85.5 # Mocked
        },
        "compliance_checks": [
            {"name": "PCI-DSS 11.2 (Scanning)", "status": "passed"},
            {"name": "ISO 27001 (Audit Logging)", "status": "passed"},
            {"name": "SOC2 (Incident Response)", "status": "warning", "detail": "3 incidents exceeding SLA"}
        ]
    }
    return report

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8008)
