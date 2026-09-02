import sys
import os
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
import requests

# Add packages to path
sys.path.append(os.path.join(os.getcwd(), "../../packages/shared-models"))
sys.path.append(os.path.join(os.getcwd(), "../../packages/core-utils"))

from shared_models import database, threat_intel
from logging_config import setup_logging

logger = setup_logging("threat-intel")

app = FastAPI(title="SecurePulse Threat Intelligence")

@app.get("/health")
async def health():
    return {"status": "online"}

@app.post("/sync")
async def sync_feeds():
    """
    Syncs with external TI feeds (e.g., AlienVault, MISP).
    """
    logger.info("Syncing with external threat feeds...")
    
    # Mock data from a feed
    mock_iocs = [
        {"type": "ipv4", "value": "1.2.3.4", "source": "AlienVault", "severity": "high"},
        {"type": "domain", "value": "malware-site.com", "source": "Internal", "severity": "critical"}
    ]
    
    db = next(database.get_db())
    for ioc in mock_iocs:
        existing = db.query(threat_intel.ThreatIndicator).filter(threat_intel.ThreatIndicator.value == ioc["value"]).first()
        if not existing:
            new_ioc = threat_intel.ThreatIndicator(
                indicator_type=ioc["type"],
                value=ioc["value"],
                source=ioc["source"],
                severity=ioc["severity"]
            )
            db.add(new_ioc)
            logger.info(f"New IOC added: {ioc['value']}")
    db.commit()
    db.close()
    return {"status": "success", "added": len(mock_iocs)}

@app.get("/lookup/{value}")
def lookup_ioc(value: str, db: Session = Depends(database.get_db)):
    ioc = db.query(threat_intel.ThreatIndicator).filter(threat_intel.ThreatIndicator.value == value).first()
    if ioc:
        return {"found": True, "details": ioc}
    return {"found": False}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8007)
