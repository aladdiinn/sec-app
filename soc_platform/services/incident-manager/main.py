import sys
import os
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

# Add packages to path
sys.path.append(os.path.join(os.getcwd(), "../../packages/shared-models"))
sys.path.append(os.path.join(os.getcwd(), "../../packages/core-utils"))

from shared_models import database, incidents
import schemas
from logging_config import setup_logging

logger = setup_logging("incident-manager")

app = FastAPI(title="SecurePulse Incident Manager")

@app.get("/health")
async def health():
    return {"status": "online"}

# --- Alert Endpoints ---

@app.post("/alerts", response_model=schemas.Alert)
def create_alert(alert: schemas.AlertCreate, db: Session = Depends(database.get_db)):
    db_alert = incidents.Alert(**alert.model_dump())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    logger.info(f"Created new alert: {db_alert.title}")

    # Trigger SOAR if critical
    if db_alert.severity == "critical":
        SOAR_URL = os.getenv("SOAR_URL", "http://localhost:8004")
        try:
            trigger_data = {
                "alert_id": db_alert.id,
                "alert_title": db_alert.title,
                "server_id": db_alert.server_id,
                "severity": db_alert.severity
            }
            requests.post(f"{SOAR_URL}/trigger", json=trigger_data)
            logger.info(f"SOAR triggered for critical alert {db_alert.id}")
        except Exception as e:
            logger.error(f"Failed to trigger SOAR: {e}")

    return db_alert

@app.get("/alerts", response_model=List[schemas.Alert])
def list_alerts(db: Session = Depends(database.get_db)):
    return db.query(incidents.Alert).all()

# --- Case Endpoints ---

@app.post("/cases", response_model=schemas.Case)
def create_case(case: schemas.CaseCreate, db: Session = Depends(database.get_db)):
    db_case = incidents.Case(**case.model_dump())
    db.add(db_case)
    db.commit()
    db.refresh(db_case)
    logger.info(f"Created new case: {db_case.title}")
    return db_case

@app.get("/cases", response_model=List[schemas.Case])
def list_cases(db: Session = Depends(database.get_db)):
    return db.query(incidents.Case).all()

@app.post("/cases/{case_id}/add-alert/{alert_id}")
def link_alert_to_case(case_id: int, alert_id: int, db: Session = Depends(database.get_db)):
    db_alert = db.query(incidents.Alert).filter(incidents.Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    db_alert.case_id = case_id
    db.commit()
    return {"message": f"Alert {alert_id} linked to case {case_id}"}
