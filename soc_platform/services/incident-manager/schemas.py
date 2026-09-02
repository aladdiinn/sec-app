from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class AlertBase(BaseModel):
    server_id: int
    alert_type: str
    severity: str
    title: str
    description: str
    mitre_attack_id: Optional[str] = None

class AlertCreate(AlertBase):
    pass

class Alert(AlertBase):
    id: int
    case_id: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True

class CaseBase(BaseModel):
    title: str
    status: str = "open"
    priority: str = "medium"
    summary: Optional[str] = None

class CaseCreate(CaseBase):
    pass

class Case(BaseBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]
    alerts: List[Alert] = []

    class Config:
        from_attributes = True
