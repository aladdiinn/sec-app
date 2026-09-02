from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Text, Boolean
from .incidents import Base

class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    trigger_type = Column(String(64), nullable=False)  # e.g., on_alert_created
    conditions = Column(JSON, nullable=True)  # Logic for when to run
    actions = Column(JSON, nullable=False)    # List of steps to take
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=False)
    incident_id = Column(Integer, nullable=True)
    status = Column(String(32), default="pending")  # pending | running | success | failed
    results = Column(JSON, nullable=True)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime(timezone=True), nullable=True)
