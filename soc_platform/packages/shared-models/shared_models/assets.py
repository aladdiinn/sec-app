from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, JSON
from .incidents import Base

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(64))
    os_type = Column(String(64))  # linux, windows, macos
    os_version = Column(String(128))
    criticality = Column(String(16), default='medium')  # low, medium, high, mission_critical
    agent_version = Column(String(32))
    last_seen = Column(DateTime(timezone=True))
    status = Column(String(32), default='unknown')
    tags = Column(JSON)  # For custom groupings
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
