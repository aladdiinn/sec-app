from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from .incidents import Base

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True)
    indicator_type = Column(String(32), nullable=False)  # ipv4 | domain | file_hash | url
    value = Column(String(512), nullable=False, index=True)
    source = Column(String(128), nullable=True)  # e.g., AlienVault, MISP
    confidence = Column(Integer, default=50)  # 0-100
    severity = Column(String(16), default="medium")
    last_seen = Column(DateTime(timezone=True))
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
