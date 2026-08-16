from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from datetime import datetime
from app.db.base import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = Column(String(100), nullable=True)
    role = Column(String(50), nullable=True)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    payload_diff = Column(JSON, nullable=True)