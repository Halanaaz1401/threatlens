import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, JSON
from app.db.base import Base

class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = Column(String(36), nullable=True)
    actor = Column(String(100), nullable=True, default="System")
    user = Column(String(100), nullable=True, default="System")
    role = Column(String(50), nullable=True)
    action = Column(String(100), nullable=False)
    target_resource = Column(String(255), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    payload_diff = Column(JSON, nullable=True)