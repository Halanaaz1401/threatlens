import uuid
import enum
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime
from app.db.base import Base

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    SECURITY_ENGINEER = "security_engineer"
    ANALYST = "analyst"
    SOC_ANALYST = "soc_analyst"
    INCIDENT_RESPONDER = "incident_responder"
    THREAT_HUNTER = "threat_hunter"
    VIEWER = "viewer"
    EXECUTIVE = "executive"

# Alias for compatibility
Role = UserRole

class User(Base):
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="viewer", nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

__all__ = ["User", "UserRole", "Role"]
