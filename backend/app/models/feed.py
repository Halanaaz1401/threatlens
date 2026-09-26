import uuid
from sqlalchemy import Column, String, Boolean, DateTime, Integer
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timezone
from app.db.base import Base

class Feed(Base):
    __tablename__ = "feeds"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, nullable=False)
    enabled = Column(Boolean, default=True)
    poll_interval_seconds = Column(Integer, default=3600)
    last_polled_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
