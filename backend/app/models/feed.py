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
    display_name = Column(String(100), nullable=True)
    provider = Column(String(100), nullable=True)
    feed_type = Column(String(50), nullable=True)
    endpoint_url = Column(String(500), nullable=True)
    description = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    status = Column(String(50), default="active")  # active, disabled, failing, error
    poll_interval_seconds = Column(Integer, default=3600)
    last_polled_at = Column(DateTime, nullable=True)
    last_successful_fetch_at = Column(DateTime, nullable=True)
    last_attempted_fetch_at = Column(DateTime, nullable=True)
    error_message = Column(String, nullable=True)
    total_indicators_ingested = Column(Integer, default=0)
    last_ingested_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
