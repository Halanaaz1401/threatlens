import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text
from app.db.base import Base

class WebhookConfig(Base):
    """
    Configuration and operational telemetry for Inbound SIEM/EDR Webhook Integrations (FR-29).
    Providers: splunk, qradar, sentinel, crowdstrike, elastic
    """
    __tablename__ = "webhook_configs"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    provider = Column(String(50), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    is_enabled = Column(Boolean, default=True, nullable=False)
    secret_token = Column(String(255), nullable=True)  # Secret token or key hash
    hmac_secret = Column(String(255), nullable=True)   # Optional HMAC secret for signed payloads
    total_events_received = Column(Integer, default=0, nullable=False)
    last_received_at = Column(DateTime, nullable=True)
    last_status = Column(String(50), default="idle", nullable=False)  # idle, active, error
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
