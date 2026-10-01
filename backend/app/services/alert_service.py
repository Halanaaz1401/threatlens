import logging
import asyncio
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.indicator import Indicator, ThreatSeverity
from app.core.config import settings
from app.core.redis import redis_manager
from app.core.websocket import ws_manager

logger = logging.getLogger("threatlens.alert_service")

def evaluate_ioc_for_alerts(db: Session, indicator: Indicator) -> Alert | None:
    """
    Evaluates IOC against alerting threshold rules (PRD Section 6.4).
    Triggers Alert if IOC is CRITICAL/HIGH or threat_score >= 60.
    Persists to PostgreSQL, checks deduplication, writes audit event,
    and publishes structured event to Redis Pub/Sub for real-time WebSocket fan-out.
    """
    try:
        # Severity threshold check
        is_high_threat = (
            str(indicator.severity).upper() in ["HIGH", "CRITICAL", ThreatSeverity.HIGH.value, ThreatSeverity.CRITICAL.value] or 
            indicator.threat_score >= 60
        )

        if not is_high_threat:
            return None

        # Deduplication: Check if active/open alert already exists for this indicator
        active_statuses = [
            AlertStatus.NEW.value, AlertStatus.ACKNOWLEDGED.value, AlertStatus.IN_PROGRESS.value,
            "new", "acknowledged", "in_progress", "NEW", "ACKNOWLEDGED", "IN_PROGRESS"
        ]
        existing_alert = db.query(Alert).filter(
            (Alert.indicator_id == indicator.id) | (Alert.indicator_value == indicator.value),
            Alert.status.in_(active_statuses)
        ).first()

        if existing_alert:
            # Update severity score and sightings if new score is higher
            if indicator.threat_score > (existing_alert.severity_score or 0):
                existing_alert.severity_score = indicator.threat_score
                if indicator.threat_score >= 85:
                    existing_alert.severity = AlertSeverity.CRITICAL.value
                db.commit()
            return existing_alert

        # Determine severity level
        is_crit = (
            str(indicator.severity).upper() in ["CRITICAL", ThreatSeverity.CRITICAL.value] or 
            indicator.threat_score >= 85
        )
        alert_sev = AlertSeverity.CRITICAL if is_crit else AlertSeverity.HIGH
        raw_type = indicator.type.value if hasattr(indicator.type, 'value') else str(indicator.type)
        alert_code = f"ALT-{str(indicator.id)[:8].upper()}"

        new_alert = Alert(
            alert_code=alert_code,
            title=f"Threat Detected: {indicator.value}",
            description=f"Automated threat alert triggered for {raw_type} from {indicator.source} with score {indicator.threat_score}.",
            severity=alert_sev.value,
            severity_score=indicator.threat_score,
            status=AlertStatus.NEW.value,
            indicator_id=indicator.id,
            indicator_value=indicator.value,
            source=indicator.source or "ThreatLens Ingestion",
            mitre_technique=indicator.mitre_technique or "T1071",
            rule_name="SEVERITY_THRESHOLD_RULE",
            context={
                "ioc_value": indicator.value,
                "threat_score": indicator.threat_score,
                "source": indicator.source,
                "tags": indicator.tags or [],
                "alert_code": alert_code
            }
        )

        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        # Audit Event Logging
        try:
            from app.services.audit_service import log_action
            log_action(
                db=db,
                action="ALERT_GENERATED",
                actor="SYSTEM_ALERT_ENGINE",
                target_resource=f"alert:{new_alert.id}",
                details={
                    "alert_id": str(new_alert.id),
                    "alert_code": new_alert.alert_code,
                    "title": new_alert.title,
                    "severity": new_alert.severity,
                    "indicator_value": indicator.value,
                    "threat_score": indicator.threat_score,
                    "source": indicator.source
                }
            )
        except Exception as audit_err:
            logger.debug(f"Audit log entry skipped: {audit_err}")

        # Construct Canonical Event Payload
        alert_payload = {
            "type": "NEW_ALERT",
            "event": "NEW_CRITICAL_ALERT",
            "channel": settings.REDIS_ALERT_CHANNEL,
            "timestamp": new_alert.created_at.isoformat() if hasattr(new_alert.created_at, "isoformat") else str(new_alert.created_at),
            "data": {
                "id": str(new_alert.id),
                "alert_code": new_alert.alert_code,
                "title": new_alert.title,
                "severity": str(new_alert.severity),
                "status": str(new_alert.status),
                "indicator": indicator.value,
                "type": raw_type,
                "source": indicator.source,
                "threat_score": indicator.threat_score,
                "severity_score": indicator.threat_score,
                "mitre": indicator.mitre_technique or "T1071",
                "timestamp": new_alert.created_at.isoformat() if hasattr(new_alert.created_at, "isoformat") else str(new_alert.created_at)
            }
        }

        # Publish to Redis Pub/Sub (and local WebSocket bus)
        redis_manager.publish_event(settings.REDIS_ALERT_CHANNEL, alert_payload)
        logger.info(f"Published real-time alert event for IOC {indicator.value} to Redis channel {settings.REDIS_ALERT_CHANNEL}")

        # Phase 4A: Correlate Alert into Security Incident (Step 9)
        try:
            from app.services.correlation_service import correlate_alert_to_incident
            correlate_alert_to_incident(db, new_alert)
        except Exception as corr_err:
            logger.error(f"Correlation engine error for Alert {new_alert.id}: {corr_err}")

        return new_alert

    except Exception as e:
        db.rollback()
        logger.error(f"Error evaluating alert for IOC {getattr(indicator, 'value', 'unknown')}: {e}")
        return None