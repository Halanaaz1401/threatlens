import logging
from sqlalchemy.orm import Session
import asyncio

from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.indicator import Indicator, ThreatSeverity
from app.core.websocket import ws_manager

logger = logging.getLogger(__name__)

def evaluate_ioc_for_alerts(db: Session, indicator: Indicator) -> Alert | None:
    """
    Evaluates IOC against alerting threshold rules (PRD Section 6.4).
    Triggers Alert if IOC is CRITICAL/HIGH or threat_score >= 60.
    """
    try:
        # Severity check (Threshold rule)
        is_high_threat = (
            indicator.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL] or 
            indicator.threat_score >= 60
        )

        if not is_high_threat:
            return None

        alert_sev = AlertSeverity.CRITICAL if (indicator.severity == ThreatSeverity.CRITICAL or indicator.threat_score >= 85) else AlertSeverity.HIGH

        new_alert = Alert(
            title=f"Threat Detected: {indicator.value}",
            description=f"Automated alert triggered for {indicator.type.value if hasattr(indicator.type, 'value') else indicator.type} from {indicator.source} with score {indicator.threat_score}.",
            severity=alert_sev,
            status=AlertStatus.NEW,
            indicator_id=indicator.id,
            rule_name="SEVERITY_THRESHOLD_RULE",
            context={
                "ioc_value": indicator.value,
                "threat_score": indicator.threat_score,
                "source": indicator.source,
                "tags": indicator.tags
            }
        )

        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        # Broadcast via WebSocket
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                alert_payload = {
                    "id": str(new_alert.id),
                    "title": new_alert.title,
                    "severity": new_alert.severity.value,
                    "status": new_alert.status.value,
                    "ioc_value": indicator.value,
                    "threat_score": indicator.threat_score,
                    "created_at": new_alert.created_at.isoformat()
                }
                loop.create_task(ws_manager.broadcast_alert(alert_payload))
        except Exception:
            pass

        return new_alert
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating alert for IOC {indicator.value}: {e}")
        return None