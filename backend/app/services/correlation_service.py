import logging
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.indicator import Indicator, ThreatSeverity
from app.models.incident import SecurityEvent, Incident, IncidentTimeline, IncidentSeverity, IncidentStatus

logger = logging.getLogger(__name__)

def correlate_and_create_incident(db: Session, event_data: dict) -> Incident | None:
    """
    Correlates an incoming internal security event against Threat Intelligence IOCs.
    If a match is detected, an Incident is raised with automated timeline tracking.
    """
    # 1. Store the raw security event
    sec_event = SecurityEvent(
        source_ip=event_data.get("source_ip"),
        destination_ip=event_data.get("destination_ip"),
        domain=event_data.get("domain"),
        file_hash=event_data.get("file_hash"),
        event_type=event_data.get("event_type", "NETWORK_LOG"),
        raw_log=event_data.get("raw_log")
    )
    db.add(sec_event)
    db.commit()

    # 2. Check for matching IOCs
    candidates = [
        event_data.get("source_ip"),
        event_data.get("destination_ip"),
        event_data.get("domain"),
        event_data.get("file_hash")
    ]
    extracted_vals = [c for c in candidates if c]

    matched_ioc = db.query(Indicator).filter(Indicator.value.in_(extracted_vals)).first()

    if not matched_ioc:
        return None

    # 3. Create Incident
    inc_sev = IncidentSeverity.CRITICAL if matched_ioc.severity == ThreatSeverity.CRITICAL else IncidentSeverity.HIGH
    
    incident = Incident(
        title=f"Security Incident: Active Communication with Malicious IOC ({matched_ioc.value})",
        description=f"Internal event correlated with threat intelligence IOC '{matched_ioc.value}' sourced from {matched_ioc.source} (Threat Score: {matched_ioc.threat_score}).",
        severity=inc_sev,
        status=IncidentStatus.OPEN,
        indicator_id=matched_ioc.id,
        matched_ioc_value=matched_ioc.value
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    # 4. Add Initial Timeline Entry
    initial_timeline = IncidentTimeline(
        incident_id=incident.id,
        action="INCIDENT_OPENED",
        details=f"Automated correlation rule triggered match for IOC {matched_ioc.value} from event log.",
        actor="Correlation Engine"
    )
    db.add(initial_timeline)
    db.commit()

    return incident