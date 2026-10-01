import logging
import uuid
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.indicator import Indicator, ThreatSeverity
from app.models.incident import (
    Incident,
    IncidentTimeline,
    IncidentSeverity,
    IncidentStatus,
    SecurityEvent,
    is_valid_status_transition,
    VALID_STATUS_TRANSITIONS
)
from app.core.config import settings
from app.core.redis import redis_manager
from app.services.audit_service import log_action

logger = logging.getLogger("threatlens.correlation_service")

# ---------------------------------------------------------------------------
# Phase 4A Deterministic Correlation Scoring Weights (Documented)
# ---------------------------------------------------------------------------
# SAME_IOC_WEIGHT: Identical IOC indicator value match (High Confidence) -> 40 pts
# SAME_HOST_WEIGHT: Same affected internal endpoint / workstation -> 30 pts
# SAME_MITRE_WEIGHT: Same MITRE ATT&CK technique (e.g. T1071) -> 20 pts
# SAME_SOURCE_WEIGHT: Same threat intelligence feed provenance -> 10 pts
# TEMPORAL_PROXIMITY_WEIGHT: Activity detected within correlation window -> 15 pts
# CLUSTERING_THRESHOLD: Minimum correlation score to merge into existing incident -> 50 pts
# ---------------------------------------------------------------------------
WEIGHT_SAME_IOC = 40
WEIGHT_SAME_HOST = 30
WEIGHT_SAME_MITRE = 20
WEIGHT_SAME_SOURCE = 10
WEIGHT_TEMPORAL = 15
CLUSTERING_THRESHOLD = 50

# Active incident statuses eligible for alert correlation
ACTIVE_INCIDENT_STATUSES = [
    IncidentStatus.OPEN.value,
    IncidentStatus.ACKNOWLEDGED.value,
    IncidentStatus.IN_PROGRESS.value,
    IncidentStatus.INVESTIGATING.value,
    "OPEN",
    "ACKNOWLEDGED",
    "IN_PROGRESS",
    "INVESTIGATING"
]

def normalize_ioc_value(value: Optional[str]) -> str:
    """Normalize IOC value for deterministic fuzzy comparison."""
    if not value:
        return ""
    v = value.strip().lower()
    # Strip URL schemes and trailing slashes for domain/host correlation
    if v.startswith("http://"):
        v = v[7:]
    elif v.startswith("https://"):
        v = v[8:]
    return v.rstrip("/")

def evaluate_correlation(alert: Alert, incident: Incident, window_minutes: int = 15) -> Tuple[int, List[str], str]:
    """
    Evaluates correlation between an Alert and an existing Incident.
    Returns (correlation_score, explanation_factors, explanation_summary).
    Deterministic, explainable, and grounded in multi-dimensional telemetry signals.
    """
    score = 0
    factors: List[str] = []

    # 1. Temporal Proximity Dimension
    now = alert.created_at or datetime.utcnow()
    incident_last_seen = incident.last_seen or incident.created_at or now
    time_delta = abs((now - incident_last_seen).total_seconds()) / 60.0

    if time_delta <= window_minutes:
        # Scale temporal score slightly higher for immediate proximity (< 5 mins)
        temporal_pts = WEIGHT_TEMPORAL if time_delta <= 5.0 else max(5, int(WEIGHT_TEMPORAL * (1.0 - (time_delta / window_minutes))))
        score += temporal_pts
        factors.append(f"temporal proximity ({round(time_delta, 1)}m delta in {window_minutes}m window)")
    else:
        # Outside temporal correlation window
        return 0, [], "Outside correlation time window"

    # 2. Same IOC Dimension (Direct indicator match)
    norm_alert_ioc = normalize_ioc_value(alert.indicator_value)
    norm_inc_ioc = normalize_ioc_value(incident.primary_indicator or incident.matched_ioc_value)

    if (alert.indicator_id and incident.indicator_id and alert.indicator_id == incident.indicator_id) or \
       (norm_alert_ioc and norm_inc_ioc and norm_alert_ioc == norm_inc_ioc):
        score += WEIGHT_SAME_IOC
        factors.append(f"same IOC ({alert.indicator_value})")
    elif norm_alert_ioc and norm_inc_ioc and (norm_alert_ioc in norm_inc_ioc or norm_inc_ioc in norm_alert_ioc):
        # Substring / sub-domain correlation
        score += int(WEIGHT_SAME_IOC * 0.7)
        factors.append(f"related IOC value ({alert.indicator_value} related to {incident.primary_indicator})")

    # 3. Same Internal Host / Asset Dimension
    if alert.internal_host and incident.affected_host and alert.internal_host.strip().lower() == incident.affected_host.strip().lower():
        score += WEIGHT_SAME_HOST
        factors.append(f"same affected host ({alert.internal_host})")

    # 4. Same MITRE ATT&CK Technique Dimension
    inc_mitre = incident.mitre_techniques or []
    if isinstance(inc_mitre, str):
        inc_mitre = [inc_mitre]
    if alert.mitre_technique and (alert.mitre_technique in inc_mitre or alert.mitre_technique == getattr(incident, "mitre_technique", None)):
        score += WEIGHT_SAME_MITRE
        factors.append(f"same MITRE technique ({alert.mitre_technique})")

    # 5. Same Threat Source / Provenance Dimension
    if alert.source and incident.primary_source and alert.source.strip().lower() == incident.primary_source.strip().lower():
        score += WEIGHT_SAME_SOURCE
        factors.append(f"same threat source ({alert.source})")

    explanation = f"Correlated because: {'; '.join(factors)}" if factors else "No matching correlation dimensions"
    return score, factors, explanation

def derive_incident_severity(current_severity: str, alerts: List[Alert]) -> str:
    """
    Deterministic Severity / Risk Propagation Rule (Step 8):
    1. Incident severity is never downgraded automatically.
    2. Any CRITICAL alert elevates incident to CRITICAL.
    3. >= 2 HIGH alerts elevate incident to CRITICAL.
    4. Affected host with multiple high-risk alerts elevates incident to CRITICAL.
    """
    severity_order = {
        IncidentSeverity.LOW.value: 1,
        IncidentSeverity.MEDIUM.value: 2,
        IncidentSeverity.HIGH.value: 3,
        IncidentSeverity.CRITICAL.value: 4,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    current_level = severity_order.get(str(current_severity).upper(), 3)

    critical_count = sum(1 for a in alerts if str(a.severity).upper() in ["CRITICAL", "4"])
    high_count = sum(1 for a in alerts if str(a.severity).upper() in ["HIGH", "3"])

    if critical_count >= 1 or high_count >= 2:
        return IncidentSeverity.CRITICAL.value

    if high_count >= 1:
        computed_level = max(current_level, 3)
    else:
        computed_level = current_level

    # Return corresponding severity name
    for sev_name, lvl in severity_order.items():
        if lvl == computed_level:
            return sev_name
    return IncidentSeverity.HIGH.value

def correlate_alert_to_incident(db: Session, alert: Alert) -> Incident:
    """
    Step 9: Correlates incoming Alert to an open Incident or clusters into a new Incident.
    Step 16: Uses database transaction locking to prevent duplicate incident race conditions.
    Emits Redis events and updates chronological incident timeline.
    """
    window_minutes = settings.CORRELATION_WINDOW_MINUTES
    now = alert.created_at or datetime.utcnow()
    window_start = now - timedelta(minutes=window_minutes)

    # 1. Query candidate active incidents within the time window
    # In PostgreSQL, with_for_update locks matching rows to prevent concurrency race conditions
    candidate_query = db.query(Incident).filter(
        Incident.status.in_(ACTIVE_INCIDENT_STATUSES),
        Incident.last_seen >= window_start
    ).order_by(desc(Incident.last_seen))

    try:
        candidates = candidate_query.with_for_update().all()
    except Exception:
        # Fallback for SQLite in unit tests which doesn't support with_for_update
        candidates = candidate_query.all()

    best_incident: Optional[Incident] = None
    best_score = 0
    best_explanation = ""

    for inc in candidates:
        score, factors, explanation = evaluate_correlation(alert, inc, window_minutes)
        if score >= CLUSTERING_THRESHOLD and score > best_score:
            best_score = score
            best_incident = inc
            best_explanation = explanation

    if best_incident:
        # -------------------------------------------------------------------
        # Existing Incident Match Found: Attach Alert & Propagate
        # -------------------------------------------------------------------
        alert.incident_id = best_incident.id
        best_incident.last_seen = now
        best_incident.correlation_score = max(best_incident.correlation_score or 0, best_score)

        # Merge MITRE techniques
        current_techniques = list(best_incident.mitre_techniques or [])
        if alert.mitre_technique and alert.mitre_technique not in current_techniques:
            current_techniques.append(alert.mitre_technique)
            best_incident.mitre_techniques = current_techniques

        # Update affected host if previously unknown
        if not best_incident.affected_host and alert.internal_host:
            best_incident.affected_host = alert.internal_host

        # Re-evaluate Severity Propagation
        old_sev = str(best_incident.severity).upper()
        attached_alerts = list(best_incident.alerts or [])
        if alert not in attached_alerts:
            attached_alerts.append(alert)
        new_sev = derive_incident_severity(old_sev, attached_alerts)
        severity_changed = (new_sev != old_sev)
        best_incident.severity = new_sev

        # Add Timeline Entry for Correlated Alert
        timeline_entry = IncidentTimeline(
            incident_id=best_incident.id,
            action="ALERT_CORRELATED",
            details=f"Alert {alert.alert_code or alert.id} attached. {best_explanation} (Correlation Score: {best_score}).",
            actor="Correlation Engine",
            created_at=now
        )
        db.add(timeline_entry)

        if severity_changed:
            sev_timeline = IncidentTimeline(
                incident_id=best_incident.id,
                action="SEVERITY_ESCALATED",
                details=f"Incident severity escalated: {old_sev} -> {new_sev} due to multi-alert threat threshold.",
                actor="Risk Engine",
                created_at=now
            )
            db.add(sev_timeline)

        db.commit()
        db.refresh(best_incident)

        # Emit Redis Incident Event
        event_type = "INCIDENT_SEVERITY_CHANGED" if severity_changed else "INCIDENT_UPDATED"
        publish_incident_event(best_incident, event_type, explanation=best_explanation)

        # Audit Log
        log_action(
            db=db,
            action=event_type,
            actor="CORRELATION_ENGINE",
            target_resource=f"incident:{best_incident.id}",
            details={
                "incident_id": str(best_incident.id),
                "incident_code": best_incident.incident_code,
                "attached_alert_id": str(alert.id),
                "alert_code": alert.alert_code,
                "correlation_score": best_score,
                "severity": best_incident.severity,
                "explanation": best_explanation
            }
        )

        logger.info(f"Attached Alert {alert.id} to existing Incident {best_incident.incident_code} (Score: {best_score})")
        return best_incident

    else:
        # -------------------------------------------------------------------
        # No Candidate Match: Create New Clustered Incident
        # -------------------------------------------------------------------
        date_str = now.strftime("%Y%m%d")
        inc_code = f"INC-{date_str}-{str(uuid.uuid4())[:6].upper()}"
        initial_score = WEIGHT_SAME_IOC + WEIGHT_TEMPORAL

        mitre_list = [alert.mitre_technique] if alert.mitre_technique else ["T1071"]
        inc_title = f"Security Incident: Active Threat Detected ({alert.indicator_value or alert.title})"
        inc_desc = (
            f"Correlated security incident initialized from Alert {alert.alert_code or alert.id} "
            f"for indicator {alert.indicator_value} from {alert.source}."
        )

        new_incident = Incident(
            incident_code=inc_code,
            title=inc_title,
            description=inc_desc,
            severity=alert.severity or IncidentSeverity.HIGH.value,
            status=IncidentStatus.OPEN.value,
            correlation_score=initial_score,
            indicator_id=alert.indicator_id,
            matched_ioc_value=alert.indicator_value,
            primary_indicator=alert.indicator_value,
            primary_source=alert.source,
            mitre_techniques=mitre_list,
            affected_host=alert.internal_host,
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now
        )
        db.add(new_incident)
        db.flush()

        # Link alert to new incident
        alert.incident_id = new_incident.id

        # Timeline Entry for Initial Incident Creation
        creation_timeline = IncidentTimeline(
            incident_id=new_incident.id,
            action="INCIDENT_CREATED",
            details=f"Incident {inc_code} created from Alert {alert.alert_code or alert.id}. Primary indicator: {alert.indicator_value}.",
            actor="Correlation Engine",
            created_at=now
        )
        db.add(creation_timeline)

        db.commit()
        db.refresh(new_incident)

        # Emit Redis Event
        publish_incident_event(new_incident, "INCIDENT_CREATED", explanation="Initial alert threshold match created incident cluster")

        # Audit Log
        log_action(
            db=db,
            action="INCIDENT_CREATED",
            actor="CORRELATION_ENGINE",
            target_resource=f"incident:{new_incident.id}",
            details={
                "incident_id": str(new_incident.id),
                "incident_code": new_incident.incident_code,
                "initial_alert_id": str(alert.id),
                "alert_code": alert.alert_code,
                "primary_indicator": alert.indicator_value,
                "severity": new_incident.severity
            }
        )

        logger.info(f"Created new Incident {new_incident.incident_code} from Alert {alert.id}")
        return new_incident

def publish_incident_event(incident: Incident, event_type: str, explanation: str = ""):
    """
    Publishes structured incident event to Redis Pub/Sub channels (Step 10).
    Publishes to REDIS_INCIDENT_CHANNEL and REDIS_ALERT_CHANNEL for multi-subscriber fan-out.
    """
    try:
        alert_ids = [str(a.id) for a in (incident.alerts or [])]
        payload = {
            "type": event_type,
            "event": event_type,
            "channel": settings.REDIS_INCIDENT_CHANNEL,
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "incident_id": str(incident.id),
                "incident_code": incident.incident_code,
                "title": incident.title,
                "severity": str(incident.severity),
                "status": str(incident.status),
                "correlation_score": incident.correlation_score,
                "primary_indicator": incident.primary_indicator,
                "primary_source": incident.primary_source,
                "affected_host": incident.affected_host,
                "mitre_techniques": incident.mitre_techniques or [],
                "alert_ids": alert_ids,
                "alerts_count": len(alert_ids),
                "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
                "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
                "explanation": explanation
            }
        }
        # Publish to both incident and alert channels so active UI connections receive updates
        redis_manager.publish_event(settings.REDIS_INCIDENT_CHANNEL, payload)
        redis_manager.publish_event(settings.REDIS_ALERT_CHANNEL, payload)
        logger.debug(f"Published {event_type} event for {incident.incident_code} to Redis")
    except Exception as e:
        logger.error(f"Failed to publish Redis incident event: {e}")

# ---------------------------------------------------------------------------
# Lifecycle State Transition & Severity Update Services
# ---------------------------------------------------------------------------

def update_incident_status(
    db: Session,
    incident_id: str,
    new_status: str,
    actor: str = "SOC Analyst",
    note: Optional[str] = None
) -> Incident:
    """
    Validates and executes a controlled state transition for an incident (Step 6).
    Appends to investigation timeline and records immutable audit log.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise ValueError(f"Incident with ID {incident_id} not found")

    old_status = str(incident.status).upper()
    target_status = new_status.upper()

    if not is_valid_status_transition(old_status, target_status):
        raise ValueError(f"Invalid status transition from {old_status} to {target_status}")

    incident.status = target_status
    incident.updated_at = datetime.utcnow()

    # Timeline entry
    timeline_action = "INCIDENT_RESOLVED" if target_status in ["RESOLVED", "CLOSED"] else "STATUS_CHANGED"
    timeline_entry = IncidentTimeline(
        incident_id=incident.id,
        action=f"{timeline_action}: {old_status} -> {target_status}",
        details=note or f"Status updated by {actor}",
        actor=actor,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()
    db.refresh(incident)

    # Redis event
    event_type = "INCIDENT_RESOLVED" if target_status in ["RESOLVED", "CLOSED"] else "INCIDENT_UPDATED"
    publish_incident_event(incident, event_type, explanation=f"Status changed from {old_status} to {target_status}")

    # Audit log
    log_action(
        db=db,
        action=event_type,
        actor=actor,
        target_resource=f"incident:{incident.id}",
        details={
            "incident_id": str(incident.id),
            "incident_code": incident.incident_code,
            "old_status": old_status,
            "new_status": target_status,
            "note": note
        }
    )

    return incident

def update_incident_severity(
    db: Session,
    incident_id: str,
    new_severity: str,
    actor: str = "SOC Analyst",
    reason: Optional[str] = None
) -> Incident:
    """
    Validates and updates incident severity with audit trail and timeline.
    """
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise ValueError(f"Incident with ID {incident_id} not found")

    old_sev = str(incident.severity).upper()
    target_sev = new_severity.upper()

    valid_severities = [s.value for s in IncidentSeverity]
    if target_sev not in valid_severities:
        raise ValueError(f"Invalid severity '{new_severity}'. Must be one of: {valid_severities}")

    incident.severity = target_sev
    incident.updated_at = datetime.utcnow()

    timeline_entry = IncidentTimeline(
        incident_id=incident.id,
        action=f"SEVERITY_CHANGED: {old_sev} -> {target_sev}",
        details=reason or f"Severity manually updated by {actor}",
        actor=actor,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()
    db.refresh(incident)

    publish_incident_event(incident, "INCIDENT_SEVERITY_CHANGED", explanation=f"Severity updated from {old_sev} to {target_sev}")

    log_action(
        db=db,
        action="INCIDENT_SEVERITY_CHANGED",
        actor=actor,
        target_resource=f"incident:{incident.id}",
        details={
            "incident_id": str(incident.id),
            "incident_code": incident.incident_code,
            "old_severity": old_sev,
            "new_severity": target_sev,
            "reason": reason
        }
    )

    return incident

# Legacy function preserved for backward compatibility with older route tests
def correlate_and_create_incident(db: Session, event_data: dict) -> Incident | None:
    """
    Legacy internal telemetry security event correlation.
    Maintained for backward compatibility with POST /api/v1/incidents/correlate-event.
    """
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

    # Construct alert-like object and run correlation engine
    telemetry_alert = Alert(
        title=f"Internal Event Match: {matched_ioc.value}",
        description=f"Internal event matched IOC {matched_ioc.value}",
        severity=AlertSeverity.CRITICAL.value if matched_ioc.severity == ThreatSeverity.CRITICAL else AlertSeverity.HIGH.value,
        status=AlertStatus.NEW.value,
        indicator_id=matched_ioc.id,
        indicator_value=matched_ioc.value,
        source="Internal Security Event",
        internal_host=event_data.get("source_ip") or "internal_host"
    )
    db.add(telemetry_alert)
    db.commit()
    db.refresh(telemetry_alert)

    return correlate_alert_to_incident(db, telemetry_alert)