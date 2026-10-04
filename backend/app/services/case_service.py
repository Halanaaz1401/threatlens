import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc, func

from app.models.case import (
    Case,
    CaseStatus,
    CaseSeverity,
    CasePriority,
    CaseIncident,
    CaseAlert,
    CaseIndicator,
    CaseEvidence,
    CaseNote,
    CaseTimeline,
    is_valid_case_status_transition,
    VALID_CASE_STATUS_TRANSITIONS
)
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.indicator import Indicator
from app.models.audit import AuditLog
from app.services.audit_service import log_action
from app.core.redis import publish_case_event

logger = logging.getLogger("threatlens.case_service")

def generate_case_number(db: Session) -> str:
    """Generate deterministic case reference code: CASE-YYYY-XXXX."""
    year = datetime.now(timezone.utc).year
    prefix = f"CASE-{year}-"
    
    # Query highest sequence for the current year
    last_case = db.query(Case).filter(Case.case_number.like(f"{prefix}%")).order_by(desc(Case.case_number)).first()
    if last_case and last_case.case_number:
        try:
            seq_part = last_case.case_number.replace(prefix, "")
            next_seq = int(seq_part) + 1
        except Exception:
            next_seq = db.query(func.count(Case.id)).scalar() + 1
    else:
        next_seq = 1
        
    return f"{prefix}{next_seq:04d}"

def create_case(
    db: Session,
    title: str,
    description: Optional[str] = None,
    severity: str = "MEDIUM",
    priority: str = "P2",
    creator: str = "System",
    source: str = "Manual",
    tags: Optional[List[str]] = None,
    owner: Optional[str] = None,
    assignee: Optional[str] = None,
) -> Case:
    """Create a new investigation case with timeline recording and audit log."""
    sev = severity.upper() if severity else "MEDIUM"
    if sev not in [s.value for s in CaseSeverity]:
        sev = "MEDIUM"

    prio = priority.upper() if priority else "P2"
    if prio not in [p.value for p in CasePriority]:
        prio = "P2"

    case_num = generate_case_number(db)
    new_case = Case(
        case_number=case_num,
        title=title.strip(),
        description=description.strip() if description else None,
        severity=sev,
        priority=prio,
        status=CaseStatus.OPEN.value,
        owner=owner.strip() if owner else creator,
        assignee=assignee.strip() if assignee else None,
        source=source,
        tags=tags or [],
        created_by=creator,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    # Initial timeline entry
    timeline_entry = CaseTimeline(
        case_id=new_case.id,
        event_type="CASE_CREATED",
        title="Case Created",
        details=f"Investigation case {case_num} opened: {title}",
        actor=creator,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()

    # Immutable Audit Log
    log_action(
        db=db,
        action="CASE_CREATED",
        actor=creator,
        target_resource=f"case:{new_case.id}",
        details={
            "case_id": new_case.id,
            "case_number": case_num,
            "title": title,
            "severity": sev,
            "priority": prio,
            "source": source
        }
    )

    # Publish Redis Event
    publish_case_event("CASE_CREATED", {
        "case_id": new_case.id,
        "case_number": case_num,
        "title": title,
        "severity": sev,
        "status": CaseStatus.OPEN.value,
        "creator": creator
    })

    return new_case

def update_case_status(
    db: Session,
    case_id: str,
    new_status: str,
    actor: str,
    note: Optional[str] = None
) -> Case:
    """Validate lifecycle transition and update case status."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    target_status = new_status.upper()
    if not is_valid_case_status_transition(case.status, target_status):
        allowed = VALID_CASE_STATUS_TRANSITIONS.get(case.status, [])
        raise ValueError(f"Invalid status transition from {case.status} to {target_status}. Allowed: {allowed}")

    old_status = case.status
    case.status = target_status
    case.updated_at = datetime.utcnow()

    if target_status in [CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value]:
        case.closed_at = datetime.utcnow()
        case.closed_by = actor
    elif old_status in [CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value] and target_status in [CaseStatus.OPEN.value, CaseStatus.IN_PROGRESS.value]:
        # Case reopened
        case.closed_at = None
        case.closed_by = None

    db.commit()
    db.refresh(case)

    # Timeline entry
    timeline_desc = f"Status changed from {old_status} to {target_status}."
    if note:
        timeline_desc += f" Note: {note}"

    timeline_entry = CaseTimeline(
        case_id=case.id,
        event_type="STATUS_CHANGED",
        title=f"Case Status: {target_status}",
        details=timeline_desc,
        actor=actor,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()

    # Audit Log
    log_action(
        db=db,
        action="CASE_STATUS_CHANGED",
        actor=actor,
        target_resource=f"case:{case.id}",
        details={"case_id": case.id, "old_status": old_status, "new_status": target_status, "note": note}
    )

    # Publish Redis Event
    publish_case_event("CASE_STATUS_CHANGED", {
        "case_id": case.id,
        "case_number": case.case_number,
        "old_status": old_status,
        "new_status": target_status,
        "actor": actor
    })

    return case

def update_case(
    db: Session,
    case_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    severity: Optional[str] = None,
    priority: Optional[str] = None,
    assignee: Optional[str] = None,
    owner: Optional[str] = None,
    tags: Optional[List[str]] = None,
    actor: str = "System"
) -> Case:
    """Update general fields of an existing investigation case."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    changes = {}
    if title and title.strip() != case.title:
        changes["title"] = (case.title, title.strip())
        case.title = title.strip()

    if description is not None and description.strip() != (case.description or ""):
        changes["description"] = "updated"
        case.description = description.strip()

    if severity:
        sev = severity.upper()
        if sev in [s.value for s in CaseSeverity] and sev != case.severity:
            changes["severity"] = (case.severity, sev)
            case.severity = sev

    if priority:
        prio = priority.upper()
        if prio in [p.value for p in CasePriority] and prio != case.priority:
            changes["priority"] = (case.priority, prio)
            case.priority = prio

    if assignee is not None and assignee.strip() != (case.assignee or ""):
        changes["assignee"] = (case.assignee, assignee.strip())
        case.assignee = assignee.strip()

    if owner is not None and owner.strip() != (case.owner or ""):
        changes["owner"] = (case.owner, owner.strip())
        case.owner = owner.strip()

    if tags is not None:
        case.tags = tags
        changes["tags"] = tags

    if changes:
        case.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(case)

        # Timeline recording
        timeline_entry = CaseTimeline(
            case_id=case.id,
            event_type="CASE_UPDATED",
            title="Case Metadata Updated",
            details=", ".join([f"{k}: {v}" for k, v in changes.items()]),
            actor=actor,
            created_at=datetime.utcnow()
        )
        db.add(timeline_entry)
        db.commit()

        # Audit Log
        log_action(
            db=db,
            action="CASE_UPDATED",
            actor=actor,
            target_resource=f"case:{case.id}",
            details={"case_id": case.id, "changes": str(changes)}
        )

        publish_case_event("CASE_UPDATED", {
            "case_id": case.id,
            "case_number": case.case_number,
            "actor": actor
        })

    return case

def link_incident_to_case(
    db: Session,
    case_id: str,
    incident_id: str,
    actor: str = "System"
) -> CaseIncident:
    """Link an Incident to a Case (Idempotent)."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    incident = db.query(Incident).filter(or_(Incident.id == incident_id, Incident.incident_code == incident_id)).first()
    if not incident:
        raise ValueError("Incident not found")

    existing = db.query(CaseIncident).filter(
        CaseIncident.case_id == case.id,
        CaseIncident.incident_id == incident.id
    ).first()

    if existing:
        return existing

    link = CaseIncident(
        case_id=case.id,
        incident_id=incident.id,
        linked_at=datetime.utcnow(),
        linked_by=actor
    )
    db.add(link)
    case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(link)

    # Timeline entry
    timeline_entry = CaseTimeline(
        case_id=case.id,
        event_type="INCIDENT_LINKED",
        title=f"Incident Linked: {incident.incident_code or incident.id[:8]}",
        details=f"Incident '{incident.title}' linked by {actor}.",
        actor=actor,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()

    # Audit Log
    log_action(
        db=db,
        action="INCIDENT_LINKED",
        actor=actor,
        target_resource=f"case:{case.id}",
        details={"case_id": case.id, "incident_id": incident.id, "incident_code": incident.incident_code}
    )

    publish_case_event("INCIDENT_LINKED", {
        "case_id": case.id,
        "incident_id": incident.id,
        "actor": actor
    })

    return link

def unlink_incident_from_case(
    db: Session,
    case_id: str,
    incident_id: str,
    actor: str = "System"
) -> bool:
    """Unlink an Incident from a Case."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    incident = db.query(Incident).filter(or_(Incident.id == incident_id, Incident.incident_code == incident_id)).first()
    if not incident:
        raise ValueError("Incident not found")

    link = db.query(CaseIncident).filter(
        CaseIncident.case_id == case.id,
        CaseIncident.incident_id == incident.id
    ).first()

    if not link:
        return False

    db.delete(link)
    case.updated_at = datetime.utcnow()
    db.commit()

    # Timeline entry
    timeline_entry = CaseTimeline(
        case_id=case.id,
        event_type="INCIDENT_UNLINKED",
        title=f"Incident Unlinked: {incident.incident_code or incident.id[:8]}",
        details=f"Incident '{incident.title}' unlinked by {actor}.",
        actor=actor,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()

    # Audit Log
    log_action(
        db=db,
        action="INCIDENT_UNLINKED",
        actor=actor,
        target_resource=f"case:{case.id}",
        details={"case_id": case.id, "incident_id": incident.id}
    )

    return True

def link_alert_to_case(
    db: Session,
    case_id: str,
    alert_id: str,
    actor: str = "System"
) -> CaseAlert:
    """Link an Alert to a Case (Idempotent)."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    alert = db.query(Alert).filter(or_(Alert.id == alert_id, Alert.alert_code == alert_id)).first()
    if not alert:
        raise ValueError("Alert not found")

    existing = db.query(CaseAlert).filter(
        CaseAlert.case_id == case.id,
        CaseAlert.alert_id == alert.id
    ).first()

    if existing:
        return existing

    link = CaseAlert(
        case_id=case.id,
        alert_id=alert.id,
        linked_at=datetime.utcnow(),
        linked_by=actor
    )
    db.add(link)
    case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(link)

    # Timeline
    timeline_entry = CaseTimeline(
        case_id=case.id,
        event_type="ALERT_LINKED",
        title=f"Alert Linked: {alert.alert_code or alert.id[:8]}",
        details=f"Alert '{alert.title}' linked by {actor}.",
        actor=actor,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()

    log_action(
        db=db,
        action="ALERT_LINKED",
        actor=actor,
        target_resource=f"case:{case.id}",
        details={"case_id": case.id, "alert_id": alert.id}
    )

    return link

def unlink_alert_from_case(
    db: Session,
    case_id: str,
    alert_id: str,
    actor: str = "System"
) -> bool:
    """Unlink an Alert from a Case."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    alert = db.query(Alert).filter(or_(Alert.id == alert_id, Alert.alert_code == alert_id)).first()
    if not alert:
        raise ValueError("Alert not found")

    link = db.query(CaseAlert).filter(
        CaseAlert.case_id == case.id,
        CaseAlert.alert_id == alert.id
    ).first()

    if not link:
        return False

    db.delete(link)
    case.updated_at = datetime.utcnow()
    db.commit()

    timeline_entry = CaseTimeline(
        case_id=case.id,
        event_type="ALERT_UNLINKED",
        title=f"Alert Unlinked: {alert.alert_code or alert.id[:8]}",
        details=f"Alert unlinked by {actor}.",
        actor=actor,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()

    log_action(
        db=db,
        action="ALERT_UNLINKED",
        actor=actor,
        target_resource=f"case:{case.id}",
        details={"case_id": case.id, "alert_id": alert.id}
    )
    return True

def link_indicator_to_case(
    db: Session,
    case_id: str,
    indicator_id: str,
    actor: str = "System"
) -> CaseIndicator:
    """Link an Indicator to a Case (Idempotent)."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    indicator = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not indicator:
        raise ValueError("Indicator not found")

    existing = db.query(CaseIndicator).filter(
        CaseIndicator.case_id == case.id,
        CaseIndicator.indicator_id == indicator.id
    ).first()

    if existing:
        return existing

    link = CaseIndicator(
        case_id=case.id,
        indicator_id=indicator.id,
        linked_at=datetime.utcnow(),
        linked_by=actor
    )
    db.add(link)
    case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(link)

    timeline_entry = CaseTimeline(
        case_id=case.id,
        event_type="INDICATOR_LINKED",
        title=f"Indicator Linked: {indicator.value}",
        details=f"Indicator ({indicator.type}) linked by {actor}.",
        actor=actor,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()

    log_action(
        db=db,
        action="INDICATOR_LINKED",
        actor=actor,
        target_resource=f"case:{case.id}",
        details={"case_id": case.id, "indicator_id": indicator.id, "value": indicator.value}
    )

    return link

def unlink_indicator_from_case(
    db: Session,
    case_id: str,
    indicator_id: str,
    actor: str = "System"
) -> bool:
    """Unlink an Indicator from a Case."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    link = db.query(CaseIndicator).filter(
        CaseIndicator.case_id == case.id,
        CaseIndicator.indicator_id == indicator_id
    ).first()

    if not link:
        return False

    db.delete(link)
    case.updated_at = datetime.utcnow()
    db.commit()

    timeline_entry = CaseTimeline(
        case_id=case.id,
        event_type="INDICATOR_UNLINKED",
        title="Indicator Unlinked",
        details=f"Indicator {indicator_id} unlinked by {actor}.",
        actor=actor,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()

    log_action(
        db=db,
        action="INDICATOR_UNLINKED",
        actor=actor,
        target_resource=f"case:{case.id}",
        details={"case_id": case.id, "indicator_id": indicator_id}
    )
    return True

def add_case_evidence(
    db: Session,
    case_id: str,
    evidence_type: str,
    title: str,
    description: Optional[str] = None,
    source_entity: Optional[str] = None,
    source_provider: Optional[str] = None,
    reference_hash: Optional[str] = None,
    confidence: int = 80,
    data: Optional[Dict[str, Any]] = None,
    collected_by: str = "System",
    observed_at: Optional[datetime] = None
) -> CaseEvidence:
    """Add a piece of forensic evidence to an investigation case."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    evidence = CaseEvidence(
        case_id=case.id,
        evidence_type=evidence_type.upper().strip(),
        title=title.strip(),
        description=description.strip() if description else None,
        source_entity=source_entity.strip() if source_entity else None,
        source_provider=source_provider.strip() if source_provider else None,
        reference_hash=reference_hash.strip() if reference_hash else None,
        confidence=max(0, min(100, int(confidence))),
        data=data or {},
        observed_at=observed_at or datetime.utcnow(),
        collected_at=datetime.utcnow(),
        collected_by=collected_by,
        created_at=datetime.utcnow()
    )
    db.add(evidence)
    case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(evidence)

    # Timeline entry
    timeline_entry = CaseTimeline(
        case_id=case.id,
        event_type="EVIDENCE_ADDED",
        title=f"Evidence Added: {title}",
        details=f"Type: {evidence.evidence_type}, Source: {source_provider or 'Internal'}, Confidence: {confidence}%",
        actor=collected_by,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()

    # Audit Log
    log_action(
        db=db,
        action="EVIDENCE_ADDED",
        actor=collected_by,
        target_resource=f"case:{case.id}",
        details={
            "case_id": case.id,
            "evidence_id": evidence.id,
            "type": evidence.evidence_type,
            "title": title
        }
    )

    publish_case_event("EVIDENCE_ADDED", {
        "case_id": case.id,
        "evidence_id": evidence.id,
        "title": title,
        "collector": collected_by
    })

    return evidence

def add_case_note(
    db: Session,
    case_id: str,
    author: str,
    content: str,
    author_id: Optional[str] = None
) -> CaseNote:
    """Add an append-only investigator note ensuring forensic integrity."""
    case = db.query(Case).filter(or_(Case.id == case_id, Case.case_number == case_id)).first()
    if not case:
        raise ValueError("Case not found")

    text = content.strip()
    if not text:
        raise ValueError("Note content cannot be empty")
    if len(text) > 10000:
        raise ValueError("Note content exceeds maximum limit of 10,000 characters")

    note = CaseNote(
        case_id=case.id,
        author=author,
        author_id=author_id,
        content=text,
        created_at=datetime.utcnow()
    )
    db.add(note)
    case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(note)

    # Timeline entry
    timeline_entry = CaseTimeline(
        case_id=case.id,
        event_type="NOTE_ADDED",
        title="Investigator Note Added",
        details=text[:100] + ("..." if len(text) > 100 else ""),
        actor=author,
        created_at=datetime.utcnow()
    )
    db.add(timeline_entry)
    db.commit()

    log_action(
        db=db,
        action="NOTE_ADDED",
        actor=author,
        target_resource=f"case:{case.id}",
        details={"case_id": case.id, "note_id": note.id}
    )

    publish_case_event("NOTE_ADDED", {
        "case_id": case.id,
        "note_id": note.id,
        "author": author
    })

    return note

def link_or_create_case_for_incident(
    db: Session,
    incident: Incident
) -> Optional[Case]:
    """
    Deterministic Automated Incident -> Case clustering.
    If an open case exists matching the incident's matched IOC value, primary indicator,
    or affected host, attaches the incident to avoid case explosion.
    Otherwise, for significant incidents (CRITICAL, HIGH, or correlation score >= 60),
    creates a new Case and links the incident.
    """
    if not incident:
        return None

    # Check if incident is already attached to any case
    existing_link = db.query(CaseIncident).filter(CaseIncident.incident_id == incident.id).first()
    if existing_link:
        return db.query(Case).filter(Case.id == existing_link.case_id).first()

    # Determine significance
    sev_str = str(incident.severity.value if hasattr(incident.severity, "value") else incident.severity).upper()
    score = incident.correlation_score or 0
    is_significant = (sev_str in ["CRITICAL", "HIGH"]) or (score >= 60)

    if not is_significant:
        return None

    ioc_val = incident.matched_ioc_value or incident.primary_indicator
    host_val = incident.affected_host

    # Try finding an existing open/in_progress case that already matches this threat context
    active_statuses = [CaseStatus.OPEN.value, CaseStatus.IN_PROGRESS.value, CaseStatus.CONTAINED.value]
    
    # 1. Check if another incident linked to an active case shares this IOC or host
    candidate_case = None
    if ioc_val:
        matching_inc = db.query(Incident).join(CaseIncident, CaseIncident.incident_id == Incident.id)\
            .join(Case, Case.id == CaseIncident.case_id)\
            .filter(
                Case.status.in_(active_statuses),
                Incident.id != incident.id,
                or_(
                    Incident.matched_ioc_value == ioc_val,
                    Incident.primary_indicator == ioc_val
                )
            ).first()
        if matching_inc:
            link = db.query(CaseIncident).filter(CaseIncident.incident_id == matching_inc.id).first()
            if link:
                candidate_case = db.query(Case).filter(Case.id == link.case_id).first()

    if not candidate_case and host_val:
        matching_host_inc = db.query(Incident).join(CaseIncident, CaseIncident.incident_id == Incident.id)\
            .join(Case, Case.id == CaseIncident.case_id)\
            .filter(
                Case.status.in_(active_statuses),
                Incident.id != incident.id,
                Incident.affected_host == host_val
            ).first()
        if matching_host_inc:
            link = db.query(CaseIncident).filter(CaseIncident.incident_id == matching_host_inc.id).first()
            if link:
                candidate_case = db.query(Case).filter(Case.id == link.case_id).first()

    if candidate_case:
        # Attach incident to existing case
        link_incident_to_case(db, candidate_case.id, incident.id, actor="Automated Incident Engine")
        # Update case severity if incident is more severe
        if sev_str == "CRITICAL" and candidate_case.severity != "CRITICAL":
            candidate_case.severity = "CRITICAL"
            candidate_case.priority = "P1"
            db.commit()
        return candidate_case

    # No existing case: create a new investigation case
    title = f"Investigation: {incident.title}"
    priority = "P1" if sev_str == "CRITICAL" else "P2"
    tags = ["automated-correlation"]
    if incident.primary_source:
        tags.append(str(incident.primary_source))

    new_case = create_case(
        db=db,
        title=title,
        description=f"Automated case opened from correlated incident {incident.incident_code or incident.id[:8]}.\nDetails: {incident.description or ''}",
        severity=sev_str,
        priority=priority,
        creator="Automated Incident Engine",
        source="Automated Correlation",
        tags=tags,
        owner="SOC Operations"
    )

    # Attach this incident
    link_incident_to_case(db, new_case.id, incident.id, actor="Automated Incident Engine")

    # If incident has an associated indicator, link it too
    if incident.indicator_id:
        try:
            link_indicator_to_case(db, new_case.id, str(incident.indicator_id), actor="Automated Incident Engine")
        except Exception as e:
            logger.debug(f"Could not link indicator to case: {e}")

    # If incident has correlated alerts, link top alerts
    if incident.alerts:
        for alert in incident.alerts[:10]:
            try:
                link_alert_to_case(db, new_case.id, str(alert.id), actor="Automated Incident Engine")
            except Exception as e:
                logger.debug(f"Could not link alert to case: {e}")

    return new_case
