"""Detection Rule API Endpoints for ThreatLens (Phase 4D-B).

Provides canonical authenticated endpoints for:
- Listing and inspecting detection rules
- Creating and updating rules with declarative condition DSL validation
- Enabling / disabling rules (Security Engineer / Admin)
- Deleting rules (Security Engineer / Admin)
- Dry-run testing of detection rules against real indicators
- Multi-rule evaluation and alert routing
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Request, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.indicator import Indicator
from app.models.enrichment import IndicatorEnrichment
from app.models.detection_rule import DetectionRule, RuleSeverity, RuleRoutingQueue
from app.services.detection_rule_service import (
    create_detection_rule,
    get_detection_rule,
    list_detection_rules,
    update_detection_rule,
    set_rule_enabled_status,
    delete_detection_rule,
    execute_rule_dry_run,
    evaluate_indicator_against_rules,
    validate_rule_conditions,
)
from app.services.audit_service import log_action
from app.core.rbac import (
    require_authenticated_user,
    require_analyst,
    require_engineer,
)

router = APIRouter()

class RuleConditionSchema(BaseModel):
    field: str = Field(..., description="Target indicator/enrichment field name")
    operator: str = Field(..., description="Comparison operator (==, !=, >, >=, <, <=, in, not_in, contains, regex_match)")
    value: Any = Field(..., description="Expected value or pattern")

class CreateDetectionRuleRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=200, description="Descriptive rule name")
    conditions: List[RuleConditionSchema] = Field(..., min_length=1, description="List of rule conditions")
    severity: Optional[str] = Field("HIGH", description="Severity assigned to generated alerts (LOW, MEDIUM, HIGH, CRITICAL)")
    priority: Optional[int] = Field(50, ge=1, le=100, description="Rule evaluation priority (1-100)")
    rule_code: Optional[str] = Field(None, max_length=50, description="Optional unique rule code")
    description: Optional[str] = Field(None, description="Detailed rule description and rationale")
    logic_operator: Optional[str] = Field("AND", description="Logic operator across conditions (AND or OR)")
    match_scope: Optional[str] = Field("indicator", description="Matching scope (indicator, enrichment, all)")
    routing_target: Optional[str] = Field("SOC_TIER_2", description="Target destination queue (SOC_TIER_1, SOC_TIER_2, IR_LEAD, THREAT_HUNTING, SECURITY_ENGINEER, CISO_ESCALATION)")
    routing_channel: Optional[str] = Field("internal", description="Routing notification channel (internal, email_notification, webhook)")
    dedup_window_minutes: Optional[int] = Field(60, ge=1, le=10080, description="Alert deduplication window in minutes")
    actions: Optional[List[str]] = Field(["create_alert"], description="Actions executed upon match")

class UpdateDetectionRuleRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=200)
    conditions: Optional[List[RuleConditionSchema]] = None
    severity: Optional[str] = None
    priority: Optional[int] = Field(None, ge=1, le=100)
    description: Optional[str] = None
    logic_operator: Optional[str] = None
    match_scope: Optional[str] = None
    routing_target: Optional[str] = None
    routing_channel: Optional[str] = None
    dedup_window_minutes: Optional[int] = Field(None, ge=1, le=10080)
    actions: Optional[List[str]] = None

class DryRunTestRequest(BaseModel):
    indicator_id: Optional[str] = Field(None, description="UUID of existing indicator to test against")
    indicator_value: Optional[str] = Field(None, description="IOC value if testing without indicator ID")
    indicator_type: Optional[str] = Field(None, description="IOC type (ip, domain, url, etc.)")
    threat_score: Optional[int] = Field(None, description="Simulated threat score")
    rule_id: Optional[str] = Field(None, description="Optional rule ID if testing an existing rule")
    rule_data: Optional[CreateDetectionRuleRequest] = Field(None, description="Rule definition if testing draft conditions")

class EvaluateIndicatorRequest(BaseModel):
    indicator_id: str = Field(..., description="ID of indicator to evaluate against active detection rules")


@router.get("")
def list_rules(
    is_enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    routing_target: Optional[str] = Query(None, description="Filter by routing queue"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """List detection rules with optional filtering and pagination (Viewer+)."""
    return list_detection_rules(
        db=db,
        is_enabled=is_enabled,
        severity=severity,
        routing_target=routing_target,
        skip=skip,
        limit=limit,
    )


@router.get("/{rule_id}")
def get_rule_details(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """Retrieve details for a single detection rule (Viewer+)."""
    rule = get_detection_rule(db, rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )
    return {"status": "success", "data": rule.to_dict()}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_rule(
    payload: CreateDetectionRuleRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create a new declarative detection rule (Analyst+)."""
    try:
        rule = create_detection_rule(
            db=db,
            name=payload.name,
            conditions=[c.model_dump() if hasattr(c, "model_dump") else c.dict() for c in payload.conditions],
            severity=payload.severity or "HIGH",
            priority=payload.priority or 50,
            rule_code=payload.rule_code,
            description=payload.description,
            logic_operator=payload.logic_operator or "AND",
            match_scope=payload.match_scope or "indicator",
            routing_target=payload.routing_target or "SOC_TIER_2",
            routing_channel=payload.routing_channel or "internal",
            dedup_window_minutes=payload.dedup_window_minutes or 60,
            actions=payload.actions or ["create_alert"],
            created_by=current_user.username or current_user.email,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    try:
        log_action(
            db=db,
            action="RULE_CREATED",
            user_id=current_user.id,
            actor=current_user.username,
            target_resource=f"rule:{rule.id}",
            details={"name": rule.name, "rule_code": rule.rule_code, "severity": rule.severity},
            request=request,
        )
    except Exception:
        pass

    return {"status": "success", "data": rule.to_dict()}


@router.put("/{rule_id}")
def update_rule(
    rule_id: str,
    payload: UpdateDetectionRuleRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update an existing detection rule (Analyst+)."""
    rule = get_detection_rule(db, rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )

    update_dict = payload.dict(exclude_unset=True)
    if "conditions" in update_dict and update_dict["conditions"] is not None:
        update_dict["conditions"] = [c.dict() if hasattr(c, "dict") else c for c in payload.conditions]

    try:
        updated = update_detection_rule(
            db=db,
            rule_id=rule.id,
            update_data=update_dict,
            updated_by=current_user.username or current_user.email,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    try:
        log_action(
            db=db,
            action="RULE_UPDATED",
            user_id=current_user.id,
            actor=current_user.username,
            target_resource=f"rule:{rule.id}",
            details={"name": updated.name, "version": updated.version},
            request=request,
        )
    except Exception:
        pass

    return {"status": "success", "data": updated.to_dict()}


@router.delete("/{rule_id}")
def delete_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer),
):
    """Delete a detection rule (Security Engineer / Admin only)."""
    rule = get_detection_rule(db, rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )

    rule_name = rule.name
    deleted = delete_detection_rule(db, rule.id)

    try:
        log_action(
            db=db,
            action="RULE_DELETED",
            user_id=current_user.id,
            actor=current_user.username,
            target_resource=f"rule:{rule_id}",
            details={"name": rule_name},
            request=request,
        )
    except Exception:
        pass

    return {"status": "success", "message": f"Rule '{rule_name}' deleted."}


@router.post("/{rule_id}/enable")
def enable_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer),
):
    """Enable a detection rule (Security Engineer / Admin only)."""
    try:
        rule = set_rule_enabled_status(db, rule_id, is_enabled=True)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    try:
        log_action(
            db=db,
            action="RULE_ENABLED",
            user_id=current_user.id,
            actor=current_user.username,
            target_resource=f"rule:{rule.id}",
            details={"name": rule.name},
            request=request,
        )
    except Exception:
        pass

    return {"status": "success", "data": rule.to_dict()}


@router.post("/{rule_id}/disable")
def disable_rule(
    rule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_engineer),
):
    """Disable a detection rule (Security Engineer / Admin only)."""
    try:
        rule = set_rule_enabled_status(db, rule_id, is_enabled=False)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    try:
        log_action(
            db=db,
            action="RULE_DISABLED",
            user_id=current_user.id,
            actor=current_user.username,
            target_resource=f"rule:{rule.id}",
            details={"name": rule.name},
            request=request,
        )
    except Exception:
        pass

    return {"status": "success", "data": rule.to_dict()}


@router.post("/test")
def test_detection_rule(
    payload: DryRunTestRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Dry-run test a detection rule against real or supplied indicator data (Analyst+).
    Strictly does NOT generate alerts, incidents, or production events.
    """
    # 1. Resolve indicator
    indicator = None
    if payload.indicator_id:
        indicator = db.query(Indicator).filter(Indicator.id == payload.indicator_id).first()
        if not indicator:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Indicator '{payload.indicator_id}' not found.",
            )
    elif payload.indicator_value:
        indicator = Indicator(
            value=payload.indicator_value,
            type=payload.indicator_type or "ip",
            threat_score=payload.threat_score or 75,
            severity="HIGH",
        )
    else:
        # Default to first indicator in database for testing
        indicator = db.query(Indicator).first()
        if not indicator:
            indicator = Indicator(
                value="198.51.100.1",
                type="ip",
                threat_score=75,
                severity="HIGH",
            )

    # 2. Resolve rule data
    rule_dict = {}
    if payload.rule_id:
        existing_rule = get_detection_rule(db, payload.rule_id)
        if not existing_rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule '{payload.rule_id}' not found.",
            )
        rule_dict = existing_rule.to_dict()
    elif payload.rule_data:
        rule_dict = payload.rule_data.model_dump() if hasattr(payload.rule_data, "model_dump") else payload.rule_data.dict()
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either rule_id or rule_data to test.",
        )

    # 3. Resolve enrichment if indicator has an ID
    enrichment = None
    if getattr(indicator, "id", None):
        enrichment = db.query(IndicatorEnrichment).filter(
            IndicatorEnrichment.indicator_id == indicator.id
        ).order_by(IndicatorEnrichment.created_at.desc()).first()

    try:
        result = execute_rule_dry_run(rule_dict, indicator, enrichment)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    try:
        log_action(
            db=db,
            action="RULE_TESTED",
            user_id=current_user.id,
            actor=current_user.username,
            target_resource=f"rule:{payload.rule_id or 'draft'}",
            details={"is_matched": result.get("is_matched")},
            request=request,
        )
    except Exception:
        pass

    return {"status": "success", "data": result}


@router.post("/evaluate")
def evaluate_indicator(
    payload: EvaluateIndicatorRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Evaluate an indicator against all active detection rules.
    Creates alerts for matches, handles deduplication, and routes notifications (Analyst+).
    """
    indicator = db.query(Indicator).filter(Indicator.id == payload.indicator_id).first()
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Indicator '{payload.indicator_id}' not found.",
        )

    matches = evaluate_indicator_against_rules(db, indicator)
    return {
        "status": "success",
        "indicator_id": indicator.id,
        "indicator_value": indicator.value,
        "total_rules_matched": len(matches),
        "matches": matches,
    }
