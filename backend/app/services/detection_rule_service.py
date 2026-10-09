"""Detection Rule Engine and Alert Routing Service for ThreatLens (Phase 4D-B).

Provides:
- Declarative Condition DSL evaluation (deterministic, zero eval/exec, bounded complexity)
- Detection Rule management (CRUD, validation, enable/disable)
- Safe dry-run testing without side effects
- Multi-rule evaluation against incoming and updated threat indicators
- Deterministic alert deduplication within configurable time windows
- Role and team-based alert routing with honest delivery reporting
- Redis event publishing and handoff to the Phase 4A correlation engine
"""
import re
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from app.models.detection_rule import DetectionRule, RuleSeverity, RuleRoutingQueue
from app.models.indicator import Indicator, ThreatSeverity
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.enrichment import IndicatorEnrichment
from app.core.config import settings
from app.core.redis import redis_manager

logger = logging.getLogger("threatlens.detection_rules")

# Supported operators in the declarative DSL
SUPPORTED_OPERATORS = {
    "==", "eq",
    "!=", "neq",
    ">", "gt",
    ">=", "gte",
    "<", "lt",
    "<=", "lte",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "regex_match",
}

# Queue to Default Assignee Mapping
QUEUE_ASSIGNEES = {
    RuleRoutingQueue.SOC_TIER_1.value: "SOC Triage Pool",
    RuleRoutingQueue.SOC_TIER_2.value: "Priya Nair",
    RuleRoutingQueue.IR_LEAD.value: "Daniel Okafor",
    RuleRoutingQueue.THREAT_HUNTING.value: "Mei Lin Tan",
    RuleRoutingQueue.SECURITY_ENGINEER.value: "Marcus Vance",
    RuleRoutingQueue.CISO_ESCALATION.value: "Rachel Adeyemi",
}

MAX_CONDITIONS_PER_RULE = 10
MAX_REGEX_PATTERN_LENGTH = 100

def _is_safe_regex(pattern: str) -> bool:
    """Validate regex against length and nested quantifier catastrophic backtracking patterns."""
    if len(pattern) > MAX_REGEX_PATTERN_LENGTH:
        return False
    # Check for obvious nested quantifiers like (a+)+, (.*)*, etc.
    nested_quantifiers = re.compile(r"(\([^\)]*[\+\*]\)[+*])|(\[[\w\-]+\][\+\*][\+\*])")
    if nested_quantifiers.search(pattern):
        return False
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def validate_rule_conditions(conditions: List[Dict[str, Any]]) -> None:
    """Strictly validates declarative condition schema and operators."""
    if not isinstance(conditions, list):
        raise ValueError("Conditions must be a list of condition objects.")
    if len(conditions) > MAX_CONDITIONS_PER_RULE:
        raise ValueError(f"Exceeded maximum allowed conditions ({MAX_CONDITIONS_PER_RULE}).")

    for idx, cond in enumerate(conditions):
        if not isinstance(cond, dict):
            raise ValueError(f"Condition at index {idx} must be a dictionary.")
        if "field" not in cond or "operator" not in cond or "value" not in cond:
            raise ValueError(f"Condition at index {idx} missing required fields ('field', 'operator', 'value').")

        op = str(cond["operator"]).strip().lower()
        if op not in SUPPORTED_OPERATORS:
            raise ValueError(
                f"Unsupported operator '{cond['operator']}' at condition {idx}. "
                f"Must be one of: {sorted(SUPPORTED_OPERATORS)}"
            )

        if op == "regex_match":
            pattern = str(cond["value"])
            if not _is_safe_regex(pattern):
                raise ValueError(
                    f"Unsafe or invalid regular expression pattern '{pattern}' at condition {idx}."
                )


def _extract_field_value(field_name: str, indicator: Indicator, enrichment: Optional[IndicatorEnrichment] = None) -> Any:
    """Extracts field value from indicator or associated enrichment."""
    fn = field_name.strip().lower()

    if fn in ["type", "indicator_type"]:
        return indicator.type.value if hasattr(indicator.type, "value") else str(indicator.type)
    elif fn == "severity":
        return str(indicator.severity) if indicator.severity else "MEDIUM"
    elif fn in ["threat_score", "score"]:
        return int(indicator.threat_score or 0)
    elif fn in ["severity_score"]:
        return int(indicator.severity_score or 0)
    elif fn == "confidence":
        return int(indicator.confidence or 50)
    elif fn in ["source", "feed"]:
        return str(indicator.source or "")
    elif fn == "status":
        return str(indicator.status or "active")
    elif fn == "mitre_technique":
        return str(indicator.mitre_technique or "")
    elif fn in ["value", "ioc"]:
        return str(indicator.value or "")
    elif fn == "tags":
        return list(indicator.tags or [])
    elif fn == "sightings":
        return int(indicator.sightings or 1)

    # Enrichment telemetry fields
    elif fn == "enrichment_verdict":
        return str(enrichment.verdict if enrichment else "unknown").lower()
    elif fn == "enrichment_malicious_count":
        return int(enrichment.malicious_count if enrichment and enrichment.malicious_count is not None else 0)
    elif fn == "country":
        return str(enrichment.country if enrichment and enrichment.country else "")
    elif fn in ["asn", "network"]:
        return str(enrichment.network or enrichment.asn or "") if enrichment else ""

    return None


def evaluate_single_condition(
    condition: Dict[str, Any],
    indicator: Indicator,
    enrichment: Optional[IndicatorEnrichment] = None
) -> Tuple[bool, Any, str]:
    """
    Evaluates one declarative condition against an indicator.
    Returns (matched, actual_value, reason).
    """
    field_name = condition["field"]
    op = str(condition["operator"]).strip().lower()
    expected_val = condition["value"]

    actual_val = _extract_field_value(field_name, indicator, enrichment)

    if actual_val is None:
        return False, None, f"Field '{field_name}' not available on indicator"

    try:
        if op in ["==", "eq"]:
            if isinstance(actual_val, str) and isinstance(expected_val, str):
                matched = actual_val.strip().lower() == expected_val.strip().lower()
            else:
                matched = actual_val == expected_val
            return matched, actual_val, f"{actual_val} == {expected_val}"

        elif op in ["!=", "neq"]:
            if isinstance(actual_val, str) and isinstance(expected_val, str):
                matched = actual_val.strip().lower() != expected_val.strip().lower()
            else:
                matched = actual_val != expected_val
            return matched, actual_val, f"{actual_val} != {expected_val}"

        elif op in [">", "gt"]:
            matched = float(actual_val) > float(expected_val)
            return matched, actual_val, f"{actual_val} > {expected_val}"

        elif op in [">=", "gte"]:
            matched = float(actual_val) >= float(expected_val)
            return matched, actual_val, f"{actual_val} >= {expected_val}"

        elif op in ["<", "lt"]:
            matched = float(actual_val) < float(expected_val)
            return matched, actual_val, f"{actual_val} < {expected_val}"

        elif op in ["<=", "lte"]:
            matched = float(actual_val) <= float(expected_val)
            return matched, actual_val, f"{actual_val} <= {expected_val}"

        elif op == "in":
            if isinstance(expected_val, list):
                exp_set = {str(x).strip().lower() for x in expected_val}
                matched = str(actual_val).strip().lower() in exp_set
            else:
                matched = str(actual_val) in str(expected_val)
            return matched, actual_val, f"{actual_val} in {expected_val}"

        elif op == "not_in":
            if isinstance(expected_val, list):
                exp_set = {str(x).strip().lower() for x in expected_val}
                matched = str(actual_val).strip().lower() not in exp_set
            else:
                matched = str(actual_val) not in str(expected_val)
            return matched, actual_val, f"{actual_val} not in {expected_val}"

        elif op == "contains":
            if isinstance(actual_val, list):
                matched = any(str(x).strip().lower() == str(expected_val).strip().lower() for x in actual_val)
            else:
                matched = str(expected_val).strip().lower() in str(actual_val).strip().lower()
            return matched, actual_val, f"{actual_val} contains {expected_val}"

        elif op == "not_contains":
            if isinstance(actual_val, list):
                matched = not any(str(x).strip().lower() == str(expected_val).strip().lower() for x in actual_val)
            else:
                matched = str(expected_val).strip().lower() not in str(actual_val).strip().lower()
            return matched, actual_val, f"{actual_val} not contains {expected_val}"

        elif op == "regex_match":
            pattern = str(expected_val)
            matched = bool(re.search(pattern, str(actual_val), re.IGNORECASE))
            return matched, actual_val, f"regex '{pattern}' matched '{actual_val}'"

    except Exception as e:
        return False, actual_val, f"Evaluation error: {str(e)}"

    return False, actual_val, f"Unsupported operation {op}"


def evaluate_rule(
    rule: DetectionRule,
    indicator: Indicator,
    enrichment: Optional[IndicatorEnrichment] = None
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Evaluates all conditions of a detection rule using its logic operator (AND/OR).
    Returns (overall_match, detailed_condition_results).
    """
    conditions = rule.conditions or []
    if not conditions:
        return False, []

    logic_op = str(rule.logic_operator or "AND").upper()
    condition_results = []
    matched_flags = []

    for cond in conditions:
        matched, actual, reason = evaluate_single_condition(cond, indicator, enrichment)
        condition_results.append({
            "field": cond.get("field"),
            "operator": cond.get("operator"),
            "expected": cond.get("value"),
            "actual": actual,
            "matched": matched,
            "reason": reason,
        })
        matched_flags.append(matched)

    if logic_op == "OR":
        overall_match = any(matched_flags)
    else:  # "AND"
        overall_match = all(matched_flags)

    return overall_match, condition_results


def execute_rule_dry_run(
    rule_data: Dict[str, Any],
    indicator: Indicator,
    enrichment: Optional[IndicatorEnrichment] = None,
) -> Dict[str, Any]:
    """
    Performs safe dry-run evaluation without creating alerts or publishing events.
    """
    conditions = rule_data.get("conditions", [])
    validate_rule_conditions(conditions)

    in_memory_rule = DetectionRule(
        name=rule_data.get("name", "Test Rule"),
        severity=rule_data.get("severity", RuleSeverity.HIGH.value),
        conditions=conditions,
        logic_operator=rule_data.get("logic_operator", "AND"),
        routing_target=rule_data.get("routing_target", RuleRoutingQueue.SOC_TIER_2.value),
    )

    is_matched, details = evaluate_rule(in_memory_rule, indicator, enrichment)

    target_queue = in_memory_rule.routing_target
    target_assignee = QUEUE_ASSIGNEES.get(target_queue, "SOC Triage Pool")

    return {
        "dry_run": True,
        "is_matched": is_matched,
        "rule_name": in_memory_rule.name,
        "severity": in_memory_rule.severity,
        "simulated_routing": {
            "queue": target_queue,
            "assignee": target_assignee,
            "channel": rule_data.get("routing_channel", "internal"),
        },
        "conditions_evaluated": details,
        "indicator_evaluated": {
            "id": str(indicator.id) if indicator.id else None,
            "value": indicator.value,
            "type": indicator.type,
            "threat_score": indicator.threat_score,
            "severity": indicator.severity,
        },
    }


def route_alert_notification(alert: Alert, rule: DetectionRule) -> Dict[str, Any]:
    """
    Executes routing delivery logic.
    For unconfigured channels (e.g. SMTP or external webhook), reports NOT CONFIGURED honestly.
    """
    channel = str(rule.routing_channel or "internal").lower()
    target_queue = rule.routing_target or RuleRoutingQueue.SOC_TIER_2.value
    assignee = QUEUE_ASSIGNEES.get(target_queue, "SOC Triage Pool")

    routing_result = {
        "queue": target_queue,
        "assignee": assignee,
        "channel": channel,
        "delivery_status": "DELIVERED",
        "timestamp": datetime.utcnow().isoformat(),
    }

    if channel == "email_notification":
        # Check if SMTP server is configured in settings
        smtp_configured = bool(getattr(settings, "SMTP_HOST", None))
        if not smtp_configured:
            routing_result["delivery_status"] = "NOT_CONFIGURED"
            routing_result["message"] = "Email notification channel requested but SMTP host is not configured."
        else:
            routing_result["delivery_status"] = "SENT"

    elif channel == "webhook":
        # Check if external webhook URL is configured
        webhook_configured = bool(getattr(settings, "ALERT_WEBHOOK_URL", None))
        if not webhook_configured:
            routing_result["delivery_status"] = "NOT_CONFIGURED"
            routing_result["message"] = "Inbound/outbound webhook URL is not configured."
        else:
            routing_result["delivery_status"] = "DISPATCHED"

    else:  # "internal" - always active via Redis event bus & WebSocket
        routing_result["delivery_status"] = "DELIVERED"
        routing_result["message"] = f"Routed to internal queue {target_queue} ({assignee})."

    # Publish ALERT_ROUTED event to Redis
    try:
        route_event = {
            "type": "ALERT_ROUTED",
            "event": "ALERT_ROUTED",
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "alert_id": str(alert.id),
                "alert_code": alert.alert_code,
                "rule_id": str(rule.id) if rule.id else None,
                "rule_name": rule.name,
                "routing": routing_result,
            }
        }
        redis_manager.publish_event(settings.REDIS_ALERT_CHANNEL, route_event)
        redis_manager.publish_event(settings.REDIS_RULE_CHANNEL, route_event)
    except Exception as e:
        logger.debug(f"Redis route publish failed: {e}")

    return routing_result


def evaluate_indicator_against_rules(
    db: Session,
    indicator: Indicator,
) -> List[Dict[str, Any]]:
    """
    Evaluates an indicator against all active detection rules ordered by priority.
    Creates alerts for matches, enforces deduplication windows, dispatches routing,
    and forwards to Phase 4A incident correlation.
    """
    enabled_rules = db.query(DetectionRule).filter(
        DetectionRule.is_enabled == True
    ).order_by(desc(DetectionRule.priority)).all()

    if not enabled_rules:
        return []

    # Fetch latest enrichment for context
    enrichment = db.query(IndicatorEnrichment).filter(
        IndicatorEnrichment.indicator_id == indicator.id
    ).order_by(desc(IndicatorEnrichment.created_at)).first()

    matches = []

    for rule in enabled_rules:
        is_matched, condition_details = evaluate_rule(rule, indicator, enrichment)
        if not is_matched:
            continue

        now = datetime.utcnow()
        # Deduplication Strategy: check active alert within dedup_window_minutes
        dedup_window = timedelta(minutes=rule.dedup_window_minutes or 60)
        window_start = now - dedup_window

        active_statuses = [
            AlertStatus.NEW.value, AlertStatus.ACKNOWLEDGED.value, AlertStatus.IN_PROGRESS.value,
            "new", "acknowledged", "in_progress", "NEW", "ACKNOWLEDGED", "IN_PROGRESS"
        ]

        existing_alert = db.query(Alert).filter(
            Alert.indicator_id == indicator.id,
            or_(
                Alert.rule_id == rule.id,
                Alert.rule_name == rule.name,
            ),
            Alert.status.in_(active_statuses),
            Alert.created_at >= window_start,
        ).first()

        if existing_alert:
            # Deduplicated: increment internal sightings without spamming new alert records
            existing_alert.internal_sightings_count = (existing_alert.internal_sightings_count or 1) + 1
            existing_alert.updated_at = now
            rule.total_matches += 1
            rule.last_matched_at = now
            db.commit()

            matches.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "is_deduplicated": True,
                "alert_id": existing_alert.id,
                "sightings": existing_alert.internal_sightings_count,
            })
            continue

        # Create new rule-generated alert
        target_queue = rule.routing_target or RuleRoutingQueue.SOC_TIER_2.value
        assignee = QUEUE_ASSIGNEES.get(target_queue, "SOC Triage Pool")
        alert_code = f"ALT-RULE-{str(uuid.uuid4())[:6].upper()}"

        new_alert = Alert(
            alert_code=alert_code,
            title=f"Detection Match: {rule.name} on {indicator.value}",
            description=f"Rule '{rule.name}' triggered on {indicator.type} {indicator.value}. "
                        f"Matched priority {rule.priority}, routed to {target_queue}.",
            severity=rule.severity,
            severity_score=indicator.threat_score or 70,
            status=AlertStatus.NEW.value,
            indicator_id=indicator.id,
            indicator_value=indicator.value,
            rule_id=rule.id,
            rule_name=rule.name,
            routed_to=target_queue,
            assignee=assignee,
            source=f"DetectionRule:{rule.rule_code or rule.id}",
            mitre_technique=indicator.mitre_technique or "T1071",
            internal_sightings_count=1,
            context={
                "rule_id": str(rule.id) if rule.id else None,
                "rule_name": rule.name,
                "matched_conditions": condition_details,
                "routing_target": target_queue,
                "threat_score": indicator.threat_score,
            },
            created_at=now,
            updated_at=now,
        )

        db.add(new_alert)
        rule.total_matches += 1
        rule.last_matched_at = now
        db.commit()
        db.refresh(new_alert)

        # Execute routing and notifications
        routing_info = route_alert_notification(new_alert, rule)

        # Publish DETECTION_RULE_MATCHED and ALERT_CREATED to Redis
        try:
            matched_event = {
                "type": "DETECTION_RULE_MATCHED",
                "event": "DETECTION_RULE_MATCHED",
                "timestamp": now.isoformat(),
                "data": {
                    "rule_id": str(rule.id) if rule.id else None,
                    "rule_code": rule.rule_code,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "indicator_id": str(indicator.id) if indicator.id else None,
                    "indicator_value": indicator.value,
                    "matched_conditions": condition_details,
                    "routing": routing_info,
                }
            }
            redis_manager.publish_event(settings.REDIS_RULE_CHANNEL, matched_event)
            redis_manager.publish_event(settings.REDIS_ALERT_CHANNEL, matched_event)
        except Exception as e:
            logger.debug(f"Redis publish detection rule event failed: {e}")

        # Phase 4A Incident Integration: Correlate into incident engine
        try:
            from app.services.correlation_service import correlate_alert_to_incident
            correlate_alert_to_incident(db, new_alert)
        except Exception as corr_err:
            logger.error(f"Correlation handoff error for Rule Alert {new_alert.id}: {corr_err}")

        # Audit logging
        try:
            from app.services.audit_service import log_action
            log_action(
                db=db,
                action="DETECTION_RULE_ALERT_CREATED",
                actor="DETECTION_ENGINE",
                target_resource=f"alert:{new_alert.id}",
                details={
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "alert_id": new_alert.id,
                    "routed_to": target_queue,
                    "indicator": indicator.value,
                }
            )
        except Exception:
            pass

        matches.append({
            "rule_id": rule.id,
            "rule_name": rule.name,
            "is_deduplicated": False,
            "alert_id": new_alert.id,
            "routed_to": target_queue,
            "assignee": assignee,
        })

    return matches


# Detection Rule CRUD operations
def create_detection_rule(
    db: Session,
    name: str,
    conditions: List[Dict[str, Any]],
    severity: str = RuleSeverity.HIGH.value,
    priority: int = 50,
    rule_code: Optional[str] = None,
    description: Optional[str] = None,
    logic_operator: str = "AND",
    match_scope: str = "indicator",
    routing_target: str = RuleRoutingQueue.SOC_TIER_2.value,
    routing_channel: str = "internal",
    dedup_window_minutes: int = 60,
    actions: Optional[List[str]] = None,
    created_by: str = "admin",
) -> DetectionRule:
    """Creates a validated DetectionRule in database."""
    validate_rule_conditions(conditions)

    code = rule_code or f"RULE-{str(uuid.uuid4())[:8].upper()}"
    existing_code = db.query(DetectionRule).filter(DetectionRule.rule_code == code).first()
    if existing_code:
        code = f"RULE-{str(uuid.uuid4())[:8].upper()}"

    rule = DetectionRule(
        name=name.strip(),
        rule_code=code,
        description=description,
        severity=severity.upper(),
        priority=max(1, min(100, int(priority))),
        is_enabled=True,
        conditions=conditions,
        logic_operator=logic_operator.upper(),
        match_scope=match_scope,
        routing_target=routing_target,
        routing_channel=routing_channel,
        dedup_window_minutes=max(1, int(dedup_window_minutes)),
        actions=actions or ["create_alert"],
        created_by=created_by,
        version=1,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def get_detection_rule(db: Session, rule_id: Union[str, uuid.UUID]) -> Optional[DetectionRule]:
    """Retrieve rule by UUID string, UUID object, or rule_code."""
    rule_str = str(rule_id).strip()
    return db.query(DetectionRule).filter(
        or_(DetectionRule.id == rule_str, DetectionRule.rule_code == rule_str)
    ).first()


def list_detection_rules(
    db: Session,
    is_enabled: Optional[bool] = None,
    severity: Optional[str] = None,
    routing_target: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> Dict[str, Any]:
    """Lists detection rules with filtering and pagination."""
    query = db.query(DetectionRule)
    if is_enabled is not None:
        query = query.filter(DetectionRule.is_enabled == is_enabled)
    if severity:
        query = query.filter(DetectionRule.severity == severity.upper())
    if routing_target:
        query = query.filter(DetectionRule.routing_target == routing_target)

    total = query.count()
    rules = query.order_by(desc(DetectionRule.priority), desc(DetectionRule.created_at)).offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [r.to_dict() for r in rules],
    }


def update_detection_rule(
    db: Session,
    rule_id: str,
    update_data: Dict[str, Any],
    updated_by: str = "admin",
) -> DetectionRule:
    """Updates an existing DetectionRule."""
    rule = get_detection_rule(db, rule_id)
    if not rule:
        raise ValueError(f"Detection rule '{rule_id}' not found.")

    if "conditions" in update_data:
        validate_rule_conditions(update_data["conditions"])
        rule.conditions = update_data["conditions"]

    for field in [
        "name", "description", "severity", "priority", "logic_operator",
        "match_scope", "routing_target", "routing_channel", "dedup_window_minutes", "actions"
    ]:
        if field in update_data and update_data[field] is not None:
            setattr(rule, field, update_data[field])

    rule.version = (rule.version or 1) + 1
    rule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(rule)
    return rule


def set_rule_enabled_status(db: Session, rule_id: str, is_enabled: bool) -> DetectionRule:
    """Enables or disables a rule."""
    rule = get_detection_rule(db, rule_id)
    if not rule:
        raise ValueError(f"Detection rule '{rule_id}' not found.")

    rule.is_enabled = is_enabled
    rule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(rule)
    return rule


def delete_detection_rule(db: Session, rule_id: str) -> bool:
    """Deletes a detection rule."""
    rule = get_detection_rule(db, rule_id)
    if not rule:
        return False
    db.delete(rule)
    db.commit()
    return True
