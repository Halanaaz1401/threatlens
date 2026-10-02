"""
ThreatLens - Phase 4C Threat Analytics & Statistical Aggregation Service
Provides real, deterministic analytics derived directly from authoritative
PostgreSQL indicators, alerts, incidents, and enrichment tables.
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, distinct, case

from app.models.indicator import Indicator, IndicatorSource
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.incident import Incident, IncidentStatus, IncidentTimeline
from app.models.enrichment import IndicatorEnrichment

VALID_TIME_RANGES = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}

def to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure datetime is offset-naive UTC for consistent comparisons."""
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt

def parse_time_window(time_range: str) -> Tuple[datetime, datetime, str]:
    """Validate and compute start/end UTC datetimes and bucket resolution."""
    tr = time_range.lower().strip()
    if tr not in VALID_TIME_RANGES:
        raise ValueError(f"Invalid time_range '{time_range}'. Allowed values: {list(VALID_TIME_RANGES.keys())}")
    
    days = VALID_TIME_RANGES[tr]
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    start_time = now - timedelta(days=days)
    bucket_interval = "hour" if days == 1 else "day"
    return start_time, now, bucket_interval

def get_executive_kpis(db: Session, time_range: str = "24h") -> Dict[str, Any]:
    """
    Calculate board-level executive risk posture and operational KPIs
    grounded exclusively in authoritative database tables.
    """
    start_time, now, _ = parse_time_window(time_range)

    # 1. Total & Recent Indicators
    total_indicators = db.query(func.count(Indicator.id)).scalar() or 0
    recent_indicators = db.query(func.count(Indicator.id)).filter(Indicator.created_at >= start_time).scalar() or 0

    # 2. Active Alert Volume
    active_alert_statuses = [
        AlertStatus.NEW.value,
        AlertStatus.ACKNOWLEDGED.value,
        AlertStatus.IN_PROGRESS.value,
        "new", "acknowledged", "in_progress"
    ]
    active_alerts = db.query(func.count(Alert.id)).filter(Alert.status.in_(active_alert_statuses)).scalar() or 0
    active_sev1_alerts = db.query(func.count(Alert.id)).filter(
        Alert.status.in_(active_alert_statuses),
        or_(Alert.severity == "CRITICAL", Alert.severity_score >= 80)
    ).scalar() or 0

    # 3. Incident Exposure
    open_incident_statuses = [
        IncidentStatus.OPEN.value,
        IncidentStatus.ACKNOWLEDGED.value,
        IncidentStatus.IN_PROGRESS.value,
        IncidentStatus.INVESTIGATING.value,
        "open", "investigating", "acknowledged", "in_progress"
    ]
    open_incidents = db.query(func.count(Incident.id)).filter(Incident.status.in_(open_incident_statuses)).scalar() or 0
    active_sev1_incidents = db.query(func.count(Incident.id)).filter(
        Incident.status.in_(open_incident_statuses),
        Incident.severity.in_(["CRITICAL", "critical"])
    ).scalar() or 0

    # 4. Critical & High Indicator Counts
    critical_indicators = db.query(func.count(Indicator.id)).filter(
        or_(Indicator.severity == "CRITICAL", Indicator.severity_score >= 80)
    ).scalar() or 0
    high_indicators = db.query(func.count(Indicator.id)).filter(
        or_(
            Indicator.severity == "HIGH",
            and_(Indicator.severity_score >= 60, Indicator.severity_score < 80)
        )
    ).scalar() or 0

    # 5. Enrichment Coverage
    enriched_indicators_count = db.query(func.count(distinct(IndicatorEnrichment.indicator_id))).scalar() or 0
    enrichment_coverage_pct = round((enriched_indicators_count / total_indicators * 100), 1) if total_indicators > 0 else 0.0

    # 6. Operational MTTR (Mean Time to Respond / Contain in minutes)
    contained_timelines = db.query(
        Incident.created_at,
        IncidentTimeline.created_at
    ).join(IncidentTimeline, IncidentTimeline.incident_id == Incident.id).filter(
        IncidentTimeline.action.in_(["INCIDENT_CONTAINED", "INCIDENT_RESOLVED"])
    ).all()

    if contained_timelines:
        durations = []
        for inc_created, tl_created in contained_timelines:
            inc_c = to_naive_utc(inc_created)
            tl_c = to_naive_utc(tl_created)
            if inc_c and tl_c and tl_c >= inc_c:
                durations.append((tl_c - inc_c).total_seconds() / 60.0)
        mttr_minutes = round(sum(durations) / len(durations), 1) if durations else None
    else:
        # Fallback to incident updated_at - created_at for closed/resolved incidents
        closed_incidents = db.query(Incident.created_at, Incident.updated_at).filter(
            Incident.status.in_(["CONTAINED", "RESOLVED", "CLOSED", "contained", "resolved", "closed"])
        ).all()
        if closed_incidents:
            durations = []
            for cr, upd in closed_incidents:
                cr_n = to_naive_utc(cr)
                upd_n = to_naive_utc(upd)
                if cr_n and upd_n and upd_n >= cr_n:
                    durations.append((upd_n - cr_n).total_seconds() / 60.0)
            mttr_minutes = round(sum(durations) / len(durations), 1) if durations else None
        else:
            mttr_minutes = None

    # 7. Operational MTTD (Mean Time to Detect in minutes)
    mttd_records = db.query(Indicator.first_seen, Alert.created_at).join(
        Alert, Alert.indicator_id == Indicator.id
    ).limit(500).all()

    if mttd_records:
        mttd_durations = []
        for ind_fs, al_cr in mttd_records:
            ind_fs_n = to_naive_utc(ind_fs)
            al_cr_n = to_naive_utc(al_cr)
            if ind_fs_n and al_cr_n and al_cr_n >= ind_fs_n:
                mttd_durations.append((al_cr_n - ind_fs_n).total_seconds() / 60.0)
        mttd_minutes = round(sum(mttd_durations) / len(mttd_durations), 1) if mttd_durations else None
    else:
        mttd_minutes = None

    # 8. Enterprise Risk Score (0 - 100)
    # Deterministic index derived from active severe assets relative to total corpus
    if total_indicators == 0 and open_incidents == 0:
        enterprise_risk_score = 0
    else:
        weighted_exposure = (critical_indicators * 3.0) + (high_indicators * 1.5) + (open_incidents * 12.0)
        norm_factor = max(10, total_indicators * 0.1)
        calc_score = round(min(100.0, max(0.0, (weighted_exposure / norm_factor) * 25.0)), 1)
        enterprise_risk_score = int(calc_score)

    return {
        "time_range": time_range,
        "calculated_at": now.isoformat() + "Z",
        "enterprise_risk_score": {
            "score": enterprise_risk_score,
            "max": 100,
            "level": "CRITICAL" if enterprise_risk_score >= 80 else ("HIGH" if enterprise_risk_score >= 60 else ("MEDIUM" if enterprise_risk_score >= 40 else "LOW")),
            "calculation_basis": "Weighted ratio of active SEV-1 incidents, critical indicators, and high-severity IOCs"
        },
        "mttd": {
            "value_minutes": mttd_minutes,
            "formatted": f"{mttd_minutes} mins" if mttd_minutes is not None else "N/A (insufficient alerts)",
            "calculation_basis": "Average duration from indicator first_seen to alert creation"
        },
        "mttr": {
            "value_minutes": mttr_minutes,
            "formatted": f"{mttr_minutes} mins" if mttr_minutes is not None else "N/A (no contained incidents)",
            "calculation_basis": "Average duration from incident creation to containment action in timeline"
        },
        "active_sev1_incidents": {
            "count": active_sev1_incidents,
            "total_open_incidents": open_incidents,
        },
        "indicators": {
            "total": total_indicators,
            "recent_ingested": recent_indicators,
            "critical_count": critical_indicators,
            "high_count": high_indicators,
        },
        "alerts": {
            "active_total": active_alerts,
            "active_sev1": active_sev1_alerts,
        },
        "enrichment_coverage": {
            "total_indicators": total_indicators,
            "enriched_indicators": enriched_indicators_count,
            "percentage": enrichment_coverage_pct,
        }
    }

def get_threat_trends(db: Session, time_range: str = "24h") -> Dict[str, Any]:
    """
    Generate deterministic, continuous time-series threat velocity buckets.
    Guarantees no gaps: missing time intervals are zero-filled.
    """
    start_time, now, interval = parse_time_window(time_range)
    
    # Generate expected bucket slots
    buckets: List[Dict[str, Any]] = []
    bucket_map: Dict[str, Dict[str, Any]] = {}

    if interval == "hour":
        # 24 1-hour slots
        curr = start_time.replace(minute=0, second=0, microsecond=0)
        while curr <= now:
            key = curr.strftime("%Y-%m-%d %H:00")
            label = curr.strftime("%H:00")
            item = {"timestamp": curr.isoformat() + "Z", "key": key, "label": label, "ingests": 0, "high_severity": 0}
            buckets.append(item)
            bucket_map[key] = item
            curr += timedelta(hours=1)
    else:
        # N 1-day slots
        curr = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
        while curr <= now:
            key = curr.strftime("%Y-%m-%d")
            label = curr.strftime("%b %d")
            item = {"timestamp": curr.isoformat() + "Z", "key": key, "label": label, "ingests": 0, "high_severity": 0}
            buckets.append(item)
            bucket_map[key] = item
            curr += timedelta(days=1)

    # Query real indicators within range
    dialect = db.bind.dialect.name if db.bind else "postgresql"
    
    records = db.query(
        Indicator.created_at,
        Indicator.severity,
        Indicator.severity_score
    ).filter(Indicator.created_at >= start_time).all()

    for created_at, sev, score in records:
        created_at_n = to_naive_utc(created_at)
        if not created_at_n:
            continue
        if interval == "hour":
            key = created_at_n.strftime("%Y-%m-%d %H:00")
        else:
            key = created_at_n.strftime("%Y-%m-%d")
        
        if key in bucket_map:
            bucket_map[key]["ingests"] += 1
            if (sev and sev.upper() in ["HIGH", "CRITICAL"]) or (score is not None and score >= 60):
                bucket_map[key]["high_severity"] += 1

    # Strip internal 'key' before returning
    clean_series = [{k: v for k, v in b.items() if k != "key"} for b in buckets]
    total_ingests = sum(b["ingests"] for b in clean_series)
    total_high_sev = sum(b["high_severity"] for b in clean_series)

    return {
        "time_range": time_range,
        "interval": interval,
        "start_time": start_time.isoformat() + "Z",
        "end_time": now.isoformat() + "Z",
        "total_ingests": total_ingests,
        "total_high_severity": total_high_sev,
        "series": clean_series
    }

def get_severity_distribution(db: Session) -> Dict[str, Any]:
    """
    Aggregate counts across defined severity bands for indicators, alerts, and incidents.
    """
    # 1. Indicators by Severity
    ind_rows = db.query(
        func.coalesce(Indicator.severity, "UNKNOWN").label("sev"),
        func.count(Indicator.id)
    ).group_by("sev").all()
    
    ind_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for sev, count in ind_rows:
        s_upper = sev.upper() if sev else "MEDIUM"
        if s_upper in ind_counts:
            ind_counts[s_upper] += count
        else:
            ind_counts["MEDIUM"] += count

    # 2. Alerts by Severity
    al_rows = db.query(
        func.coalesce(Alert.severity, "HIGH").label("sev"),
        func.count(Alert.id)
    ).group_by("sev").all()
    
    alert_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for sev, count in al_rows:
        s_upper = sev.upper() if sev else "HIGH"
        if s_upper in alert_counts:
            alert_counts[s_upper] += count

    # 3. Incidents by Severity
    inc_rows = db.query(
        func.coalesce(Incident.severity, "HIGH").label("sev"),
        func.count(Incident.id)
    ).group_by("sev").all()
    
    incident_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for sev, count in inc_rows:
        s_upper = sev.upper() if sev else "HIGH"
        if s_upper in incident_counts:
            incident_counts[s_upper] += count

    total_indicators = sum(ind_counts.values())

    # Format for UI Donut/Pie charts
    chart_data = [
        {"name": "Critical (80-100)", "severity": "CRITICAL", "value": ind_counts["CRITICAL"], "color": "#ef4444"},
        {"name": "High (60-79)", "severity": "HIGH", "value": ind_counts["HIGH"], "color": "#f97316"},
        {"name": "Medium (40-59)", "severity": "MEDIUM", "value": ind_counts["MEDIUM"], "color": "#eab308"},
        {"name": "Low / Info (<40)", "severity": "LOW", "value": ind_counts["LOW"] + ind_counts["INFO"], "color": "#3b82f6"},
    ]

    return {
        "indicators": ind_counts,
        "alerts": alert_counts,
        "incidents": incident_counts,
        "chart_data": chart_data,
        "total_evaluated": total_indicators
    }

def get_indicator_type_distribution(db: Session) -> Dict[str, Any]:
    """
    Aggregate counts of indicators grouped by canonical IOC type.
    """
    rows = db.query(
        func.coalesce(Indicator.type, "unknown").label("ioc_type"),
        func.count(Indicator.id)
    ).group_by("ioc_type").all()

    distribution = {}
    total = 0
    for t, count in rows:
        key = str(t).lower()
        distribution[key] = count
        total += count

    # Sorted list for UI consumption
    sorted_items = [
        {"type": k, "count": v, "percentage": round((v / total * 100), 1) if total > 0 else 0.0}
        for k, v in sorted(distribution.items(), key=lambda x: x[1], reverse=True)
    ]

    return {
        "total": total,
        "distribution": distribution,
        "items": sorted_items
    }

def get_incident_analytics(db: Session) -> Dict[str, Any]:
    """
    Provide lifecycle and resolution statistics for correlated security incidents.
    """
    total = db.query(func.count(Incident.id)).scalar() or 0
    
    # Status breakdown
    status_rows = db.query(
        func.coalesce(Incident.status, "OPEN").label("st"),
        func.count(Incident.id)
    ).group_by("st").all()
    
    status_counts = {}
    for st, count in status_rows:
        status_counts[st.upper()] = count

    # Severity breakdown
    sev_rows = db.query(
        func.coalesce(Incident.severity, "HIGH").label("sv"),
        func.count(Incident.id)
    ).group_by("sv").all()
    
    sev_counts = {}
    for sv, count in sev_rows:
        sev_counts[sv.upper()] = count

    # Total associated alerts across all incidents
    total_correlated_alerts = db.query(func.count(Alert.id)).filter(Alert.incident_id.isnot(None)).scalar() or 0
    avg_alerts_per_incident = round(total_correlated_alerts / total, 1) if total > 0 else 0.0

    return {
        "total_incidents": total,
        "by_status": status_counts,
        "by_severity": sev_counts,
        "correlated_alerts_count": total_correlated_alerts,
        "avg_alerts_per_incident": avg_alerts_per_incident
    }

def get_mitre_analytics(db: Session, limit: int = 15) -> Dict[str, Any]:
    """
    Aggregate MITRE ATT&CK technique frequencies directly from ingested indicators.
    Returns honest insufficient-data payload if no techniques are observed.
    """
    rows = db.query(
        Indicator.mitre_technique,
        func.count(Indicator.id).label("count")
    ).filter(
        Indicator.mitre_technique.isnot(None),
        Indicator.mitre_technique != "",
        Indicator.mitre_technique != "None"
    ).group_by(Indicator.mitre_technique).order_by(func.count(Indicator.id).desc()).limit(limit).all()

    if not rows:
        return {
            "has_data": False,
            "total_techniques_observed": 0,
            "techniques": [],
            "message": "No MITRE ATT&CK techniques observed in ingested threat telemetry"
        }

    techniques = []
    total_tagged = 0
    for tech, count in rows:
        total_tagged += count
        techniques.append({
            "id": tech,
            "count": count,
            # Common MITRE ATT&CK naming lookup fallback
            "name": _get_technique_name(tech),
            "tactic": _get_technique_tactic(tech),
        })

    return {
        "has_data": True,
        "total_techniques_observed": len(techniques),
        "total_indicators_tagged": total_tagged,
        "techniques": techniques
    }

def get_geographic_analytics(db: Session, limit: int = 10) -> Dict[str, Any]:
    """
    Aggregate geographic country origin density from verified threat intelligence enrichments.
    Returns honest insufficient-data payload if no enrichments contain country metadata.
    """
    rows = db.query(
        IndicatorEnrichment.country,
        func.count(IndicatorEnrichment.id).label("count")
    ).filter(
        IndicatorEnrichment.country.isnot(None),
        IndicatorEnrichment.country != "",
        IndicatorEnrichment.country != "None"
    ).group_by(IndicatorEnrichment.country).order_by(func.count(IndicatorEnrichment.id).desc()).limit(limit).all()

    if not rows:
        return {
            "has_data": False,
            "total_countries_observed": 0,
            "countries": [],
            "message": "No geographic origin telemetry recorded in threat intelligence enrichments"
        }

    total_geo = sum(count for _, count in rows)
    countries = []
    for code, count in rows:
        share = round((count / total_geo * 100), 1) if total_geo > 0 else 0.0
        countries.append({
            "country_code": code.upper(),
            "country_name": _country_code_to_name(code.upper()),
            "country": _country_code_to_name(code.upper()),
            "count": count,
            "share_percentage": share
        })

    return {
        "has_data": True,
        "total_countries_observed": len(countries),
        "total_enriched_locations": total_geo,
        "countries": countries
    }

def get_source_analytics(db: Session) -> Dict[str, Any]:
    """
    Aggregate indicator volumes grouped by threat feed and ingestion source.
    """
    rows = db.query(
        func.coalesce(Indicator.source, "manual").label("src"),
        func.count(Indicator.id).label("cnt")
    ).group_by("src").order_by(func.count(Indicator.id).desc()).all()

    total = sum(c for _, c in rows)
    sources = []
    for src, count in rows:
        share = round((count / total * 100), 1) if total > 0 else 0.0
        sources.append({
            "source": src,
            "count": count,
            "share_percentage": share
        })

    return {
        "total_sources": len(sources),
        "total_indicators": total,
        "sources": sources
    }

# MITRE technique metadata helper
def _get_technique_name(tech_id: str) -> str:
    lookup = {
        "T1071": "Standard Application Layer Protocol",
        "T1071.001": "Web Protocols (HTTP/HTTPS)",
        "T1090": "Proxy",
        "T1090.003": "Multi-hop Proxy",
        "T1566": "Phishing",
        "T1566.002": "Spearphishing Link",
        "T1027": "Obfuscated Files or Information",
        "T1190": "Exploit Public-Facing Application",
        "T1059": "Command and Scripting Interpreter",
        "T1105": "Ingress Tool Transfer",
    }
    return lookup.get(tech_id, f"Technique {tech_id}")

def _get_technique_tactic(tech_id: str) -> str:
    if tech_id.startswith("T1071") or tech_id.startswith("T1090") or tech_id.startswith("T1105"):
        return "Command and Control"
    if tech_id.startswith("T1566") or tech_id.startswith("T1190"):
        return "Initial Access"
    if tech_id.startswith("T1027"):
        return "Defense Evasion"
    if tech_id.startswith("T1059"):
        return "Execution"
    return "Adversary Tactic"

# Country code to English name helper
def _country_code_to_name(code: str) -> str:
    lookup = {
        "US": "United States",
        "CN": "China",
        "RU": "Russia",
        "DE": "Germany",
        "NL": "Netherlands",
        "GB": "United Kingdom",
        "FR": "France",
        "IN": "India",
        "BR": "Brazil",
        "KR": "South Korea",
        "JP": "Japan",
        "IR": "Iran",
        "KP": "North Korea",
        "UA": "Ukraine",
    }
    return lookup.get(code.upper(), code.upper())
