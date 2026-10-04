import os
import io
import time
import uuid
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_, desc

from app.models.indicator import Indicator, ThreatSeverity
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.models.case import Case, CaseStatus, CaseSeverity
from app.models.detection_rule import DetectionRule
from app.models.enrichment import IndicatorEnrichment
from app.models.report import Report, ReportType, ReportStatus
from app.models.audit import AuditLog
from app.services.analytics_service import (
    get_executive_kpis,
    get_trends,
    get_severity_breakdown,
    get_mitre_analytics,
    get_geographic_density,
    parse_time_window,
    to_naive_utc
)
from app.services.audit_service import log_action
from app.core.redis import publish_report_event
from app.core.config import settings

logger = logging.getLogger("threatlens.report_service")

# Controlled local storage directory for reports
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REPORTS_STORAGE_DIR = os.path.join(BASE_DIR, settings.REPORTS_DIR)
os.makedirs(REPORTS_STORAGE_DIR, exist_ok=True)

def generate_report_code(db: Session) -> str:
    """Generate deterministic report reference code: RPT-YYYY-XXXX."""
    year = datetime.now(timezone.utc).year
    prefix = f"RPT-{year}-"
    last_rpt = db.query(Report).filter(Report.report_code.like(f"{prefix}%")).order_by(desc(Report.report_code)).first()
    if last_rpt and last_rpt.report_code:
        try:
            seq_part = last_rpt.report_code.replace(prefix, "")
            next_seq = int(seq_part) + 1
        except Exception:
            next_seq = db.query(func.count(Report.id)).scalar() + 1
    else:
        next_seq = 1
    return f"{prefix}{next_seq:04d}"

def validate_safe_path(requested_path: str) -> str:
    """Validate that path is safely contained within REPORTS_STORAGE_DIR."""
    storage_root = os.path.realpath(REPORTS_STORAGE_DIR)
    canonical = os.path.realpath(requested_path)
    if not canonical.startswith(storage_root):
        raise ValueError("Path traversal attempt detected")
    return canonical

def compile_executive_report_data(
    db: Session,
    time_range: str = "30d",
    author: str = "ThreatLens System"
) -> Dict[str, Any]:
    """
    Compile comprehensive, authoritative executive security metrics.
    Grounded exclusively in live PostgreSQL tables without synthetic values.
    """
    start_time, now, bucket_interval = parse_time_window(time_range)

    # 1. Executive Posture & KPIs
    kpis = get_executive_kpis(db, time_range)

    # 2. Incidents in Window
    incidents_query = db.query(Incident).filter(Incident.created_at >= start_time)
    total_incidents = incidents_query.count()
    active_incidents = incidents_query.filter(
        Incident.status.in_([IncidentStatus.OPEN.value, IncidentStatus.IN_PROGRESS.value, "OPEN", "IN_PROGRESS"])
    ).count()
    contained_incidents = incidents_query.filter(
        Incident.status.in_([IncidentStatus.CONTAINED.value, IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value, "CONTAINED", "RESOLVED", "CLOSED"])
    ).count()

    top_critical_incidents = db.query(Incident).filter(
        Incident.created_at >= start_time,
        or_(Incident.severity == "CRITICAL", Incident.severity == "HIGH")
    ).order_by(desc(Incident.correlation_score), desc(Incident.created_at)).limit(10).all()

    # 3. Severity Distribution (Incidents)
    sev_counts = db.query(Incident.severity, func.count(Incident.id)).filter(
        Incident.created_at >= start_time
    ).group_by(Incident.severity).all()
    incident_severity_dist = {str(s): c for s, c in sev_counts}

    # 4. Cases in Window
    cases_query = db.query(Case).filter(Case.created_at >= start_time)
    total_cases = cases_query.count()
    open_cases = cases_query.filter(Case.status.in_([CaseStatus.OPEN.value, CaseStatus.IN_PROGRESS.value])).count()
    resolved_cases = cases_query.filter(Case.status.in_([CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value, CaseStatus.CONTAINED.value])).count()
    recent_cases = cases_query.order_by(desc(Case.created_at)).limit(10).all()

    # 5. Top Threat Indicators
    top_indicators = db.query(Indicator).filter(
        Indicator.created_at >= start_time
    ).order_by(desc(Indicator.severity_score), desc(Indicator.confidence)).limit(10).all()

    # 6. Detection Rules & Alert Summary
    alerts_query = db.query(Alert).filter(Alert.created_at >= start_time)
    total_alerts = alerts_query.count()
    active_alerts = alerts_query.filter(Alert.status.in_(["NEW", "ACKNOWLEDGED", "IN_PROGRESS", "new", "acknowledged", "in_progress"])).count()
    rule_counts = db.query(Alert.rule_name, func.count(Alert.id)).filter(
        Alert.created_at >= start_time
    ).group_by(Alert.rule_name).order_by(desc(func.count(Alert.id))).limit(8).all()
    rule_activity = [{"rule_name": r, "count": c} for r, c in rule_counts if r]

    # 7. MITRE ATT&CK Techniques
    mitre_data = get_mitre_analytics(db)
    top_mitre_techniques = mitre_data.get("techniques", [])[:8]

    # 8. Threat Intelligence / Enrichment
    total_enrichments = db.query(func.count(IndicatorEnrichment.id)).filter(
        IndicatorEnrichment.created_at >= start_time
    ).scalar() or 0
    provider_counts = db.query(IndicatorEnrichment.provider, func.count(IndicatorEnrichment.id)).filter(
        IndicatorEnrichment.created_at >= start_time
    ).group_by(IndicatorEnrichment.provider).all()
    enrichment_breakdown = [{"provider": p, "count": c} for p, c in provider_counts if p]

    # 9. Geographic Distribution
    geo_data = get_geographic_density(db)
    top_geography = geo_data.get("locations", [])[:8]

    # 10. Major Findings Formulation (Grounded strictly in data)
    findings = []
    if kpis.get("active_sev1_incidents", {}).get("count", 0) > 0:
        c = kpis["active_sev1_incidents"]["count"]
        findings.append(f"{c} active critical (SEV-1) security incident(s) currently require containment and mitigation.")
    if len(top_critical_incidents) > 0:
        top_inc = top_critical_incidents[0]
        ioc = top_inc.matched_ioc_value or top_inc.primary_indicator or "N/A"
        findings.append(f"Highest-risk correlation cluster detected: '{top_inc.title}' involving indicator {ioc} (Correlation Score: {top_inc.correlation_score}).")
    if top_mitre_techniques:
        lead_tech = top_mitre_techniques[0]
        findings.append(f"Dominant adversary technique observed: {lead_tech.get('name')} ({lead_tech.get('id')}) with {lead_tech.get('count')} correlated indicator sightings.")
    if total_incidents == 0 and total_alerts == 0:
        findings.append("No active security incidents or alerts detected within the current reporting window.")

    # 11. Recommended Actions Formulation
    recommendations = []
    if open_cases > 0:
        recommendations.append(f"Prioritize investigation workflows for {open_cases} open forensic case(s) currently assigned to SOC analysts.")
    if active_alerts > 0:
        recommendations.append(f"Accelerate alert triage for {active_alerts} unacknowledged/in-progress alerts across SOC Tier-1 and Tier-2 queues.")
    if kpis.get("enrichment_coverage", {}).get("percentage", 0) < 50.0 and kpis.get("indicators", {}).get("total", 0) > 0:
        recommendations.append("Increase threat intelligence enrichment quota across VirusTotal, AbuseIPDB, and AlienVault OTX to expand indicator reputation visibility.")
    if not recommendations:
        recommendations.append("Maintain continuous threat feed ingestion and routine baseline detection rule tuning.")

    return {
        "report_title": "ThreatLens Enterprise Cybersecurity Executive Briefing",
        "time_range": time_range,
        "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "end_time": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "author": author,
        "kpis": kpis,
        "incidents": {
            "total": total_incidents,
            "active": active_incidents,
            "contained": contained_incidents,
            "severity_dist": incident_severity_dist,
            "top_critical": [
                {
                    "code": inc.incident_code or inc.id[:8],
                    "title": inc.title,
                    "severity": str(inc.severity),
                    "status": str(inc.status),
                    "score": inc.correlation_score or 0,
                    "matched_ioc": inc.matched_ioc_value or inc.primary_indicator or "N/A",
                    "host": inc.affected_host or "Enterprise Network",
                }
                for inc in top_critical_incidents
            ]
        },
        "cases": {
            "total": total_cases,
            "open": open_cases,
            "resolved": resolved_cases,
            "recent": [
                {
                    "number": c.case_number,
                    "title": c.title,
                    "severity": c.severity,
                    "priority": c.priority,
                    "status": c.status,
                    "assignee": c.assignee or "Unassigned",
                    "incidents_count": len(c.case_incidents) if c.case_incidents else 0,
                    "evidence_count": len(c.evidence) if c.evidence else 0,
                }
                for c in recent_cases
            ]
        },
        "indicators": {
            "total": kpis.get("indicators", {}).get("total", 0),
            "top": [
                {
                    "type": str(ind.type),
                    "value": ind.value,
                    "severity_score": ind.severity_score,
                    "confidence": ind.confidence,
                    "source": ind.sources[0].source_name if ind.sources else "ThreatLens Ingestion",
                }
                for ind in top_indicators
            ]
        },
        "alerts": {
            "total": total_alerts,
            "active": active_alerts,
            "rule_activity": rule_activity,
        },
        "mitre_techniques": top_mitre_techniques,
        "enrichment": {
            "total": total_enrichments,
            "coverage_pct": kpis.get("enrichment_coverage", {}).get("percentage", 0),
            "breakdown": enrichment_breakdown,
        },
        "geography": top_geography,
        "findings": findings,
        "recommendations": recommendations,
    }

# ---------------------------------------------------------------------------
# PDF Generation Engines
# ---------------------------------------------------------------------------

def _render_reportlab_pdf(data: Dict[str, Any], output_path: str) -> bool:
    """Render executive PDF using reportlab if installed."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
        )
        from reportlab.pdfgen import canvas
    except ImportError:
        return False

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.draw_page_number(num_pages)
                super().showPage()
            super().save()

        def draw_page_number(self, page_count):
            self.saveState()
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            page_text = f"ThreatLens Executive Report | Page {self._pageNumber} of {page_count} | TLP:AMBER"
            self.drawRightString(612 - 36, 25, page_text)
            self.drawString(36, 25, "CONFIDENTIAL - RESTRICTED FOR EXECUTIVE LEADERSHIP")
            self.restoreState()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=12
    )
    h1_style = ParagraphStyle(
        "Heading1_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )
    empty_style = ParagraphStyle(
        "Empty_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        spaceBefore=4,
        spaceAfter=6
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("THREATLENS CYBER THREAT INTELLIGENCE", ParagraphStyle("TLHeader", fontName="Helvetica-Bold", fontSize=9, textColor=colors.HexColor("#0284c7"))))
    story.append(Paragraph(data["report_title"], title_style))
    story.append(Paragraph(f"Reporting Period: <b>{data['start_time']}</b> to <b>{data['end_time']}</b> ({data['time_range']}) | Prepared By: {data['author']}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=14))

    # 2. Executive Summary
    story.append(Paragraph("1. Executive Summary &amp; Threat Posture", h1_style))
    risk_score = data["kpis"].get("enterprise_risk_score", {}).get("score", 0)
    risk_level = data["kpis"].get("enterprise_risk_score", {}).get("level", "LOW")
    mttd = data["kpis"].get("mttd", {}).get("formatted", "N/A")
    mttr = data["kpis"].get("mttr", {}).get("formatted", "N/A")

    kpi_table_data = [
        ["Enterprise Risk Score", "Mean Time to Detect (MTTD)", "Mean Time to Respond (MTTR)", "Active SEV-1 Incidents"],
        [f"{risk_score} / 100 ({risk_level})", mttd, mttr, str(data["kpis"].get("active_sev1_incidents", {}).get("count", 0))]
    ]
    t_kpi = Table(kpi_table_data, colWidths=[135, 135, 135, 135])
    t_kpi.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8.5),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#f8fafc")),
        ('TEXTCOLOR', (0,1), (-1,1), colors.HexColor("#0f172a")),
        ('FONTNAME', (0,1), (-1,1), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_kpi)
    story.append(Spacer(1, 12))

    # 3. Security Findings
    story.append(Paragraph("2. Major Findings &amp; Observations", h1_style))
    if data["findings"]:
        for f in data["findings"]:
            story.append(Paragraph(f"• {f}", body_style))
    else:
        story.append(Paragraph("No data available for the selected reporting period.", empty_style))
    story.append(Spacer(1, 10))

    # 4. Recommended Actions
    story.append(Paragraph("3. Recommended Strategic Mitigations", h1_style))
    if data["recommendations"]:
        for r in data["recommendations"]:
            story.append(Paragraph(f"• {r}", body_style))
    else:
        story.append(Paragraph("No data available for the selected reporting period.", empty_style))
    story.append(Spacer(1, 12))

    # 5. Incident & Case Overview
    story.append(Paragraph("4. Correlated Incidents &amp; Forensic Case Overview", h1_style))
    inc_data = data["incidents"]
    case_data = data["cases"]

    overview_matrix = [
        ["Total Incidents", "Active Incidents", "Contained / Resolved", "Total Cases", "Open Cases", "Resolved Cases"],
        [str(inc_data["total"]), str(inc_data["active"]), str(inc_data["contained"]), str(case_data["total"]), str(case_data["open"]), str(case_data["resolved"])]
    ]
    t_over = Table(overview_matrix, colWidths=[90, 90, 90, 90, 90, 90])
    t_over.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#f1f5f9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_over)
    story.append(Spacer(1, 10))

    # 6. Critical & High Severity Incidents Table
    story.append(Paragraph("5. Critical &amp; High Severity Incidents", h1_style))
    top_incs = inc_data["top_critical"]
    if top_incs:
        inc_table = [["Incident Code", "Severity", "Score", "Matched Indicator", "Affected Host", "Status"]]
        for inc in top_incs[:6]:
            inc_table.append([
                inc["code"],
                inc["severity"],
                str(inc["score"]),
                Paragraph(inc["matched_ioc"][:30], body_style),
                inc["host"][:20],
                inc["status"]
            ])
        t_inc = Table(inc_table, colWidths=[80, 55, 45, 180, 100, 80])
        t_inc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#334155")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 7.5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_inc)
    else:
        story.append(Paragraph("No data available for the selected reporting period.", empty_style))
    story.append(Spacer(1, 12))

    # Page Break for Top Indicators and Intelligence Details
    story.append(PageBreak())

    # 7. Top Threat Indicators
    story.append(Paragraph("6. Top Authoritative Threat Indicators (IOCs)", h1_style))
    top_iocs = data["indicators"]["top"]
    if top_iocs:
        ioc_table = [["Type", "Indicator Value", "Severity Score", "Confidence", "Source Feed"]]
        for ioc in top_iocs[:8]:
            ioc_table.append([
                ioc["type"],
                Paragraph(ioc["value"][:45], body_style),
                str(ioc["severity_score"]),
                f"{ioc['confidence']}%",
                ioc["source"][:25]
            ])
        t_ioc = Table(ioc_table, colWidths=[70, 220, 75, 65, 110])
        t_ioc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_ioc)
    else:
        story.append(Paragraph("No data available for the selected reporting period.", empty_style))
    story.append(Spacer(1, 12))

    # 8. MITRE ATT&CK & Geographic Distribution
    story.append(Paragraph("7. MITRE ATT&amp;CK Adversary Tactics &amp; Geographic Activity", h1_style))
    techs = data["mitre_techniques"]
    if techs:
        mitre_table = [["Technique ID", "Technique Name", "Tactic", "Sightings"]]
        for t in techs[:5]:
            mitre_table.append([t.get("id", "N/A"), t.get("name", "N/A"), t.get("tactic", "N/A"), str(t.get("count", 0))])
        t_mitre = Table(mitre_table, colWidths=[80, 220, 140, 100])
        t_mitre.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#475569")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_mitre)
    else:
        story.append(Paragraph("No data available for the selected reporting period.", empty_style))
    story.append(Spacer(1, 12))

    # 9. Detection Rules & Alert Summary
    story.append(Paragraph("8. Detection Rule &amp; Threat Intelligence Summary", h1_style))
    rules = data["alerts"]["rule_activity"]
    if rules:
        rule_table = [["Detection Rule Name", "Alert Triggers"]]
        for r in rules[:5]:
            rule_table.append([r["rule_name"], str(r["count"])])
        t_rule = Table(rule_table, colWidths=[380, 160])
        t_rule.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#334155")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_rule)
    else:
        story.append(Paragraph("No data available for the selected reporting period.", empty_style))
    story.append(Spacer(1, 14))

    # 10. Generation & Forensic Traceability
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))
    meta_p = Paragraph(
        f"<b>Forensic Report Metadata:</b> Generated: {data['generated_at']} | "
        f"Classification: TLP:AMBER | Architecture: ThreatLens PostgreSQL Telemetry Engine | "
        f"Report Engine Version: v1.0 SOC Executive",
        ParagraphStyle("MetaFoot", fontName="Helvetica", fontSize=7.5, textColor=colors.HexColor("#64748b"))
    )
    story.append(meta_p)

    doc.build(story, canvasmaker=NumberedCanvas)
    return True

def _render_pure_python_pdf(data: Dict[str, Any], output_path: str) -> bool:
    """
    Robust pure-Python PDF 1.4 generator fallback.
    Produces valid, standard-compliant PDF syntax with cross-reference table,
    catalog, page objects, fonts, and layout streams.
    Ensures 100% operational guarantee even in minimal environments without C-extensions.
    """
    lines = []
    lines.append("THREATLENS CYBER THREAT INTELLIGENCE - EXECUTIVE REPORT")
    lines.append("=" * 65)
    lines.append(f"Title: {data['report_title']}")
    lines.append(f"Reporting Window: {data['start_time']} to {data['end_time']} ({data['time_range']})")
    lines.append(f"Generated At: {data['generated_at']} | Prepared By: {data['author']}")
    lines.append(f"Classification: TLP:AMBER | Restricted Distribution")
    lines.append("=" * 65)
    lines.append("")
    lines.append("1. EXECUTIVE SUMMARY & POSTURE")
    lines.append("-" * 40)
    kpis = data["kpis"]
    risk = kpis.get("enterprise_risk_score", {})
    lines.append(f"  * Enterprise Risk Score: {risk.get('score', 0)}/100 ({risk.get('level', 'LOW')})")
    lines.append(f"  * Mean Time to Detect (MTTD): {kpis.get('mttd', {}).get('formatted', 'N/A')}")
    lines.append(f"  * Mean Time to Respond (MTTR): {kpis.get('mttr', {}).get('formatted', 'N/A')}")
    lines.append(f"  * Active SEV-1 Incidents: {kpis.get('active_sev1_incidents', {}).get('count', 0)}")
    lines.append(f"  * Total Active Indicators: {kpis.get('indicators', {}).get('total', 0)}")
    lines.append(f"  * Threat Intel Enrichment Coverage: {kpis.get('enrichment_coverage', {}).get('percentage', 0)}%")
    lines.append("")
    lines.append("2. MAJOR FINDINGS & OBSERVATIONS")
    lines.append("-" * 40)
    if data["findings"]:
        for f in data["findings"]:
            lines.append(f"  [+] {f}")
    else:
        lines.append("  No data available for the selected reporting period.")
    lines.append("")
    lines.append("3. RECOMMENDED ACTIONS")
    lines.append("-" * 40)
    if data["recommendations"]:
        for r in data["recommendations"]:
            lines.append(f"  [>] {r}")
    else:
        lines.append("  No data available for the selected reporting period.")
    lines.append("")
    lines.append("4. INCIDENT & CASE METRICS")
    lines.append("-" * 40)
    lines.append(f"  * Incidents Total: {data['incidents']['total']} | Active: {data['incidents']['active']} | Contained: {data['incidents']['contained']}")
    lines.append(f"  * Cases Total: {data['cases']['total']} | Open: {data['cases']['open']} | Resolved: {data['cases']['resolved']}")
    lines.append("")
    lines.append("5. CRITICAL AND HIGH SEVERITY INCIDENTS")
    lines.append("-" * 40)
    top_incs = data["incidents"]["top_critical"]
    if top_incs:
        for inc in top_incs[:6]:
            lines.append(f"  * [{inc['code']}] {inc['title'][:40]} | Sev: {inc['severity']} | Host: {inc['host']}")
            lines.append(f"    Matched IOC: {inc['matched_ioc']} | Status: {inc['status']} | Score: {inc['score']}")
    else:
        lines.append("  No data available for the selected reporting period.")
    lines.append("")
    lines.append("6. TOP THREAT INDICATORS (IOCs)")
    lines.append("-" * 40)
    top_iocs = data["indicators"]["top"]
    if top_iocs:
        for ioc in top_iocs[:8]:
            lines.append(f"  * {ioc['type']}: {ioc['value']} | Score: {ioc['severity_score']} | Conf: {ioc['confidence']}%")
    else:
        lines.append("  No data available for the selected reporting period.")
    lines.append("")
    lines.append("7. MITRE ATT&CK ADVERSARY TECHNIQUES")
    lines.append("-" * 40)
    techs = data["mitre_techniques"]
    if techs:
        for t in techs[:5]:
            lines.append(f"  * {t.get('id')}: {t.get('name')} | Tactic: {t.get('tactic')} | Sightings: {t.get('count')}")
    else:
        lines.append("  No data available for the selected reporting period.")
    lines.append("")
    lines.append("=" * 65)
    lines.append(f"Forensic Report Generation Metadata:")
    lines.append(f"Generated: {data['generated_at']} | Source: Authoritative PostgreSQL Telemetry")
    lines.append("ThreatLens Executive PDF Generator v1.0 SOC Standard")

    # Build raw PDF objects
    def escape_pdf_text(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    # Format into pages with 45 lines per page
    page_size = 45
    page_chunks = [lines[i:i + page_size] for i in range(0, len(lines), page_size)]
    if not page_chunks:
        page_chunks = [["No data available for the selected reporting period."]]

    num_pages = len(page_chunks)
    
    # PDF Body Construction
    obj_offsets = []
    pdf_buffer = byteio = io.BytesIO()

    def write_bytes(b: bytes):
        pdf_buffer.write(b)

    write_bytes(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

    # Obj 1: Catalog
    obj_offsets.append(pdf_buffer.tell())
    write_bytes(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

    # Obj 2: Pages Root
    page_refs = " ".join([f"{3 + i*2} 0 R" for i in range(num_pages)])
    obj_offsets.append(pdf_buffer.tell())
    write_bytes(f"2 0 obj\n<< /Type /Pages /Kids [{page_refs}] /Count {num_pages} >>\nendobj\n".encode("latin-1"))

    # Obj for Font
    font_obj_id = 3 + num_pages * 2
    
    # Write page and content objects
    for idx, page_lines in enumerate(page_chunks):
        page_obj_id = 3 + idx * 2
        content_obj_id = page_obj_id + 1

        # Page Object
        obj_offsets.append(pdf_buffer.tell())
        write_bytes(
            f"{page_obj_id} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Contents {content_obj_id} 0 R /Resources << /Font << /F1 {font_obj_id} 0 R >> >> >>\nendobj\n".encode("latin-1")
        )

        # Content Stream
        stream_parts = ["BT", "/F1 9 Tf", "40 750 Td", "14 TL"]
        for line in page_lines:
            escaped = escape_pdf_text(line)
            stream_parts.append(f"({escaped}) Tj")
            stream_parts.append("T*")
        
        # Page Footer
        footer_text = escape_pdf_text(f"ThreatLens Executive Report | Page {idx + 1} of {num_pages} | TLP:AMBER")
        stream_parts.append(f"0 0 Td")
        stream_parts.append("ET")
        stream_parts.append("BT")
        stream_parts.append("/F1 8 Tf")
        stream_parts.append(f"40 30 Td ({footer_text}) Tj ET")

        content_stream = "\n".join(stream_parts).encode("latin-1")
        obj_offsets.append(pdf_buffer.tell())
        write_bytes(f"{content_obj_id} 0 obj\n<< /Length {len(content_stream)} >>\nstream\n".encode("latin-1"))
        write_bytes(content_stream)
        write_bytes(b"\nendstream\nendobj\n")

    # Font Object
    obj_offsets.append(pdf_buffer.tell())
    write_bytes(
        f"{font_obj_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\nendobj\n".encode("latin-1")
    )

    # Cross-Reference Table
    xref_offset = pdf_buffer.tell()
    total_objs = len(obj_offsets) + 1
    write_bytes(f"xref\n0 {total_objs}\n0000000000 65535 f \n".encode("latin-1"))
    for offset in obj_offsets:
        write_bytes(f"{offset:010d} 00000 n \n".encode("latin-1"))

    # Trailer
    write_bytes(
        f"trailer\n<< /Size {total_objs} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin-1")
    )

    with open(output_path, "wb") as f:
        f.write(pdf_buffer.getvalue())
    return True

def generate_pdf_report_file(data: Dict[str, Any], output_path: str) -> Tuple[int, str]:
    """
    Generate PDF to output_path using reportlab or pure-Python fallback.
    Returns (file_size_bytes, sha256_hash).
    """
    rendered = _render_reportlab_pdf(data, output_path)
    if not rendered:
        _render_pure_python_pdf(data, output_path)

    with open(output_path, "rb") as f:
        content = f.read()

    file_size = len(content)
    content_hash = hashlib.sha256(content).hexdigest()
    return file_size, content_hash

def create_executive_report(
    db: Session,
    time_range: str = "30d",
    author: str = "ThreatLens System",
    author_role: Optional[str] = "executive"
) -> Report:
    """
    Execute full executive report compilation, PDF generation, persistence, and audit.
    """
    start_time_bench = time.time()
    report_code = generate_report_code(db)
    date_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_filename = f"ThreatLens_Executive_Report_{report_code.replace('-', '_')}_{date_slug}.pdf"
    file_path = os.path.join(REPORTS_STORAGE_DIR, safe_filename)

    # 1. Compile real data
    report_data = compile_executive_report_data(db, time_range=time_range, author=author)

    # 2. Render PDF
    file_size, sha256_hash = generate_pdf_report_file(report_data, file_path)
    duration_ms = int((time.time() - start_time_bench) * 1000)

    # 3. Persist Report Entity
    report = Report(
        report_code=report_code,
        title=f"Executive Security Briefing ({time_range.upper()})",
        report_type=ReportType.EXECUTIVE_SECURITY_SUMMARY.value,
        time_range=time_range,
        status=ReportStatus.COMPLETED.value,
        file_path=file_path,
        file_name=safe_filename,
        file_size_bytes=file_size,
        content_hash=sha256_hash,
        created_by=author,
        created_by_role=author_role,
        generation_duration_ms=duration_ms,
        parameters={"time_range": time_range, "report_code": report_code},
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    # 4. Audit Log
    log_action(
        db=db,
        action="REPORT_GENERATED",
        actor=author,
        target_resource=f"report:{report.id}",
        details={
            "report_id": report.id,
            "report_code": report.report_code,
            "time_range": time_range,
            "file_size_bytes": file_size,
            "hash": sha256_hash,
            "duration_ms": duration_ms
        }
    )

    # 5. Redis Event
    publish_report_event("REPORT_GENERATED", {
        "report_id": report.id,
        "report_code": report.report_code,
        "title": report.title,
        "created_by": author,
        "file_name": safe_filename,
        "file_size": file_size
    })

    return report
