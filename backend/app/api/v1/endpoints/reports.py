import os
import re
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from pydantic import BaseModel, Field

from app.db.session import get_db
from app.models.report import Report, ReportType, ReportStatus
from app.models.user import User
from app.core.rbac import (
    require_authenticated_user,
    require_analyst,
    require_admin,
    normalize_role
)
from app.services.pdf_report_service import (
    create_executive_report,
    validate_safe_path,
    REPORTS_STORAGE_DIR
)
from app.services.audit_service import log_action

router = APIRouter()

# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class ExecutiveReportRequest(BaseModel):
    time_range: str = Field("30d", description="Reporting period: 24h, 7d, 30d, 90d")

def serialize_report(report: Report) -> Dict[str, Any]:
    """Serialize report metadata without exposing sensitive internal file paths."""
    return {
        "id": str(report.id),
        "report_code": report.report_code,
        "title": report.title,
        "report_type": report.report_type,
        "time_range": report.time_range,
        "status": report.status,
        "file_name": report.file_name,
        "file_size_bytes": report.file_size_bytes,
        "content_hash": report.content_hash,
        "created_by": report.created_by,
        "created_by_role": report.created_by_role,
        "generation_duration_ms": report.generation_duration_ms,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "download_url": f"/api/v1/reports/{report.id}/download",
    }

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/executive", status_code=status.HTTP_201_CREATED)
def generate_executive_report_endpoint(
    payload: ExecutiveReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Generate an authoritative Executive Security Report PDF on-demand (Analyst+).
    Grounded exclusively in real ThreatLens PostgreSQL telemetry.
    """
    tr = payload.time_range.lower().strip()
    if tr not in ["24h", "7d", "30d", "90d"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time_range '{payload.time_range}'. Allowed: 24h, 7d, 30d, 90d"
        )

    author_name = current_user.full_name or current_user.email or current_user.username or "SOC Analyst"
    author_role = normalize_role(current_user.role)

    try:
        report = create_executive_report(
            db=db,
            time_range=tr,
            author=author_name,
            author_role=author_role
        )
        return serialize_report(report)
    except Exception as e:
        log_action(
            db=db,
            action="REPORT_GENERATION_FAILED",
            actor=author_name,
            details=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)}"
        )

@router.get("/")
@router.get("")
def list_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    report_type: Optional[str] = Query(None, description="Filter by report_type"),
    status: Optional[str] = Query(None, description="Filter by status (COMPLETED, PENDING, FAILED)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """List generated executive reports with metadata (Authenticated)."""
    query = db.query(Report)

    if report_type:
        query = query.filter(Report.report_type.ilike(report_type.strip()))
    if status:
        query = query.filter(Report.status.ilike(status.strip()))

    reports = query.order_by(desc(Report.created_at)).offset(skip).limit(limit).all()
    return [serialize_report(r) for r in reports]

@router.get("/{report_id}")
def get_report_metadata(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """Retrieve metadata of a single report by UUID or report_code (Authenticated)."""
    report = db.query(Report).filter(
        or_(Report.id == report_id, Report.report_code == report_id)
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return serialize_report(report)

@router.get("/{report_id}/download")
def download_report_pdf(
    report_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user)
):
    """
    Download generated Executive Security Report PDF (Authenticated).
    Enforces path traversal defenses, IDOR verification, and file existence.
    """
    actor_name = current_user.email or current_user.username or "Authenticated User"

    # Defense against malformed or traversal IDs in path
    if ".." in report_id or "/" in report_id or "\\" in report_id:
        log_action(
            db=db,
            action="REPORT_ACCESS_BLOCKED_TRAVERSAL",
            actor=actor_name,
            details=f"Invalid report_id containing path traversal: {report_id}"
        )
        raise HTTPException(status_code=400, detail="Invalid report identifier")

    report = db.query(Report).filter(
        or_(Report.id == report_id, Report.report_code == report_id)
    ).first()

    if not report:
        log_action(
            db=db,
            action="REPORT_DOWNLOAD_NOT_FOUND",
            actor=actor_name,
            details=f"Attempted download for missing report {report_id}"
        )
        raise HTTPException(status_code=404, detail="Report not found")

    if not report.file_path:
        raise HTTPException(status_code=404, detail="Report file not found")

    # Path traversal validation
    try:
        canonical_path = validate_safe_path(report.file_path)
    except ValueError as path_err:
        log_action(
            db=db,
            action="REPORT_ACCESS_BLOCKED_TRAVERSAL",
            actor=actor_name,
            details=f"Unsafe path detected: {report.file_path}"
        )
        raise HTTPException(status_code=403, detail="Unsafe file path rejected")

    if not os.path.exists(canonical_path) or not os.path.isfile(canonical_path):
        raise HTTPException(status_code=404, detail="Report file does not exist on storage")

    # Audit download
    log_action(
        db=db,
        action="REPORT_DOWNLOADED",
        actor=actor_name,
        target_resource=f"report:{report.id}",
        details={
            "report_id": report.id,
            "report_code": report.report_code,
            "file_name": report.file_name,
            "file_size": report.file_size_bytes
        }
    )

    return FileResponse(
        path=canonical_path,
        media_type="application/pdf",
        filename=report.file_name,
        headers={
            "Content-Disposition": f'attachment; filename="{report.file_name}"',
            "X-ThreatLens-Report-Code": report.report_code,
            "X-ThreatLens-Report-Hash": report.content_hash or ""
        }
    )
