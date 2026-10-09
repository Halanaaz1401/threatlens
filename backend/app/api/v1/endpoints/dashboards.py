"""
ThreatLens - Phase 4F Custom Dashboard and Widget REST API Endpoints
Mounted under /api/v1/dashboards
Supports dashboard CRUD, widget catalog, widget configuration, live data resolution,
and responsive grid layout persistence.
"""
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.core.rbac import require_authenticated_user, RoleChecker
from app.services import dashboard_service

router = APIRouter(prefix="/dashboards", tags=["dashboards"])

require_analyst = RoleChecker(["admin", "analyst"])

# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class DashboardCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    is_default: bool = False
    visibility: str = Field("PRIVATE", pattern="^(PRIVATE|SHARED)$")

class DashboardUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    is_default: Optional[bool] = None
    visibility: Optional[str] = Field(None, pattern="^(PRIVATE|SHARED)$")

class WidgetCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=256)
    widget_type: str = Field(..., min_length=1, max_length=64)
    data_source: str = Field(..., min_length=1, max_length=64)
    metric: str = Field(..., min_length=1, max_length=64)
    time_range: str = Field("24h", pattern="^(24h|7d|30d|90d)$")
    filters: Optional[Dict[str, Any]] = None
    display_options: Optional[Dict[str, Any]] = None
    position_x: int = Field(0, ge=0, le=11)
    position_y: int = Field(0, ge=0)
    width: int = Field(6, ge=1, le=12)
    height: int = Field(4, ge=1, le=12)
    refresh_interval_seconds: int = Field(0, ge=0, le=3600)

class WidgetUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=256)
    widget_type: Optional[str] = Field(None, min_length=1, max_length=64)
    data_source: Optional[str] = Field(None, min_length=1, max_length=64)
    metric: Optional[str] = Field(None, min_length=1, max_length=64)
    time_range: Optional[str] = Field(None, pattern="^(24h|7d|30d|90d)$")
    filters: Optional[Dict[str, Any]] = None
    display_options: Optional[Dict[str, Any]] = None
    position_x: Optional[int] = Field(None, ge=0, le=11)
    position_y: Optional[int] = Field(None, ge=0)
    width: Optional[int] = Field(None, ge=1, le=12)
    height: Optional[int] = Field(None, ge=1, le=12)
    refresh_interval_seconds: Optional[int] = Field(None, ge=0, le=3600)

class LayoutItem(BaseModel):
    id: str
    position_x: Optional[int] = Field(None, ge=0, le=11)
    position_y: Optional[int] = Field(None, ge=0)
    width: Optional[int] = Field(None, ge=1, le=12)
    height: Optional[int] = Field(None, ge=1, le=12)

class LayoutUpdate(BaseModel):
    items: List[LayoutItem]

# ---------------------------------------------------------------------------
# Catalog Endpoint
# ---------------------------------------------------------------------------

@router.get("/catalog/widgets")
def get_widget_catalog(current_user: User = Depends(require_authenticated_user)):
    """Retrieve catalog of 18 pre-built SOC widgets with allowed metrics and sources."""
    return {"catalog": dashboard_service.get_widget_catalog()}

# ---------------------------------------------------------------------------
# Dashboard Endpoints
# ---------------------------------------------------------------------------

@router.get("")
@router.get("/")
def list_dashboards(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """List accessible custom dashboards (owned + shared)."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    dashboards, total = dashboard_service.list_dashboards(
        db=db,
        user_id=current_user.id,
        user_role=user_role,
        limit=limit,
        offset=offset
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "dashboards": [d.to_dict(include_widgets=False) for d in dashboards]
    }

@router.post("", status_code=status.HTTP_201_CREATED)
def create_dashboard(
    payload: DashboardCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create a new custom dashboard."""
    try:
        dashboard = dashboard_service.create_dashboard(
            db=db,
            user_id=current_user.id,
            name=payload.name,
            description=payload.description,
            is_default=payload.is_default,
            visibility=payload.visibility,
        )
        return dashboard.to_dict(include_widgets=True)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/{dashboard_id}")
def get_dashboard(
    dashboard_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """Get single dashboard with all attached widgets."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    try:
        dashboard = dashboard_service.get_dashboard(
            db=db,
            dashboard_id=dashboard_id,
            user_id=current_user.id,
            user_role=user_role
        )
        if not dashboard:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dashboard not found")
        return dashboard.to_dict(include_widgets=True)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

@router.patch("/{dashboard_id}")
def update_dashboard(
    dashboard_id: str,
    payload: DashboardUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update dashboard metadata."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    try:
        dashboard = dashboard_service.update_dashboard(
            db=db,
            dashboard_id=dashboard_id,
            user_id=current_user.id,
            user_role=user_role,
            name=payload.name,
            description=payload.description,
            is_default=payload.is_default,
            visibility=payload.visibility,
        )
        return dashboard.to_dict(include_widgets=True)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dashboard not found")
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.delete("/{dashboard_id}", status_code=status.HTTP_200_OK)
def delete_dashboard(
    dashboard_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Delete a custom dashboard."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    try:
        dashboard_service.delete_dashboard(
            db=db,
            dashboard_id=dashboard_id,
            user_id=current_user.id,
            user_role=user_role
        )
        return {"status": "success", "message": f"Dashboard {dashboard_id} deleted"}
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dashboard not found")
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

@router.post("/{dashboard_id}/duplicate", status_code=status.HTTP_201_CREATED)
def duplicate_dashboard(
    dashboard_id: str,
    new_name: Optional[str] = Query(None, description="Optional new dashboard name"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Duplicate an existing dashboard and its widgets."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    try:
        cloned = dashboard_service.duplicate_dashboard(
            db=db,
            dashboard_id=dashboard_id,
            user_id=current_user.id,
            user_role=user_role,
            new_name=new_name
        )
        return cloned.to_dict(include_widgets=True)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dashboard not found")
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

# ---------------------------------------------------------------------------
# Widget Endpoints
# ---------------------------------------------------------------------------

@router.get("/{dashboard_id}/widgets")
def list_widgets(
    dashboard_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """List all widgets belonging to a dashboard."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    dashboard = dashboard_service.get_dashboard(db, dashboard_id, current_user.id, user_role)
    if not dashboard:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dashboard not found")
    return {"widgets": [w.to_dict() for w in dashboard.widgets]}

@router.post("/{dashboard_id}/widgets", status_code=status.HTTP_201_CREATED)
def add_widget(
    dashboard_id: str,
    payload: WidgetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Add a validated widget from catalog to dashboard."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    try:
        widget = dashboard_service.add_widget(
            db=db,
            dashboard_id=dashboard_id,
            user_id=current_user.id,
            user_role=user_role,
            widget_data=payload.dict()
        )
        return widget.to_dict()
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dashboard not found")
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/{dashboard_id}/widgets/{widget_id}")
def get_widget(
    dashboard_id: str,
    widget_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """Get single widget definition."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    dashboard = dashboard_service.get_dashboard(db, dashboard_id, current_user.id, user_role)
    if not dashboard:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dashboard not found")
    widget = next((w for w in dashboard.widgets if w.id == widget_id), None)
    if not widget:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Widget not found")
    return widget.to_dict()

@router.patch("/{dashboard_id}/widgets/{widget_id}")
def update_widget(
    dashboard_id: str,
    widget_id: str,
    payload: WidgetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update widget configuration or dimensions."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    try:
        data = {k: v for k, v in payload.dict().items() if v is not None}
        widget = dashboard_service.update_widget(
            db=db,
            dashboard_id=dashboard_id,
            widget_id=widget_id,
            user_id=current_user.id,
            user_role=user_role,
            widget_data=data
        )
        return widget.to_dict()
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.delete("/{dashboard_id}/widgets/{widget_id}", status_code=status.HTTP_200_OK)
def delete_widget(
    dashboard_id: str,
    widget_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Delete widget from dashboard."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    try:
        dashboard_service.delete_widget(
            db=db,
            dashboard_id=dashboard_id,
            widget_id=widget_id,
            user_id=current_user.id,
            user_role=user_role
        )
        return {"status": "success", "message": f"Widget {widget_id} deleted"}
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

@router.get("/{dashboard_id}/widgets/{widget_id}/data")
def get_widget_data(
    dashboard_id: str,
    widget_id: str,
    time_range: Optional[str] = Query(None, pattern="^(24h|7d|30d|90d)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """Query live telemetry data for a specific widget."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    try:
        dashboard = dashboard_service.get_dashboard(db, dashboard_id, current_user.id, user_role)
        if not dashboard:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dashboard not found")
        widget = next((w for w in dashboard.widgets if w.id == widget_id), None)
        if not widget:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Widget not found")

        resolved_data = dashboard_service.resolve_widget_data(db, widget, time_range_override=time_range)
        return {
            "widget_id": widget.id,
            "widget_type": widget.widget_type,
            "metric": widget.metric,
            "time_range": time_range or widget.time_range,
            "data": resolved_data
        }
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to resolve widget telemetry: {str(e)}")

@router.post("/{dashboard_id}/layout")
def update_dashboard_layout(
    dashboard_id: str,
    payload: LayoutUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Batch update widget positions and sizes."""
    user_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    try:
        items = [item.dict() for item in payload.items]
        widgets = dashboard_service.update_dashboard_layout(
            db=db,
            dashboard_id=dashboard_id,
            user_id=current_user.id,
            user_role=user_role,
            layout_items=items
        )
        return {"status": "success", "widgets": [w.to_dict() for w in widgets]}
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
