"""Threat Hunting API Endpoints (Phase 4D-A).

Provides canonical authenticated endpoints for:
- Retrieving direct indicator relationships
- Retrieving bounded multi-hop subgraphs for visual investigation
- Creating validated relationships (Analyst+)
- Triggering authentic evidence-based relationship derivation (Analyst+)
- Hunting query search with indicator, relationship, enrichment, and incident context
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Request, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.indicator import Indicator
from app.models.relationship import RelationshipType
from app.services.graph_service import (
    create_relationship,
    get_direct_relationships,
    get_subgraph,
    derive_evidence_relationships,
    search_hunting,
    MAX_DEPTH_LIMIT,
    MAX_NODES_LIMIT,
)
from app.services.audit_service import log_action
from app.core.rbac import require_authenticated_user, require_analyst

router = APIRouter()

class CreateRelationshipRequest(BaseModel):
    source_indicator_id: str = Field(..., description="ID of source indicator")
    target_indicator_id: str = Field(..., description="ID of target indicator")
    relationship_type: str = Field(..., description="Canonical relationship type")
    confidence: Optional[int] = Field(70, ge=0, le=100, description="Confidence score (0-100)")
    evidence: Optional[str] = Field(None, description="Verifiable evidence or provenance for this link")

class DeriveRelationshipsRequest(BaseModel):
    indicator_id: Optional[str] = Field(None, description="Optional specific indicator ID to derive for")
    limit: Optional[int] = Field(50, ge=1, le=100, description="Maximum items to inspect")


@router.get("/indicators/{indicator_id}/relationships")
def read_indicator_relationships(
    indicator_id: str,
    direction: str = Query("both", pattern="^(outgoing|incoming|both)$"),
    relationship_type: Optional[str] = Query(None),
    min_confidence: int = Query(0, ge=0, le=100),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Retrieve direct relationships for an indicator with direction, type, and confidence filtering.
    """
    indicator = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Indicator '{indicator_id}' not found.",
        )

    return get_direct_relationships(
        db=db,
        indicator_id=indicator_id,
        direction=direction,
        relationship_type=relationship_type,
        min_confidence=min_confidence,
        limit=limit,
        offset=offset,
    )


@router.get("/graph/{indicator_id}")
def read_indicator_graph(
    indicator_id: str,
    max_depth: int = Query(2, ge=1, le=MAX_DEPTH_LIMIT),
    max_nodes: int = Query(50, ge=1, le=MAX_NODES_LIMIT),
    min_confidence: int = Query(0, ge=0, le=100),
    relationship_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Retrieve bounded multi-hop subgraph starting from an indicator for visual threat hunting.
    Enforces depth limit (max 4), node cap (max 100), and cycle prevention.
    """
    subgraph = get_subgraph(
        db=db,
        indicator_id=indicator_id,
        max_depth=max_depth,
        max_nodes=max_nodes,
        min_confidence=min_confidence,
        relationship_type=relationship_type,
    )

    if subgraph is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Indicator '{indicator_id}' not found.",
        )

    return subgraph


@router.post("/relationships", status_code=status.HTTP_201_CREATED)
def create_new_relationship(
    payload: CreateRelationshipRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Create or update a canonical relationship between two indicators (Analyst+).
    Enforces validation and uniqueness constraints.
    """
    try:
        rel = create_relationship(
            db=db,
            source_indicator_id=payload.source_indicator_id,
            target_indicator_id=payload.target_indicator_id,
            relationship_type=payload.relationship_type,
            confidence=payload.confidence or 70,
            evidence=payload.evidence,
            source=f"analyst:{current_user.username}",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Audit logging
    try:
        log_action(
            db=db,
            action="CREATE_RELATIONSHIP",
            user_id=current_user.id,
            actor=current_user.username,
            target_resource=f"relationship:{rel.id}",
            details={
                "source_indicator_id": payload.source_indicator_id,
                "target_indicator_id": payload.target_indicator_id,
                "relationship_type": payload.relationship_type,
                "confidence": payload.confidence,
            },
            request=request,
        )
    except Exception:
        pass

    return {
        "status": "success",
        "data": rel.to_dict(),
    }


@router.post("/derive")
def derive_relationships(
    request: Request,
    payload: Optional[DeriveRelationshipsRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Derive authentic relationships from URL hostnames, enrichment telemetry, and incident co-occurrence (Analyst+).
    """
    ind_id = payload.indicator_id if payload else None
    limit = payload.limit if payload and payload.limit else 50

    result = derive_evidence_relationships(db=db, indicator_id=ind_id, limit=limit)

    try:
        log_action(
            db=db,
            action="DERIVE_RELATIONSHIPS",
            user_id=current_user.id,
            actor=current_user.username,
            target_resource=f"indicator:{ind_id or 'all'}",
            details={"derived_count": result.get("derived_count", 0)},
            request=request,
        )
    except Exception:
        pass

    return {
        "status": "success",
        "data": result,
    }


@router.get("/search")
def hunting_search(
    q: str = Query(..., min_length=1, description="IOC value, technique, or keyword to hunt for"),
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated_user),
):
    """
    Search indicators and return relationship counts, enrichments, and incident links for hunting.
    """
    return search_hunting(db=db, query_str=q, limit=limit)
