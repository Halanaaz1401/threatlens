"""Dedicated Graph and Relationship Service for ThreatLens Threat Hunting (Phase 4D-A).

Provides:
- Canonical relationship creation with validation, constraint checks, and deduplication
- Direct relationship retrieval with direction, type, and confidence filtering
- Bounded multi-hop graph traversal (BFS) with strict cycle detection, max depth, and node limits
- Safe, evidence-based relationship derivation from authentic ThreatLens telemetry
- Advanced threat hunting search aggregating indicators, relationships, enrichments, and incidents
"""
import logging
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.models.indicator import Indicator, IndicatorType
from app.models.relationship import IndicatorRelationship, RelationshipType
from app.models.enrichment import IndicatorEnrichment
from app.models.incident import Incident
from app.models.alert import Alert

logger = logging.getLogger("threatlens.hunting.graph")

MAX_DEPTH_LIMIT = 4
MAX_NODES_LIMIT = 100
DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_NODES = 50

def create_relationship(
    db: Session,
    source_indicator_id: str,
    target_indicator_id: str,
    relationship_type: str,
    confidence: int = 70,
    evidence: Optional[str] = None,
    source: str = "manual",
) -> IndicatorRelationship:
    """
    Create or update a canonical relationship between two indicators.
    Enforces no self-relationships, existence of both indicators, valid type, and uniqueness.
    """
    if source_indicator_id == target_indicator_id:
        raise ValueError("Self-relationships are prohibited (source and target must be distinct).")

    # Validate relationship type
    valid_types = {t.value for t in RelationshipType}
    if relationship_type not in valid_types:
        raise ValueError(f"Invalid relationship_type '{relationship_type}'. Must be one of: {sorted(valid_types)}")

    # Validate source and target indicators exist
    source_ind = db.query(Indicator).filter(Indicator.id == source_indicator_id).first()
    if not source_ind:
        raise ValueError(f"Source indicator '{source_indicator_id}' not found.")

    target_ind = db.query(Indicator).filter(Indicator.id == target_indicator_id).first()
    if not target_ind:
        raise ValueError(f"Target indicator '{target_indicator_id}' not found.")

    # Clamp confidence
    clamped_confidence = max(0, min(100, int(confidence)))

    # Check for existing relationship
    existing = db.query(IndicatorRelationship).filter(
        IndicatorRelationship.source_indicator_id == source_indicator_id,
        IndicatorRelationship.target_indicator_id == target_indicator_id,
        IndicatorRelationship.relationship_type == relationship_type,
    ).first()

    if existing:
        # Update existing record if new confidence or evidence is provided
        if clamped_confidence > (existing.confidence or 0):
            existing.confidence = clamped_confidence
        if evidence:
            existing.evidence = evidence
        existing.source = source
        existing.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return existing

    rel = IndicatorRelationship(
        source_indicator_id=source_indicator_id,
        target_indicator_id=target_indicator_id,
        relationship_type=relationship_type,
        confidence=clamped_confidence,
        evidence=evidence,
        source=source,
    )
    db.add(rel)
    db.commit()
    db.refresh(rel)
    return rel


def get_direct_relationships(
    db: Session,
    indicator_id: str,
    direction: str = "both",
    relationship_type: Optional[str] = None,
    min_confidence: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """
    Retrieve direct 1-hop relationships for a given indicator with direction, type,
    and confidence filtering and safe pagination.
    """
    safe_limit = max(1, min(100, int(limit)))
    safe_offset = max(0, int(offset))
    safe_min_conf = max(0, min(100, int(min_confidence)))

    query = db.query(IndicatorRelationship)

    if direction == "outgoing":
        query = query.filter(IndicatorRelationship.source_indicator_id == indicator_id)
    elif direction == "incoming":
        query = query.filter(IndicatorRelationship.target_indicator_id == indicator_id)
    else:  # "both"
        query = query.filter(
            or_(
                IndicatorRelationship.source_indicator_id == indicator_id,
                IndicatorRelationship.target_indicator_id == indicator_id,
            )
        )

    if relationship_type:
        query = query.filter(IndicatorRelationship.relationship_type == relationship_type)

    if safe_min_conf > 0:
        query = query.filter(IndicatorRelationship.confidence >= safe_min_conf)

    total = query.count()
    relationships = query.order_by(IndicatorRelationship.created_at.desc()).offset(safe_offset).limit(safe_limit).all()

    # Hydrate indicators to avoid N+1 queries
    connected_ids = set()
    for r in relationships:
        connected_ids.add(r.source_indicator_id)
        connected_ids.add(r.target_indicator_id)

    indicators_map = {}
    if connected_ids:
        inds = db.query(Indicator).filter(Indicator.id.in_(list(connected_ids))).all()
        for ind in inds:
            indicators_map[ind.id] = {
                "id": ind.id,
                "value": ind.value,
                "type": ind.type,
                "severity": ind.severity,
                "threat_score": ind.threat_score,
                "confidence": ind.confidence,
                "status": ind.status,
            }

    items = []
    for r in relationships:
        r_dict = r.to_dict()
        r_dict["source_indicator"] = indicators_map.get(r.source_indicator_id)
        r_dict["target_indicator"] = indicators_map.get(r.target_indicator_id)
        items.append(r_dict)

    return {
        "indicator_id": indicator_id,
        "direction": direction,
        "total": total,
        "limit": safe_limit,
        "offset": safe_offset,
        "items": items,
    }


def get_subgraph(
    db: Session,
    indicator_id: str,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    min_confidence: int = 0,
    relationship_type: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Traverse the indicator relationship graph starting at indicator_id up to max_depth
    and capped by max_nodes using Breadth-First Search (BFS).
    Prevents cycles, bounded execution, and batches indicator hydration.
    """
    root = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not root:
        return None

    bounded_depth = max(1, min(MAX_DEPTH_LIMIT, int(max_depth)))
    bounded_nodes = max(1, min(MAX_NODES_LIMIT, int(max_nodes)))
    safe_min_conf = max(0, min(100, int(min_confidence)))

    visited_ids: Set[str] = {indicator_id}
    current_level: List[str] = [indicator_id]
    edges_by_id: Dict[str, Dict[str, Any]] = {}
    reached_depth = 0

    for depth in range(1, bounded_depth + 1):
        if not current_level or len(visited_ids) >= bounded_nodes:
            break

        reached_depth = depth
        # Query relationships connected to the current level nodes
        query = db.query(IndicatorRelationship).filter(
            or_(
                IndicatorRelationship.source_indicator_id.in_(current_level),
                IndicatorRelationship.target_indicator_id.in_(current_level),
            )
        )

        if relationship_type:
            query = query.filter(IndicatorRelationship.relationship_type == relationship_type)
        if safe_min_conf > 0:
            query = query.filter(IndicatorRelationship.confidence >= safe_min_conf)

        level_edges = query.all()
        next_level: Set[str] = set()

        for edge in level_edges:
            edges_by_id[edge.id] = edge.to_dict()

            # Determine the neighbor on the other side of this edge
            if edge.source_indicator_id in current_level:
                neighbor_id = edge.target_indicator_id
            else:
                neighbor_id = edge.source_indicator_id

            if neighbor_id not in visited_ids and len(visited_ids) < bounded_nodes:
                visited_ids.add(neighbor_id)
                next_level.add(neighbor_id)

        current_level = list(next_level)

    # Batch hydrate all visited nodes
    nodes_query = db.query(Indicator).filter(Indicator.id.in_(list(visited_ids))).all()
    nodes = []
    for ind in nodes_query:
        nodes.append({
            "id": ind.id,
            "value": ind.value,
            "type": ind.type,
            "severity": ind.severity,
            "threat_score": ind.threat_score,
            "confidence": ind.confidence,
            "status": ind.status,
            "tlp": ind.tlp,
            "sightings": ind.sightings,
            "mitre_technique": ind.mitre_technique,
            "is_root": ind.id == indicator_id,
            "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
            "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
        })

    return {
        "root_id": indicator_id,
        "max_depth": bounded_depth,
        "depth_reached": reached_depth,
        "total_nodes": len(nodes),
        "total_edges": len(edges_by_id),
        "nodes": nodes,
        "edges": list(edges_by_id.values()),
    }


def derive_evidence_relationships(
    db: Session,
    indicator_id: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Safely derives authentic relationships from existing ThreatLens evidence:
    1. URL -> Domain (HOSTED_ON): Extracts domain from URL and checks if that domain indicator exists.
    2. Incident Co-occurrence (RELATED_TO): Identifies distinct indicators linked to the same Incident or its alerts.
    3. Enrichment Resolution (RESOLVES_TO / COMMUNICATES_WITH): Identifies IPs in DNS/network enrichment matching known IP indicators.

    Every generated relationship contains real provenance/evidence.
    """
    derived_records: List[IndicatorRelationship] = []
    safe_limit = max(1, min(100, int(limit)))

    # 1. URL -> Domain (HOSTED_ON)
    url_query = db.query(Indicator).filter(Indicator.type == IndicatorType.URL.value)
    if indicator_id:
        url_query = url_query.filter(Indicator.id == indicator_id)
    url_indicators = url_query.order_by(Indicator.created_at.desc()).limit(safe_limit).all()

    for url_ind in url_indicators:
        try:
            parsed = urlparse(url_ind.value)
            hostname = parsed.hostname or parsed.netloc
            if hostname:
                # Remove port if present
                domain_val = hostname.split(":")[0].strip().lower()
                domain_ind = db.query(Indicator).filter(
                    Indicator.type == IndicatorType.DOMAIN.value,
                    Indicator.value == domain_val,
                ).first()

                if domain_ind and domain_ind.id != url_ind.id:
                    rel = create_relationship(
                        db=db,
                        source_indicator_id=url_ind.id,
                        target_indicator_id=domain_ind.id,
                        relationship_type=RelationshipType.HOSTED_ON.value,
                        confidence=90,
                        evidence=f"URL '{url_ind.value}' is hosted on domain '{domain_ind.value}'",
                        source="lexical_derivation",
                    )
                    derived_records.append(rel)
        except Exception as e:
            logger.debug(f"Failed to derive URL relationship for {url_ind.value}: {e}")

    # 2. Incident & Alert Co-occurrence (RELATED_TO)
    # Find incidents where multiple indicators are co-observed
    incidents_query = db.query(Incident)
    if indicator_id:
        incidents_query = incidents_query.filter(
            or_(
                Incident.indicator_id == indicator_id,
                Incident.alerts.any(Alert.indicator_id == indicator_id),
            )
        )
    incidents = incidents_query.order_by(Incident.created_at.desc()).limit(safe_limit).all()

    for inc in incidents:
        # Collect all indicators in this incident
        incident_indicator_ids = set()
        if inc.indicator_id:
            incident_indicator_ids.add(inc.indicator_id)

        for al in inc.alerts:
            if al.indicator_id:
                incident_indicator_ids.add(al.indicator_id)

        # Pairwise relate indicators with authentic evidence
        id_list = sorted(list(incident_indicator_ids))
        for i in range(len(id_list)):
            for j in range(i + 1, len(id_list)):
                src_id = id_list[i]
                tgt_id = id_list[j]
                try:
                    rel = create_relationship(
                        db=db,
                        source_indicator_id=src_id,
                        target_indicator_id=tgt_id,
                        relationship_type=RelationshipType.RELATED_TO.value,
                        confidence=80,
                        evidence=f"Co-observed in Incident {inc.incident_code or inc.id}: '{inc.title}'",
                        source="incident_correlation",
                    )
                    derived_records.append(rel)
                except Exception as e:
                    logger.debug(f"Failed to relate incident indicators {src_id}-{tgt_id}: {e}")

    # 3. Enrichment Network/DNS Telemetry (RESOLVES_TO / COMMUNICATES_WITH)
    enrich_query = db.query(IndicatorEnrichment).filter(IndicatorEnrichment.success == True)
    if indicator_id:
        enrich_query = enrich_query.filter(IndicatorEnrichment.indicator_id == indicator_id)
    enrichments = enrich_query.order_by(IndicatorEnrichment.created_at.desc()).limit(safe_limit).all()

    for enrich in enrichments:
        if enrich.network and isinstance(enrich.network, str):
            # Check if network string contains an IP matching a known indicator
            net_str = enrich.network.strip()
            matching_ip = db.query(Indicator).filter(
                Indicator.type == IndicatorType.IP.value,
                Indicator.value == net_str,
            ).first()
            if matching_ip and matching_ip.id != enrich.indicator_id:
                try:
                    rel = create_relationship(
                        db=db,
                        source_indicator_id=enrich.indicator_id,
                        target_indicator_id=matching_ip.id,
                        relationship_type=RelationshipType.RESOLVES_TO.value,
                        confidence=enrich.confidence or 75,
                        evidence=f"Derived from {enrich.provider} threat intel network telemetry: {net_str}",
                        source="enrichment_telemetry",
                    )
                    derived_records.append(rel)
                except Exception as e:
                    logger.debug(f"Failed to relate enrichment network IP: {e}")

    return {
        "derived_count": len(derived_records),
        "relationships": [r.to_dict() for r in derived_records],
    }


def search_hunting(
    db: Session,
    query_str: str,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    Advanced Threat Hunting query resolver.
    Looks up indicators matching query_str, populates 1-hop relationship counts,
    enrichment summaries, and associated incidents/alerts for quick hunting pivots.
    """
    safe_limit = max(1, min(50, int(limit)))
    clean_q = query_str.strip()

    # Search indicators by value exact/prefix/contains
    indicators = db.query(Indicator).filter(
        or_(
            Indicator.value.ilike(f"%{clean_q}%"),
            Indicator.type.ilike(f"%{clean_q}%"),
            Indicator.mitre_technique.ilike(f"%{clean_q}%"),
        )
    ).limit(safe_limit).all()

    results = []
    for ind in indicators:
        # Count relationships
        rel_count = db.query(IndicatorRelationship).filter(
            or_(
                IndicatorRelationship.source_indicator_id == ind.id,
                IndicatorRelationship.target_indicator_id == ind.id,
            )
        ).count()

        # Count enrichments
        enrich_count = db.query(IndicatorEnrichment).filter(
            IndicatorEnrichment.indicator_id == ind.id
        ).count()

        # Count associated incidents
        incident_count = db.query(Incident).filter(
            or_(
                Incident.indicator_id == ind.id,
                Incident.alerts.any(Alert.indicator_id == ind.id),
            )
        ).count()

        results.append({
            "id": ind.id,
            "value": ind.value,
            "type": ind.type,
            "severity": ind.severity,
            "threat_score": ind.threat_score,
            "confidence": ind.confidence,
            "status": ind.status,
            "tlp": ind.tlp,
            "mitre_technique": ind.mitre_technique,
            "relationships_count": rel_count,
            "enrichments_count": enrich_count,
            "incidents_count": incident_count,
            "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
        })

    return {
        "query": clean_q,
        "total": len(results),
        "items": results,
    }
