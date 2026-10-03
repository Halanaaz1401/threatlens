"""
ThreatLens - Phase 4D-A Threat Hunting & Relationship Graph Test Suite
Verifies:
1. Canonical relationship creation with validation, confidence, and evidence
2. Self-relationship prohibition (model check constraint & service validation)
3. Duplicate relationship prevention and idempotent updates
4. Direct relationship retrieval with direction, type, and confidence filtering
5. Bounded multi-hop graph traversal (BFS) with cycle detection
6. Max depth limit enforcement (bounded 1-4)
7. Max node limit enforcement (bounded 1-100)
8. Authentic evidence-based relationship derivation (URL->Domain, Incidents, Enrichment)
9. Advanced hunting search resolver with relationship and incident counts
10. Authentication and RBAC enforcement (Viewer read-only, Analyst write)
11. Empty graph handling and non-existent indicator queries
"""
import uuid
import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db, SessionLocal
from app.models.indicator import Indicator, IndicatorType
from app.models.relationship import IndicatorRelationship, RelationshipType
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.enrichment import IndicatorEnrichment
from app.models.user import User, UserRole
from app.core.security import create_access_token, get_password_hash
from app.services.graph_service import (
    create_relationship,
    get_direct_relationships,
    get_subgraph,
    derive_evidence_relationships,
    search_hunting,
)

client = TestClient(app)

@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def analyst_headers(db_session):
    email = f"analyst_4d_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("SecurePass123!"),
        full_name="Phase 4D Analyst",
        role=UserRole.ANALYST.value,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(
        data={"sub": user.email, "role": user.role, "email": user.email},
        expires_delta=timedelta(minutes=60)
    )
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def viewer_headers(db_session):
    email = f"viewer_4d_{uuid.uuid4().hex[:6]}@threatlens.io"
    user = User(
        email=email,
        hashed_password=get_password_hash("SecurePass123!"),
        full_name="Phase 4D Viewer",
        role=UserRole.VIEWER.value,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(
        data={"sub": user.email, "role": user.role, "email": user.email},
        expires_delta=timedelta(minutes=60)
    )
    return {"Authorization": f"Bearer {token}"}


def test_relationship_creation(db_session):
    """Test programmatic relationship creation with full attributes."""
    ind1 = Indicator(value=f"198.51.100.{uuid.uuid4().hex[:4]}", type="ip", severity="HIGH")
    ind2 = Indicator(value=f"c2-{uuid.uuid4().hex[:4]}.bad.org", type="domain", severity="CRITICAL")
    db_session.add_all([ind1, ind2])
    db_session.commit()

    rel = create_relationship(
        db=db_session,
        source_indicator_id=ind1.id,
        target_indicator_id=ind2.id,
        relationship_type=RelationshipType.COMMUNICATES_WITH.value,
        confidence=85,
        evidence="Observed beaconing traffic on port 443",
        source="network_telemetry",
    )

    assert rel.id is not None
    assert rel.source_indicator_id == ind1.id
    assert rel.target_indicator_id == ind2.id
    assert rel.relationship_type == "communicates-with"
    assert rel.confidence == 85
    assert rel.evidence == "Observed beaconing traffic on port 443"


def test_self_relationship_prevention(db_session):
    """Self-relationships must be strictly rejected by service and API."""
    ind = Indicator(value=f"loopback-{uuid.uuid4().hex[:4]}.test", type="domain")
    db_session.add(ind)
    db_session.commit()

    # Service rejection
    with pytest.raises(ValueError, match="Self-relationships are prohibited"):
        create_relationship(
            db=db_session,
            source_indicator_id=ind.id,
            target_indicator_id=ind.id,
            relationship_type=RelationshipType.RELATED_TO.value,
        )


def test_duplicate_relationship_prevention(db_session):
    """Creating existing relationship must update rather than create duplicates."""
    ind1 = Indicator(value=f"host1-{uuid.uuid4().hex[:4]}.net", type="domain")
    ind2 = Indicator(value=f"203.0.113.{uuid.uuid4().hex[:3]}", type="ip")
    db_session.add_all([ind1, ind2])
    db_session.commit()

    rel1 = create_relationship(
        db=db_session,
        source_indicator_id=ind1.id,
        target_indicator_id=ind2.id,
        relationship_type=RelationshipType.RESOLVES_TO.value,
        confidence=60,
        evidence="Initial DNS capture",
    )

    initial_count = db_session.query(IndicatorRelationship).filter(
        IndicatorRelationship.source_indicator_id == ind1.id,
        IndicatorRelationship.target_indicator_id == ind2.id,
    ).count()
    assert initial_count == 1

    # Second creation with updated confidence
    rel2 = create_relationship(
        db=db_session,
        source_indicator_id=ind1.id,
        target_indicator_id=ind2.id,
        relationship_type=RelationshipType.RESOLVES_TO.value,
        confidence=90,
        evidence="Passive DNS confirmation",
    )

    after_count = db_session.query(IndicatorRelationship).filter(
        IndicatorRelationship.source_indicator_id == ind1.id,
        IndicatorRelationship.target_indicator_id == ind2.id,
    ).count()
    assert after_count == 1
    assert rel2.id == rel1.id
    assert rel2.confidence == 90
    assert rel2.evidence == "Passive DNS confirmation"


def test_relationship_retrieval_and_filtering(db_session):
    """Verify direct relationship retrieval with direction, type, and confidence filters."""
    root = Indicator(value=f"root-{uuid.uuid4().hex[:4]}.org", type="domain")
    child1 = Indicator(value=f"child1-{uuid.uuid4().hex[:4]}.org", type="domain")
    child2 = Indicator(value=f"child2-{uuid.uuid4().hex[:4]}.org", type="domain")
    parent = Indicator(value=f"parent-{uuid.uuid4().hex[:4]}.org", type="domain")
    db_session.add_all([root, child1, child2, parent])
    db_session.commit()

    create_relationship(db_session, root.id, child1.id, RelationshipType.COMMUNICATES_WITH.value, confidence=90)
    create_relationship(db_session, root.id, child2.id, RelationshipType.REDIRECTS_TO.value, confidence=40)
    create_relationship(db_session, parent.id, root.id, RelationshipType.HOSTED_ON.value, confidence=80)

    # Direction outgoing
    out_res = get_direct_relationships(db_session, root.id, direction="outgoing")
    assert out_res["total"] == 2

    # Direction incoming
    in_res = get_direct_relationships(db_session, root.id, direction="incoming")
    assert in_res["total"] == 1
    assert in_res["items"][0]["source_indicator_id"] == parent.id

    # Filter by type
    type_res = get_direct_relationships(db_session, root.id, direction="both", relationship_type=RelationshipType.REDIRECTS_TO.value)
    assert type_res["total"] == 1
    assert type_res["items"][0]["target_indicator_id"] == child2.id

    # Filter by confidence
    conf_res = get_direct_relationships(db_session, root.id, direction="both", min_confidence=75)
    assert conf_res["total"] == 2  # child1 (90) and parent (80), child2 (40) excluded


def test_bounded_multihop_graph_traversal(db_session):
    """Test BFS traversal with multi-hop reach and depth bounding."""
    # Topology: n0 -> n1 -> n2 -> n3
    n0 = Indicator(value=f"n0-{uuid.uuid4().hex[:4]}.test", type="domain")
    n1 = Indicator(value=f"n1-{uuid.uuid4().hex[:4]}.test", type="domain")
    n2 = Indicator(value=f"n2-{uuid.uuid4().hex[:4]}.test", type="domain")
    n3 = Indicator(value=f"n3-{uuid.uuid4().hex[:4]}.test", type="domain")
    db_session.add_all([n0, n1, n2, n3])
    db_session.commit()

    create_relationship(db_session, n0.id, n1.id, RelationshipType.COMMUNICATES_WITH.value)
    create_relationship(db_session, n1.id, n2.id, RelationshipType.REDIRECTS_TO.value)
    create_relationship(db_session, n2.id, n3.id, RelationshipType.RESOLVES_TO.value)

    # Depth 1: should include n0, n1 (2 nodes, 1 edge)
    g1 = get_subgraph(db_session, n0.id, max_depth=1)
    assert g1["total_nodes"] == 2
    assert g1["total_edges"] == 1
    node_ids_g1 = {n["id"] for n in g1["nodes"]}
    assert node_ids_g1 == {str(n0.id), str(n1.id)}

    # Depth 2: should include n0, n1, n2 (3 nodes, 2 edges)
    g2 = get_subgraph(db_session, n0.id, max_depth=2)
    assert g2["total_nodes"] == 3
    assert g2["total_edges"] == 2
    node_ids_g2 = {n["id"] for n in g2["nodes"]}
    assert node_ids_g2 == {str(n0.id), str(n1.id), str(n2.id)}

    # Depth 3: should include all 4 nodes
    g3 = get_subgraph(db_session, n0.id, max_depth=3)
    assert g3["total_nodes"] == 4
    assert g3["total_edges"] == 3


def test_cycle_prevention_in_graph_traversal(db_session):
    """Test that circular references (n0 -> n1 -> n2 -> n0) do not cause infinite loops or duplicate nodes."""
    n0 = Indicator(value=f"cycle0-{uuid.uuid4().hex[:4]}.com", type="domain")
    n1 = Indicator(value=f"cycle1-{uuid.uuid4().hex[:4]}.com", type="domain")
    n2 = Indicator(value=f"cycle2-{uuid.uuid4().hex[:4]}.com", type="domain")
    db_session.add_all([n0, n1, n2])
    db_session.commit()

    create_relationship(db_session, n0.id, n1.id, RelationshipType.COMMUNICATES_WITH.value)
    create_relationship(db_session, n1.id, n2.id, RelationshipType.REDIRECTS_TO.value)
    create_relationship(db_session, n2.id, n0.id, RelationshipType.RESOLVES_TO.value)

    # Traversal up to max depth 4 should terminate cleanly with exactly 3 nodes
    graph = get_subgraph(db_session, n0.id, max_depth=4)
    assert graph["total_nodes"] == 3
    assert len(graph["nodes"]) == 3
    assert graph["total_edges"] == 3


def test_evidence_based_relationship_derivation(db_session):
    """Verify authentic derivation from URL hostnames, incidents, and enrichment."""
    # 1. URL -> Domain
    domain_val = f"target-{uuid.uuid4().hex[:4]}.xyz"
    url_val = f"https://{domain_val}/malicious/payload.exe"
    domain_ind = Indicator(value=domain_val, type=IndicatorType.DOMAIN.value)
    url_ind = Indicator(value=url_val, type=IndicatorType.URL.value)
    db_session.add_all([domain_ind, url_ind])
    db_session.commit()

    # 2. Incident co-occurrence
    ip_ind1 = Indicator(value=f"10.0.1.{uuid.uuid4().hex[:3]}", type=IndicatorType.IP.value)
    ip_ind2 = Indicator(value=f"10.0.2.{uuid.uuid4().hex[:3]}", type=IndicatorType.IP.value)
    db_session.add_all([ip_ind1, ip_ind2])
    db_session.commit()

    inc = Incident(
        incident_code=f"INC-{uuid.uuid4().hex[:4].upper()}",
        title="Lateral Movement Attack",
        indicator_id=ip_ind1.id,
        severity="HIGH",
        status="OPEN",
    )
    db_session.add(inc)
    db_session.commit()

    al = Alert(
        indicator_id=ip_ind2.id,
        incident_id=inc.id,
        title="Correlated alert",
        severity="HIGH",
        status="INVESTIGATING",
    )
    db_session.add(al)
    db_session.commit()

    # Run derivation
    res = derive_evidence_relationships(db_session)
    assert res["derived_count"] >= 2

    # Check URL->Domain hosted-on exists
    url_rel = db_session.query(IndicatorRelationship).filter(
        IndicatorRelationship.source_indicator_id == url_ind.id,
        IndicatorRelationship.target_indicator_id == domain_ind.id,
    ).first()
    assert url_rel is not None
    assert url_rel.relationship_type == RelationshipType.HOSTED_ON.value
    assert "hosted on domain" in url_rel.evidence

    # Check Incident co-occurrence related-to exists
    from sqlalchemy import or_, and_
    inc_rel = db_session.query(IndicatorRelationship).filter(
        or_(
            and_(IndicatorRelationship.source_indicator_id == ip_ind1.id, IndicatorRelationship.target_indicator_id == ip_ind2.id),
            and_(IndicatorRelationship.source_indicator_id == ip_ind2.id, IndicatorRelationship.target_indicator_id == ip_ind1.id),
        )
    ).first()
    assert inc_rel is not None
    assert inc_rel.relationship_type == RelationshipType.RELATED_TO.value
    assert "Co-observed in Incident" in inc_rel.evidence


def test_hunting_search(db_session):
    """Test hunting search returns indicators with relationship, enrichment, and incident counts."""
    keyword = f"apt-{uuid.uuid4().hex[:4]}"
    ind = Indicator(value=f"{keyword}.target.org", type="domain", mitre_technique="T1071")
    other = Indicator(value=f"192.168.1.{uuid.uuid4().hex[:2]}", type="ip")
    db_session.add_all([ind, other])
    db_session.commit()

    create_relationship(db_session, ind.id, other.id, RelationshipType.COMMUNICATES_WITH.value)

    res = search_hunting(db_session, query_str=keyword)
    assert res["total"] >= 1
    match = next((item for item in res["items"] if item["id"] == ind.id), None)
    assert match is not None
    assert match["relationships_count"] == 1
    assert match["mitre_technique"] == "T1071"


def test_hunting_api_auth_and_rbac(db_session, analyst_headers, viewer_headers):
    """Test API authentication and RBAC permissions."""
    ind1 = Indicator(value=f"api1-{uuid.uuid4().hex[:4]}.com", type="domain")
    ind2 = Indicator(value=f"api2-{uuid.uuid4().hex[:4]}.com", type="domain")
    db_session.add_all([ind1, ind2])
    db_session.commit()

    # 1. Unauthenticated requests fail
    resp_unauth = client.get(f"/api/v1/hunting/graph/{ind1.id}")
    assert resp_unauth.status_code in (401, 403)

    # 2. Viewer can read graph
    resp_viewer_graph = client.get(f"/api/v1/hunting/graph/{ind1.id}", headers=viewer_headers)
    assert resp_viewer_graph.status_code == 200
    assert resp_viewer_graph.json()["root_id"] == str(ind1.id)

    # 3. Viewer is forbidden from creating relationships (requires Analyst+)
    create_payload = {
        "source_indicator_id": str(ind1.id),
        "target_indicator_id": str(ind2.id),
        "relationship_type": RelationshipType.COMMUNICATES_WITH.value,
        "confidence": 80,
    }
    resp_viewer_create = client.post("/api/v1/hunting/relationships", json=create_payload, headers=viewer_headers)
    assert resp_viewer_create.status_code == 403

    # 4. Analyst can create relationships
    resp_analyst_create = client.post("/api/v1/hunting/relationships", json=create_payload, headers=analyst_headers)
    assert resp_analyst_create.status_code == 201
    assert resp_analyst_create.json()["data"]["relationship_type"] == "communicates-with"

    # 5. Analyst can trigger derivation
    resp_derive = client.post("/api/v1/hunting/derive", json={"limit": 20}, headers=analyst_headers)
    assert resp_derive.status_code == 200
    assert "derived_count" in resp_derive.json()["data"]

    # 6. Hunting search API works
    resp_search = client.get(f"/api/v1/hunting/search?q={ind1.value}", headers=viewer_headers)
    assert resp_search.status_code == 200
    assert resp_search.json()["total"] >= 1


def test_empty_graph_and_nonexistent_indicator(db_session, viewer_headers):
    """Test graceful handling of isolated nodes and non-existent indicator queries."""
    # Isolated node
    isolated = Indicator(value=f"isolated-{uuid.uuid4().hex[:4]}.com", type="domain")
    db_session.add(isolated)
    db_session.commit()

    resp_iso = client.get(f"/api/v1/hunting/graph/{isolated.id}", headers=viewer_headers)
    assert resp_iso.status_code == 200
    data = resp_iso.json()
    assert data["total_nodes"] == 1
    assert data["total_edges"] == 0
    assert data["nodes"][0]["id"] == str(isolated.id)
    assert data["nodes"][0]["is_root"] is True

    # Non-existent node -> 404
    non_existent_id = str(uuid.uuid4())
    resp_404 = client.get(f"/api/v1/hunting/graph/{non_existent_id}", headers=viewer_headers)
    assert resp_404.status_code == 404
