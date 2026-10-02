# ThreatLens Phase 4D-A: Advanced Threat Hunting & Indicator Relationship Graph Report

**Date:** 2026-10-02  
**Phase Status:** COMPLETE  
**Git Checkpoint:** `3df1135`  
**Test Suite Status:** 106 Passed / 0 Failed / 0 Errors / 0 Skipped  
**Frontend Build:** PASS (Next.js 16.3.1 Turbopack, 0 TypeScript errors)  
**Mock Data Audit:** CLEAN (Zero fake graph data, 0 synthetic nodes, 0 `Math.random()`)  

---

## 1. Executive Summary

Phase 4D-A delivers the **Advanced Threat Hunting and Indicator Relationship Graph** engine for ThreatLens, fulfilling requirements **FR-09** (Indicator Relationships) and **FR-25** (Advanced Threat Hunting & Faceted Search). 

The implementation introduces a canonical relational graph model (`indicator_relationships`), an Alembic schema migration (`4d1re1at1onsh1p`), a dedicated `GraphService` with bounded Breadth-First Search (BFS) multi-hop traversal and cycle prevention, authentic evidence-based relationship derivation (URL hostnames, incident co-occurrences, enrichment network telemetry), canonical enterprise authenticated REST endpoints under `/api/v1/hunting`, and an interactive deterministic SVG visualization component (`HuntingGraph.tsx`) embedded within `/dashboard/hunting` with full search query routing from `Navbar.tsx`.

---

## 2. Relationship Model

The relational database model is canonically defined in [backend/app/models/relationship.py](file:///c:/Users/Hala/Downloads/Project%20Files/threatlens-main/threatlens-main-git/backend/app/models/relationship.py):

```python
class IndicatorRelationship(Base):
    __tablename__ = "indicator_relationships"
    __table_args__ = (
        UniqueConstraint("source_indicator_id", "target_indicator_id", "relationship_type", name="uq_indicator_relationship"),
        CheckConstraint("source_indicator_id != target_indicator_id", name="ck_no_self_relationship"),
        {"extend_existing": True},
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    target_indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False, index=True)
    confidence = Column(SmallInteger, default=70)
    evidence = Column(Text, nullable=True)
    source = Column(String(100), default="automated")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

### Constraints and Guarantees
- **No Self-Relationships:** Enforced at both the database level via `CheckConstraint("source_indicator_id != target_indicator_id")` and at the service layer with validation exceptions.
- **Deduplication:** Enforced via `UniqueConstraint("source_indicator_id", "target_indicator_id", "relationship_type")`. Re-creating existing relationships idempotently updates confidence and evidence without generating redundant edges.
- **Referential Integrity:** Foreign keys to `indicators.id` with `ondelete="CASCADE"`.
- **Bidirectional ORM Relationships:** [backend/app/models/indicator.py](file:///c:/Users/Hala/Downloads/Project%20Files/threatlens-main/threatlens-main-git/backend/app/models/indicator.py) exposes `outgoing_relationships` and `incoming_relationships`.
- **Alembic Migration:** [backend/alembic/versions/4d1re1at1onsh1p_phase4d_a_indicator_relationships.py](file:///c:/Users/Hala/Downloads/Project%20Files/threatlens-main/threatlens-main-git/backend/alembic/versions/4d1re1at1onsh1p_phase4d_a_indicator_relationships.py) creates the table and composite indexes for PostgreSQL and SQLite.

---

## 3. Relationship Types

Only semantically valid, justified relationship types are supported (`RelationshipType` enum):

| Relationship Type | Description | Directionality |
| :--- | :--- | :--- |
| `resolves-to` | Domain or hostname resolving to an IP address | Domain -> IP |
| `communicates-with` | Observed network beaconing, traffic, or protocol activity | Indicator -> Indicator |
| `redirects-to` | HTTP redirection or CNAME chaining | URL/Domain -> URL/Domain |
| `hosted-on` | URL or service hosted on an identifiable domain or infrastructure | URL -> Domain |
| `related-to` | Co-occurrence within an incident, shared malware campaign, or actor | Indicator <-> Indicator |
| `downloaded-from` | File artifact or payload downloaded from a URL or host | Hash -> URL |

---

## 4. Relationship Generation & Provenance

ThreatLens prohibits fabricated or synthetic edges. Relationships are derived strictly from authentic data:

1. **URL to Domain (`hosted-on`):**
   - Extracts hostname from URL indicators (`urllib.parse.urlparse`).
   - If a matching domain indicator exists, links `URL -> Domain` with confidence `90` and evidence: `URL '{url}' is hosted on domain '{domain}'`.
2. **Incident Co-occurrence (`related-to`):**
   - Identifies distinct indicators linked to the same canonical `Incident` (via `indicator_id` or correlated `alerts`).
   - Pairs indicators with confidence `80` and evidence: `Co-observed in Incident {code}: '{title}'`.
3. **Enrichment Telemetry (`resolves-to`):**
   - Matches resolved network IPs in `IndicatorEnrichment` records (e.g. VirusTotal, AbuseIPDB, OTX) to existing IP indicators.
   - Sets confidence to the provider confidence with evidence: `Derived from {provider} threat intel network telemetry: {ip}`.

---

## 5. Graph Service Architecture

Defined in [backend/app/services/graph_service.py](file:///c:/Users/Hala/Downloads/Project%20Files/threatlens-main/threatlens-main-git/backend/app/services/graph_service.py):

- `create_relationship(...)`: Validates indicators, non-self constraints, clamps confidence (0–100), and handles idempotent upserts.
- `get_direct_relationships(...)`: Retrieves direct 1-hop links with direction filtering (`outgoing`, `incoming`, `both`), type filtering, min confidence, and paginated limits. Hydrates connected indicators in a single batch query (avoiding N+1).
- `get_subgraph(...)`: Bounded Breadth-First Search (BFS) algorithm:
  - Conservative default depth: `max_depth = 2` (hard cap `4`).
  - Safe node cap: `max_nodes = 50` (hard cap `100`).
  - Strict cycle detection via `visited_ids` set.
  - Batched node hydration query for all visited IDs.
- `derive_evidence_relationships(...)`: Executes safe, evidence-based relationship derivation across the active database.
- `search_hunting(...)`: Aggregates indicator matches with 1-hop relationship counts, enrichment totals, and associated incident metrics.

---

## 6. Hunting API Specification

Mounted canonically under `/api/v1/hunting` in [backend/app/api/v1/endpoints/hunting.py](file:///c:/Users/Hala/Downloads/Project%20Files/threatlens-main/threatlens-main-git/backend/app/api/v1/endpoints/hunting.py):

| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/hunting/indicators/{id}/relationships` | Authenticated | Direct 1-hop relationships with direction and confidence filters |
| `GET` | `/api/v1/hunting/graph/{id}` | Authenticated | Bounded multi-hop subgraph (`max_depth=1..4`, `max_nodes=1..100`) |
| `POST` | `/api/v1/hunting/relationships` | Analyst+ | Programmatic creation/update of validated indicator relationships |
| `POST` | `/api/v1/hunting/derive` | Analyst+ | Triggers authentic evidence derivation from telemetry and incidents |
| `GET` | `/api/v1/hunting/search?q={query}` | Authenticated | IOC search returning relationship, enrichment, and incident counts |

Every endpoint enforces JWT authentication, role verification, input constraints, and immutable audit logging for state-changing actions.

---

## 7. Advanced Hunting Search & Navbar Connection

- **Navbar Integration:** [frontend/src/components/Navbar.tsx](file:///c:/Users/Hala/Downloads/Project%20Files/threatlens-main/threatlens-main-git/frontend/src/components/Navbar.tsx) was connected to the search flow. Submitting a search routes directly to `/dashboard/hunting?q={query}`.
- **Hunting Query Bar:** [frontend/src/app/dashboard/hunting/page.tsx](file:///c:/Users/Hala/Downloads/Project%20Files/threatlens-main/threatlens-main-git/frontend/src/app/dashboard/hunting/page.tsx) automatically reads URL query parameters (`?q=...`), searches the backend, and presents matching indicators with relationship indicators.

---

## 8. Frontend Graph Visualization

Defined in [frontend/src/components/HuntingGraph.tsx](file:///c:/Users/Hala/Downloads/Project%20Files/threatlens-main/threatlens-main-git/frontend/src/components/HuntingGraph.tsx):

- **Deterministic Layout:** Radial/concentric layout without random coordinates. The focal root indicator is positioned at the exact center `(centerX, centerY)`. 1-hop direct neighbors are positioned deterministically along an inner orbit ring ($R_1 = 0.28 \times \min(W, H)$), and 2+-hop nodes on an outer orbit ring ($R_2 = 0.42 \times \min(W, H)$).
- **Visual Styling:**
  - Nodes color-coded by severity: `CRITICAL` (red glow/border), `HIGH` (orange), `MEDIUM` (yellow), `LOW` (slate/blue).
  - Center icons reflect indicator type: IP (🌐), DOMAIN (🏢), URL (🔗), CVE (🛡️), HASH (🔑), EMAIL (✉️).
  - Edges labeled with relationship types and confidence pills.
- **Interactive Capabilities:**
  - Single-click on any node opens the Target Node Inspector panel.
  - Double-click on any node pivots the entire graph to center on that indicator.
  - Hover tooltips display real threat scores, MITRE techniques, and relationship provenance.
- **State Handling:** Dedicated renders for loading (spinner), API errors, empty states, and isolated nodes.

---

## 9. Test Suite Verification

Dedicated test suite created in [backend/tests/test_phase4d_hunting.py](file:///c:/Users/Hala/Downloads/Project%20Files/threatlens-main/threatlens-main-git/backend/tests/test_phase4d_hunting.py):

| Test Case | Description | Status |
| :--- | :--- | :--- |
| `test_relationship_creation` | Creates canonical relationship with type, confidence, and evidence | PASS |
| `test_self_relationship_prevention` | Rejects self-referential relationships (`source == target`) | PASS |
| `test_duplicate_relationship_prevention` | Deduplicates edges; updates confidence without row inflation | PASS |
| `test_relationship_retrieval_and_filtering` | Validates direction (`outgoing`/`incoming`/`both`), type, and confidence filters | PASS |
| `test_bounded_multihop_graph_traversal` | Validates BFS depth progression (depth 1, depth 2, depth 3) | PASS |
| `test_cycle_prevention_in_graph_traversal` | Traverses circular topologies (A -> B -> C -> A) without infinite loops | PASS |
| `test_evidence_based_relationship_derivation` | Derives `hosted-on` from URLs and `related-to` from incidents | PASS |
| `test_hunting_search` | Resolves query string with aggregated relationship and incident counts | PASS |
| `test_hunting_api_auth_and_rbac` | Enforces 401 unauth, Viewer read-only, Analyst write permissions | PASS |
| `test_empty_graph_and_nonexistent_indicator` | Handles isolated nodes (0 edges) and non-existent IDs (404) | PASS |

### Full Pytest Regression
```
pytest tests/ -v
====================== 106 passed, 500 warnings in 7.21s ======================
```
- Total test count increased from **96** to **106**.
- **0 failed, 0 errors, 0 skipped.**
- Zero regressions against Phase 1–4C test suites.

---

## 10. Frontend Production Build Verification

```
> frontend@0.1.0 build
> next build

▲ Next.js 16.3.1 (Turbopack)
✓ Running next.config.ts took 151ms
✓ Compiled successfully in 7.0s
  Running TypeScript ...
  Finished TypeScript in 4.4s ...
  Collecting page data using 9 workers ...
✓ Generating static pages using 9 workers (8/8) in 982ms
  Finalizing page optimization ...

Route (app)
┌ ○ /
├ ○ /_not-found
├ ○ /dashboard/analyst
├ ○ /dashboard/executive
├ ○ /dashboard/hunting
└ ○ /dashboard/incidents

○  (Static)  prerendered as static content
```
Result: **0 errors, 0 warnings.**

---

## 11. Mock Data Audit

Forensic scan of production code:
- `Math.random`: 0 usages in application logic (1 comment referencing deterministic layout).
- `synthetic`: 0 occurrences.
- `fake`: 0 occurrences.
- `hardcoded graph`: 0 occurrences.
- `sample relationships`: 0 occurrences.
- **Production Graph Simulation:** **ZERO**.

---

## 12. Audit Matrix Update

Updated in [THREATLENS_IMPLEMENTATION_AUDIT.md](file:///c:/Users/Hala/Downloads/Project%20Files/threatlens-main/threatlens-main-git/THREATLENS_IMPLEMENTATION_AUDIT.md):
- **FR-09:** Changed from `MISSING` to **`REAL`**.
- **FR-25:** Changed from `BROKEN` to **`REAL`**.

---

## 13. Files Changed

### Backend Files
1. `backend/app/models/relationship.py` (New: `IndicatorRelationship`, `RelationshipType`)
2. `backend/app/models/indicator.py` (Updated: Added `outgoing_relationships`, `incoming_relationships`)
3. `backend/app/models/__init__.py` (Updated: Re-export relationship models)
4. `backend/alembic/versions/4d1re1at1onsh1p_phase4d_a_indicator_relationships.py` (New: Migration)
5. `backend/app/services/graph_service.py` (New: `GraphService` with traversal, derivation, search)
6. `backend/app/api/v1/endpoints/hunting.py` (New: Authenticated REST endpoints)
7. `backend/app/api/v1/api.py` (Updated: Mounted `/hunting` router)
8. `backend/tests/test_phase4d_hunting.py` (New: 10 unit and integration tests)

### Frontend Files
9. `frontend/src/lib/api.ts` (Updated: Added graph, relationships, search, and derivation fetchers)
10. `frontend/src/components/Navbar.tsx` (Updated: Connected search form to `/dashboard/hunting?q=...`)
11. `frontend/src/components/HuntingGraph.tsx` (New: Interactive deterministic SVG graph visualizer)
12. `frontend/src/app/dashboard/hunting/page.tsx` (Updated: Full threat hunting query bar, graph, inspector, and pivoting)

### Documentation & Audit Files
13. `THREATLENS_IMPLEMENTATION_AUDIT.md` (Updated: FR-09 and FR-25 marked REAL)
14. `PHASE_4D_A_HUNTING_GRAPH_REPORT.md` (New: Complete implementation and QA report)

---

## 14. Phase 4D-A Status: COMPLETE
Phase 4D-A is fully implemented, verified, and ready for review.
