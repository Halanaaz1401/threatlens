# THREATLENS — PHASE 4F BASELINE AUDIT & ARCHITECTURE SPECIFICATION
**Target Component:** FR-22 Custom Dashboard Widget Builder  
**Audit Date:** October 2026  
**Auditor Mode:** Autonomous Implementation & Forensic Engineering  

---

## 1. Executive Summary

Phase 4F addresses the final functional requirement in the ThreatLens Product Requirements Document (PRD v1.0): **FR-22 — Custom Dashboard Widget Builder**.

The objective of Phase 4F is to empower SOC analysts, incident response leads, threat hunters, and security executives to configure and organize custom dashboards composed of modular, data-driven security widgets powered strictly by real ThreatLens telemetry.

### Architectural Invariant: Controlled Predefined Registry
A critical architectural constraint mandated by Phase 4F is:
**The widget builder must NOT become an arbitrary code execution system.**
Users will **never** submit arbitrary SQL queries, Python/JavaScript code, executable expressions, arbitrary HTML, or dynamic API URLs. All widgets are strictly backed by safe, predefined enumerations resolving directly against trusted internal analytics services (`analytics_service.py`, `incident_service`, `case_service`, `alert_service`, `indicator_service`, `enrichment_service`, `detection_rule_service`).

---

## 2. Current Architecture & Existing Reusable Assets

### 2.1 Analytics Backend (`analytics_service.py`)
Phase 4C established a deterministic statistical aggregation service calculating live telemetry from PostgreSQL:
- `get_executive_kpis`: Risk score (0–100), MTTD, MTTR, SEV-1 active incidents, total/recent indicators, active alerts, enrichment coverage.
- `get_threat_trends`: Zero-filled continuous time-series threat velocity and high-severity ingestion rate.
- `get_severity_distribution`: Severity breakdown across indicators, alerts, and incidents.
- `get_indicator_type_distribution`: Distribution across IPv4, IPv6, Domain, URL, Hash (MD5/SHA1/SHA256), CVE.
- `get_incident_analytics`: Incident status breakdown, severity breakdown, alert-to-incident correlation ratio.
- `get_mitre_analytics`: ATT&CK technique frequencies, tactics, and naming lookups.
- `get_geographic_analytics`: Country origin density derived from verified enrichments.
- `get_source_analytics`: Ingestion volume grouped by threat feed and source.

### 2.2 Reusable Frontend Components
- `AnalyticsCharts.tsx`: Recharts-powered area charts and donut/pie distribution visualizations.
- `GlobalHeatmap.tsx` / `AttackHeatmap.tsx`: World map visualization mapping threat origins.
- `HuntingGraph.tsx`: Interactive SVG relationship graph.
- Threat status badges, severity tags, and dark-theme Tailwind UI design language.

### 2.3 Existing Gaps (FR-22)
1. **No Dashboard Entity:** No database table exists to store user-created dashboards, their titles, descriptions, owners, or visibility.
2. **No Widget Persistence:** No database table exists to persist widget configurations (type, title, metrics, filters, position, width, height, refresh interval).
3. **No Dashboard / Widget APIs:** Canonical endpoints `/api/v1/dashboards` do not exist.
4. **No Dashboard Builder UI:** No route `/dashboard/builder` exists to let users compose custom layouts, select widget templates, preview data, and save grids.
5. **No Layout Persistence:** Current dashboard pages (`/dashboard/executive`, `/dashboard/analyst`, `/dashboard/incidents`, `/dashboard/hunting`, `/dashboard/cases`) are statically structured rather than customizable.

---

## 3. PRD FR-22 Requirements Traceability

| Requirement | PRD Reference | Target Behavior |
| :--- | :--- | :--- |
| **Custom Dashboard Builder** | FR-22 | Allow users to create, view, update, and delete custom dashboards with customized names and descriptions. |
| **Widget Library** | FR-22, Step 3 | Provide a catalog of 18 pre-built SOC widgets (KPIs, time-series, bar/line charts, distributions, recent alerts/incidents, rule activity). |
| **Safe Configuration** | Step 4, 16 | Configuration uses strict Pydantic models with enums for `widget_type`, `data_source`, `metric`, `time_range`. Zero arbitrary SQL/code. |
| **Grid Layout Persistence** | Step 12 | Persist `position_x`, `position_y`, `width`, `height` in database; support responsive grid rendering. |
| **Real Telemetry Resolution** | Step 7, 19 | Each widget queries canonical internal services. Zero mock/synthetic data. Honest empty states. |
| **Server-Side RBAC & IDOR** | Step 13, FR-26 | Viewer read-only (403 on mutation), Analyst/Admin full management; strict user ownership and IDOR isolation. |
| **Audit & Redis Events** | Step 17, 18 | Write audit entries for dashboard and widget operations; publish to `threatlens:events:dashboards`. |

---

## 4. Proposed Architecture

### 4.1 Database Models
Two new canonical tables linked to `users`:
1. **`dashboards` Table (`Dashboard` model):**
   - `id`: String(36) UUID PK
   - `name`: String(128)
   - `description`: String(512), nullable
   - `owner_id`: String(36) FK to `users.id`
   - `is_default`: Boolean, default False
   - `visibility`: String(32) Enum (`PRIVATE`, `SHARED`), default `PRIVATE`
   - `created_at`: DateTime(timezone=True)
   - `updated_at`: DateTime(timezone=True)
2. **`dashboard_widgets` Table (`DashboardWidget` model):**
   - `id`: String(36) UUID PK
   - `dashboard_id`: String(36) FK to `dashboards.id` (CASCADE on delete)
   - `title`: String(128)
   - `description`: String(256), nullable
   - `widget_type`: String(64) Enum (`KPI`, `TIME_SERIES`, `BAR_CHART`, `LINE_CHART`, `SEVERITY_DISTRIBUTION`, `INCIDENT_TREND`, `ALERT_TREND`, `IOC_TYPE_DISTRIBUTION`, `THREAT_INTEL_SOURCES`, `MITRE_ATTACK`, `GEOGRAPHIC_DISTRIBUTION`, `DETECTION_RULE_ACTIVITY`, `CASE_STATUS_DISTRIBUTION`, `CASE_SEVERITY_DISTRIBUTION`, `TOP_INDICATORS`, `RECENT_CRITICAL_INCIDENTS`, `RECENT_CRITICAL_ALERTS`, `ENRICHMENT_STATISTICS`)
   - `data_source`: String(64) Enum (`ANALYTICS`, `INCIDENTS`, `ALERTS`, `INDICATORS`, `CASES`, `DETECTION_RULES`, `ENRICHMENT`)
   - `metric`: String(64) Enum
   - `time_range`: String(32) Enum (`24h`, `7d`, `30d`, `90d`), default `24h`
   - `filters`: JSON (structured, whitelisted filter dict)
   - `display_options`: JSON (chart colors, display flags)
   - `position_x`: Integer, default 0
   - `position_y`: Integer, default 0
   - `width`: Integer, default 6 (out of 12-column grid)
   - `height`: Integer, default 4
   - `refresh_interval_seconds`: Integer, default 0 (0 = manual, 30–3600 bounded)
   - `created_at`: DateTime(timezone=True)
   - `updated_at`: DateTime(timezone=True)

### 4.2 Migration Strategy
Alembic migration `4f1dashboards_phase4f_custom_dashboards_and_widgets.py` revising `4e1casemgmt`.
Single canonical Alembic head maintained.

### 4.3 Backend API Design (`/api/v1/dashboards`)
- `GET /` — List dashboards accessible to current user (own + shared)
- `POST /` — Create custom dashboard
- `GET /{dashboard_id}` — Get dashboard metadata and attached widgets
- `PATCH /{dashboard_id}` — Update dashboard name, description, visibility, default flag
- `DELETE /{dashboard_id}` — Delete dashboard (owner or admin only)
- `POST /{dashboard_id}/duplicate` — Duplicate existing dashboard with all widgets
- `POST /{dashboard_id}/widgets` — Add widget to dashboard
- `GET /{dashboard_id}/widgets` — List widgets
- `GET /{dashboard_id}/widgets/{widget_id}` — Get single widget definition
- `PATCH /{dashboard_id}/widgets/{widget_id}` — Update widget config/layout
- `DELETE /{dashboard_id}/widgets/{widget_id}` — Remove widget
- `GET /{dashboard_id}/widgets/{widget_id}/data` — Query live telemetry for widget
- `POST /{dashboard_id}/layout` — Batch update positions/sizes of widgets

### 4.4 Frontend Architecture (`/dashboard/builder`)
- **Dashboard Selector / Creator:** Select active dashboard, create new dashboard, rename, set as default, duplicate.
- **Widget Catalog Modal:** Card-based selector displaying the 18 supported SOC widgets with visual badges, descriptions, and previews.
- **Widget Configuration Drawer:** Configures title, time range (`24h`, `7d`, `30d`, `90d`), chart options, and safe filters with real-time live preview.
- **Responsive 12-Column Dashboard Grid:** Clean, drag/reorder/resize interface adhering to ThreatLens dark mode.
- **Widget Renderers:**
  - KPI card renderer (big numbers, trend indicator, calculation basis)
  - Recharts time-series & bar chart renderer
  - Severity donut renderer
  - Table / tabular list renderer for recent incidents, alerts, top IOCs
  - Geographic list renderer
  - Detection rule activity bar renderer

---

## 5. Security Invariants & Risk Assessment

1. **Zero Dynamic Code Execution:** Completely reject `eval()`, `exec()`, or custom code string evaluation.
2. **Strict Enumeration Validation:** Every `widget_type`, `data_source`, `metric`, and `time_range` validated by strict Pydantic field validators and database check constraints.
3. **IDOR & Cross-User Defense:** Users cannot view or modify dashboards owned by others unless explicitly marked `SHARED`. Viewer role blocked with HTTP 403 on all mutations.
4. **Safe Query Dispatch:** Widget data resolution calls direct Python helper functions. Zero user input is interpolated into raw SQL.
5. **Bounded Polling:** Client polling bounded to >= 30 seconds to prevent denial of service.

---

## 6. Testing & Quality Assurance Plan

1. **Unit & Integration Tests (`test_phase4f_dashboards_and_widgets.py`):**
   - Dashboard CRUD, default dashboard assignment, visibility rules.
   - Widget creation across all 18 supported types.
   - Validation failures on illegal widget types, metrics, or invalid time ranges.
   - Live widget data resolution against empty and populated datasets.
   - Batch layout updating and persistence.
   - Server-side RBAC (Viewer 403 on mutation, Analyst/Admin allowed).
   - IDOR rejection when attempting to edit/delete another user's private dashboard.
   - Audit trail verification and Redis event publication.
2. **Full Regression:** Run all 158 existing tests (Phases 1A–4E) ensuring zero regressions.
3. **Runtime Verification:** Standalone QA script executing end-to-end dashboard and widget lifecycle with 0 mock data.
