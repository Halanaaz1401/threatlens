<div align="center">

# 🛡️ ThreatLens — Cyber Threat Intelligence (CTI) Platform

[![CI/CD Pipeline](https://github.com/Halanaaz1401/threatlens/actions/workflows/ci.yml/badge.svg)](https://github.com/Halanaaz1401/threatlens/actions/workflows/ci.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-16.0+-black.svg?logo=next.js&logoColor=white)](https://nextjs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571.svg?logo=elasticsearch&logoColor=white)](https://www.elastic.co)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

*An enterprise-grade Cyber Threat Intelligence (CTI) and SOC platform designed to aggregate, correlate, enrich, score, and operationalise threat intelligence across Security Operations Center (SOC) workflows.*

</div>

---

## 🏗️ Architecture & Core Capabilities

- **Automated Multi-Source Feed Ingestion**: Ingests, normalises, and deduplicates indicators from AlienVault OTX, AbuseIPDB, URLhaus, MalwareBazaar, and Feodo Tracker.
- **Dynamic Severity Scoring Engine**: 0–100 weighted risk algorithm factoring source reputation, confidence, recency decay, and internal sightings.
- **Sub-Second Search Engine**: Elasticsearch cluster integration providing full-text, faceted, and ATT&CK-mapped threat hunting queries.
- **Role-Specific SOC Dashboards**:
  - **Executive Overview (CISO)**: Strategic risk posture, 30-day exposure trends, alert throughput, and global threat heatmap.
  - **SOC Analyst Triage**: Prioritised alert queue, one-click indicator enrichment, and MITRE ATT&CK technique tags.
  - **Incident Response**: Correlated telemetry timeline, evidence chain reconstruction, and containment checklists.
  - **Threat Hunting**: Graph-based indicator pivoting and infrastructure correlation.
- **Interoperability & Standards**: STIX 2.1 JSON bundle generation, CSV SIEM blocklist exports, and automated PDF executive briefings.
- **Enterprise Security**: OWASP security headers, `slowapi` IP rate limiting, non-root container sandboxing, and automated dependency audit gating.

---

## ⚡ Quickstart Setup

### 1. Start Stateful Infrastructure
```bash
docker-compose up -d