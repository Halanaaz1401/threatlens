<div align="center">

# 🛡️ ThreatLens — Enterprise Cyber Threat Intelligence (CTI) Platform

[![CI/CD Pipeline](https://github.com/Halanaaz1401/threatlens/actions/workflows/ci.yml/badge.svg)](https://github.com/Halanaaz1401/threatlens/actions/workflows/ci.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-16.0+-black.svg?logo=next.js&logoColor=white)](https://nextjs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-dc382d.svg?logo=redis&logoColor=white)](https://redis.io)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571.svg?logo=elasticsearch&logoColor=white)](https://www.elastic.co)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

*An enterprise-grade Cyber Threat Intelligence (CTI) and SOC platform designed to aggregate, correlate, enrich, score, and operationalise threat telemetry across modern Security Operations Center (SOC) workflows.*

</div>

---

## 📖 Overview

**ThreatLens** is a full-stack, enterprise-ready Cyber Threat Intelligence platform. It bridges raw threat feeds with real-time operational security workflows, empowering security operations teams (SOC Tier 1/2, Incident Responders, Threat Hunters, and CISOs) to rapidly ingest, contextualize, correlate, and remediate emerging adversary activity.

---

## ⚡ Core Capabilities

- **Automated Multi-Source Feed Ingestion**: Ingests, normalizes, and deduplicates indicators from authoritative feeds including AlienVault OTX, AbuseIPDB, URLhaus, ThreatFox, MalwareBazaar, and Feodo Tracker.
- **Deterministic Incident Correlation**: Evaluates incoming telemetry against shared indicators, normalized infrastructure, MITRE ATT&CK techniques, and temporal windows to cluster related alerts into unified incidents.
- **Multi-Provider Threat Enrichment**: Integrates with external threat intelligence APIs (VirusTotal, AbuseIPDB, AlienVault OTX) with Redis caching, aggregate reputation scoring (0–100), and automated background enrichment.
- **Graph-Based Threat Hunting**: Interactive SVG relationship graph with bounded BFS traversal, multi-hop exploration, and cycle detection across IP, domain, hash, URL, and threat actor nodes.
- **Declarative Detection Engine & Alert Routing**: Configurable rule engine with safe declarative operators, catastrophic backtracking prevention, dry-run testing, deduplication windows, and queue routing (SOC Tier 1/2, IR Lead, Hunting, Engineering).
- **Comprehensive IOC Lifecycle Management**: Tracks status transitions (`NEW` → `ACTIVE` → `UNDER_INVESTIGATION` → `REVOKED` / `WHITELISTED`), automated expiration, confidence adjustments, and custom feed subscriptions.
- **SIEM & SOAR Integrations**: Inbound and outbound webhook pipelines supporting Splunk, Microsoft Sentinel, IBM QRadar, CrowdStrike, and Elastic Security, alongside TAXII 2.1 collection endpoints.
- **Incident & Case Management**: Complete investigation lifecycle with Kanban boards, evidence vault attachments, chronological forensic timelines, and containment task checklists.
- **Role-Based Access Control (RBAC)**: Fine-grained permissions across four enterprise personas: `viewer`, `analyst`, `incident_responder`, and `admin`.
- **Real-Time Telemetry & Auditability**: Authenticated WebSocket event stream (`/api/v1/ws/alerts`) and database-level immutable audit logging for all authentication and security state changes.

---

## 🏗️ Architecture

```
                    ┌────────────────────────────────────────┐
                    │      Next.js 16 Client (App Router)    │
                    │  Tailwind CSS · Lucide · Recharts      │
                    └───────────────────┬────────────────────┘
                                        │ HTTPS / WSS
                                        ▼
                    ┌────────────────────────────────────────┐
                    │          FastAPI Backend (v1)          │
                    │   JWT / Argon2id Auth · RBAC Engine    │
                    │   Correlation · Detection · TAXII 2.1  │
                    └───────┬───────────┬────────────┬───────┘
                            │           │            │
             SQLAlchemy /   │           │ Pub/Sub &  │ Full-Text &
             Alembic        │           │ Cache      │ Faceted Search
                            ▼           ▼            ▼
                   ┌────────────┐ ┌───────────┐ ┌───────────────┐
                   │ PostgreSQL │ │  Redis 7  │ │ Elasticsearch │
                   │     16     │ │    AOF    │ │     8.13      │
                   └────────────┘ └───────────┘ └───────────────┘
```

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS, Lucide React, Recharts |
| **Backend** | Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic, Argon2id, PyJWT, SlowAPI |
| **Relational Database** | PostgreSQL 16 (QueuePool connection pooling, immutable audit triggers) |
| **Cache & Event Bus** | Redis 7 (Append-Only File persistence, token revocation blocklist, Pub/Sub) |
| **Search Engine** | Elasticsearch 8.13.4 (full-text search, faceted aggregations, ATT&CK mapping) |
| **Containers & Deploy** | Docker, Docker Compose, Kubernetes manifests, Vercel / Render cloud deployment |

---

## 🚀 Quickstart with Docker Compose

The fastest way to deploy the entire ThreatLens stack locally is with Docker Compose:

### 1. Clone the Repository
```bash
git clone https://github.com/Halanaaz1401/threatlens.git
cd threatlens
```

### 2. Configure Environment
Create a `.env` file in the project root:
```bash
# Core Security
ENVIRONMENT=production
SECRET_KEY=change_this_to_a_secure_random_64_character_hex_string

# PostgreSQL
POSTGRES_USER=threatlens_admin
POSTGRES_PASSWORD=change_this_postgres_password
POSTGRES_DB=threatlens_db

# Frontend Target
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### 3. Launch Services
```bash
docker compose up -d
```

### 4. Verify Service Health
```bash
docker compose ps
curl -f http://localhost:8000/health
curl -f http://localhost:8000/health/ready
```

Access the frontend application at `http://localhost:3000` and the interactive API documentation at `http://localhost:8000/docs`.

---

## 💻 Local Development Setup

### Prerequisites
- Python 3.12+
- Node.js 20+ and npm
- PostgreSQL 16
- Redis 7
- Elasticsearch 8.x (optional for development; queries fall back to PostgreSQL)

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start API development server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## ⚙️ Environment Variables Reference

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `development` | Deployment environment (`development`, `staging`, `production`) |
| `DATABASE_URL` | `postgresql://...` | Connection URI for PostgreSQL database |
| `REDIS_URL` | `redis://localhost:6379/0` | Connection URI for Redis broker and cache |
| `ELASTICSEARCH_URL` | `http://localhost:9200` | URL for Elasticsearch cluster |
| `ELASTICSEARCH_INDEX` | `threatlens_indicators` | Name of the primary indicator search index |
| `SECRET_KEY` | *(Required)* | High-entropy key for JWT signature and verification |
| `ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Access token lifespan in minutes |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-delimited list of CORS-approved client origins |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Base HTTP endpoint for the backend API |
| `NEXT_PUBLIC_WS_URL` | `ws://localhost:8000/...` | WebSocket endpoint for real-time alert streaming |

---

## 🧪 Testing & Quality Assurance

### Run Backend Test Suite
```bash
cd backend
pytest tests/ -v
```

### Run Frontend Production Build
```bash
cd frontend
npm run build
```

### Run Frontend Typecheck & Lint
```bash
cd frontend
npm run lint
```

---

## 📚 Operational Documentation

- **[Disaster Recovery & Backup Runbook](DISASTER_RECOVERY.md)**: Procedures for PostgreSQL snapshots, automated cron scheduling, point-in-time recovery, cold node disaster recovery, and audit log immutability verification.

---

## 🔒 Security & Vulnerability Reporting

ThreatLens adheres to responsible disclosure guidelines. If you discover a security vulnerability or security-sensitive bug within this platform, please do not disclose it in public issues.

Please submit a confidential report through **[GitHub Security Advisories](https://github.com/Halanaaz1401/threatlens/security/advisories/new)** or contact the security team directly at **security@threatlens.io**.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.