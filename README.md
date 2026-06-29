# AegisFA: AI-Powered Forensic Assistant for Security Operations Centers

> **AegisFA** (Aegis Forensic Assistant) automates the full SOC incident analysis pipeline — from raw log ingestion through ML classification, rule-based correlation, MITRE ATT&CK mapping, and LLM-generated investigation guides — delivering analyst-ready intelligence in seconds instead of minutes.

<p align="center">
  <img src="frontend/src/assets/A.png" alt="Project Logo" width="200" height="200">
</p>

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Environment Variables](#environment-variables)
  - [Docker Setup (Recommended)](#docker-setup-recommended)
  - [Manual Setup (Development)](#manual-setup-development)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Machine Learning](#machine-learning)
- [Security Model](#security-model)
- [Project Structure](#project-structure)
- [Known Limitations](#known-limitations)
- [Future Work](#future-work)
- [License](#license)

---

## Overview

Modern SOC teams face alert fatigue by dealing with hundreds of incidents per shift, each requiring manual log correlation, threat framework mapping, and triage. AegisFA compresses what traditionally requires multiple tools and manual steps into a single automated pipeline:

1. Analyst uploads a log file (CSV, JSON, NDJSON, or plain text — up to 2 GB via chunked upload).
2. The **ingestion pipeline** auto-detects the source type (Windows Event, Firewall, Auth, Syslog, Custom) and normalizes entries to a consistent schema.
3. A **RandomForest classifier** trained on CICIDS2017/2019 classifies events across 10 categories and 25+ attack types with calibrated confidence scores.
4. A **rule-based correlation engine** evaluates configurable detection rules across the normalized events.
5. A **RAG pipeline** (pgvector + HNSW) semantically matches threats to MITRE ATT&CK techniques using 1536-dimensional OpenAI embeddings.
6. An **LLM layer** (GPT-4o-mini) generates threat insights, incident narratives, investigation guides, and phased remediation plans.
7. A **blended confidence score** aggregates all four signals (RF 30%, correlation 30%, LLM 20%, retrieval 20%) and stores the full breakdown in `verdict_sources` for auditability.

---

## Key Features

| Feature | Detail |
|---|---|
| **Multi-format log ingestion** | CSV, JSON, NDJSON, plain text; up to 110 MB direct or 2 GB chunked (4 MB parts, session-managed) |
| **Log source auto-detection** | Windows Event, Firewall, Authentication, Syslog, Custom |
| **ML classification** | RandomForest (150 estimators, max depth 25, TF-IDF bigram features, sigmoid calibration); trained on CICIDS2017/2019; 10 categories, 25+ attack types; weighted precision 0.915 |
| **Rule-based correlation** | 5 rule types (threshold, sequence, distinct_value, existence, time_rate); 9 filter operators (eq, neq, in, contains, regex, exists, gt, gte, lt); configurable per organization |
| **MITRE ATT&CK mapping** | RAG pipeline with 1536-dimensional pgvector embeddings, HNSW index, cosine similarity (threshold 0.45); top-5 technique matches with confidence scores |
| **LLM intelligence** | GPT-4o-mini generates threat insights, incident narratives, investigation guides, and 4-phase remediation plans (0-1 hr, 1-24 hr, 1-7 days, 1-3 months) |
| **Blended confidence scoring** | RF (30%) + correlation (30%) + LLM (20%) + retrieval (20%) + consistency bonus; full breakdown stored in `verdict_sources` |
| **Background job processing** | Long-running analyses tracked via `analysis_jobs` table; frontend polls `GET /analysis-jobs/{job_id}` |
| **Collaborative workspace** | Incident CRUD, task assignment, event-to-incident linking, AI-generated narratives |
| **Multi-tenant SaaS** | PostgreSQL Row-Level Security (RLS) on 17 tables; org-scoped isolation; roles: admin, analyst, viewer |
| **GitHub OAuth** | Supabase Auth; JWT Bearer token on all non-public endpoints; auto-provisioned viewer on first login |
| **Containerized deployment** | Docker Compose; single `docker-compose up --build` |

---

## Architecture

```
+-------------------------------------------------------------+
|                  Frontend (React 18 + Vite)                 |
|   Dashboard . Admin Panel . Collaborative Workspace         |
|   GitHub OAuth . Role-based rendering . Chunked upload      |
+----------------------------+--------------------------------+
                             |  HTTP REST (Bearer token)
+----------------------------v--------------------------------+
|                  Backend (Flask 3.1 + Gunicorn)             |
|                                                             |
|   before_request: Auth + Org Scope + Role Enforcement       |
|                                                             |
|  +---------------+  +---------------+  +----------------+  |
|  | file_parser   |  | normalization |  | correlation_   |  |
|  | (4 formats,   |  | (5 source     |  | engine         |  |
|  |  encoding     |  |  types, opt.  |  | (5 rule types, |  |
|  |  auto-detect) |  |  LLM augment) |  |  9 operators)  |  |
|  +-------+-------+  +-------+-------+  +-------+--------+  |
|          +------------------+-----------------+             |
|                      Analysis Pipeline                      |
|  +---------------+  +---------------+  +----------------+  |
|  | log_classifier|  | rag_service   |  |insights_       |  |
|  | (RandomForest |  | (pgvector +   |  |generator       |  |
|  |  + sigmoid    |  |  HNSW; MITRE  |  |(GPT-4o-mini:   |  |
|  |  calibration) |  |  ATT&CK RAG)  |  | insights,      |  |
|  |               |  |               |  | guides, plans) |  |
|  +---------------+  +---------------+  +----------------+  |
|               Blended Confidence Scorer                     |
+----------------------------+--------------------------------+
                             |
+----------------------------v--------------------------------+
|      Supabase (PostgreSQL + pgvector + Auth + Storage)      |
|   22 tables . 17 RLS policies . HNSW index . S3 storage     |
|   organizations . users . log_files . raw_logs              |
|   analysis_results . mitre_techniques . correlation_rules   |
|   incidents . tasks . analysis_jobs . model_versions        |
+-------------------------------------------------------------+
```

**Communication:**
- Frontend → Backend: HTTP REST via Vite dev proxy (`/api/*`); in production, `VITE_API_BASE_URL`
- Frontend → Supabase: Supabase JS client (anon key, fully RLS-scoped)
- Backend → Supabase: Python SDK (service role key, bypasses RLS for authorized writes)
- Backend → OpenAI: HTTPS REST for LLM completions and text embeddings

---

## Tech Stack

### Backend
- **Python 3.11 / Flask 3.1** — Blueprint-based REST API, Gunicorn WSGI (2 workers, 300s timeout)
- **scikit-learn** — RandomForest with `CalibratedClassifierCV` sigmoid calibration
- **OpenAI SDK** — GPT-4o-mini for analysis and `text-embedding-3-small` for MITRE embeddings
- **pgvector** — 1536-dimensional vector embeddings, HNSW index in PostgreSQL
- **structlog** — Structured JSON logging with `X-Request-ID` propagation
- **Docker** — Multi-stage builds, Docker Compose orchestration

### Frontend
- **React 18 / Vite 5** — HMR dev server, production build, API proxy
- **Supabase JS client** — Auth session management, anon-key DB reads
- **SSE + polling** — Real-time upload progress and background job tracking

### Database & Infrastructure
- **Supabase (PostgreSQL)** — Managed DB, GitHub OAuth, Storage, RLS, pgvector
- **GitHub Actions** — CI/CD
- **VS Code devcontainer** — Reproducible development environment

---

## Getting Started

### Prerequisites

| Requirement | Version |
|---|---|
| Docker Engine | 20.10+ |
| Docker Compose | v2 |
| Supabase project | Free tier or higher |
| OpenAI API key | Any tier (GPT-4o-mini) |
| GitHub OAuth app | For authentication |

For manual setup only: Python 3.11+, Node.js 20.x

### Environment Variables

**`backend/.env`**
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
OPENAI_API_KEY=sk-...
INSIGHTS_LLM_PROVIDER=openai
MAX_UPLOAD_PART_BYTES=16777216
MAX_UPLOAD_SESSIONS=100
SUPABASE_RETRY_ATTEMPTS=4
BACKGROUND_PARSE_MAX_ROWS=200000
RAW_LOG_INSERT_BATCH_SIZE=200
USE_AI_NORMALIZATION=false
LOG_LEVEL=INFO
```

**`frontend/.env`**
```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key
VITE_API_BASE_URL=http://localhost:5001
```

### Docker Setup (Recommended)

```bash
# 1. Clone
git clone https://github.com/jbvillegas/AegisFA.git
cd AegisFA

# 2. Create backend/.env and frontend/.env (see above)

# 3. Build and start all services
docker-compose up --build

# Frontend:  http://localhost:3000
# Backend:   http://localhost:5001
# Health:    http://localhost:5001/

# Stop
docker-compose down
```

### Manual Setup (Development)

**Backend**
```bash
cd backend
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
flask run --port 5005
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
# http://localhost:5173
```

**Database migrations** — apply in order to your Supabase project:
```
database/000_db_implementation.sql   # Core tables
database/001_pgvector_mitre.sql      # pgvector + MITRE embeddings + HNSW index
database/002_correlation_engine.sql  # Correlation rules + detections
database/003_rls_implementation.sql  # RLS policies on 17 tables
database/004_log_analysis_results.sql
database/005_analysis_job.sql        # Background job tracking
database/006_correlation_errors.sql
database/007_rf_training.sql         # Model versioning + training runs
```

---

## Usage

### First Login
1. Navigate to `http://localhost:3000`
2. Click **"Sign in with GitHub"**
3. New users are auto-provisioned with role `viewer`
4. To grant admin access, update the `users` table in Supabase:
   ```sql
   UPDATE users SET role = 'admin' WHERE email = 'user@example.com';
   ```

### Analyzing a Log File
1. From the **Dashboard**, click **"Upload File"**
2. Select a file (CSV, JSON, NDJSON, or plain text)
3. Select the log source type or leave on auto-detect (Windows, Firewall, Auth, Syslog, Custom)
4. Files under 110 MB → direct upload; larger files → automatic 4 MB chunked session upload with progress tracking
5. After analysis, the dashboard shows:
   - Threat summary (level, count, blended confidence score)
   - ML classification breakdown across 10 categories
   - MITRE ATT&CK technique matches with similarity scores
   - AI-generated threat insights, investigation guide, and phased remediation plan
   - Event timeline with severity filtering

### Admin Panel (admin role only)
- **Train RandomForest** — triggers `POST /rf/train`; model activates only if weighted precision ≥ 0.80
- **Manage correlation rules** — create/edit threshold, sequence, existence, distinct_value, or time_rate rules
- **User and org management** — view roles, manage organization members

### Collaborative Workspace
- Create incidents, assign tasks, link events to incidents
- View AI-generated incident narratives from the `summaries` table

### Common Workflows

**Windows Event Log:**
```powershell
# Export from PowerShell
Get-WinEvent -LogName Security | Export-Csv -Path events.csv
# Upload to AegisFA — auto-detected as "Windows"; maps EventID, User, IpAddress
```

**View Remediation Plan:**  
After analysis, click **"View Remediation"** next to any high-severity threat for phased output:
- Immediate (0–1 hr): block IP, disable account
- Short-term (1–24 hr): update firewall rules, rotate credentials
- Medium-term (1–7 days): patch systems, review logs
- Long-term (1–3 months): implement MFA, security training

---

## API Reference

All endpoints except `GET /` require `Authorization: Bearer <token>`.

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `POST` | `/upload` | analyst+ | Upload log file (≤110 MB); returns analysis result |
| `POST` | `/upload-sessions/init` | analyst+ | Initialize chunked upload session |
| `POST` | `/upload-sessions/upload-part` | analyst+ | Upload a single chunk part |
| `POST` | `/upload-sessions/complete` | analyst+ | Assemble parts, create background job; returns `job_id` |
| `GET` | `/analysis-jobs/{job_id}` | analyst+ | Poll background job status and progress |
| `GET` | `/analysis/{file_id}` | analyst+ | Full analysis result for a file |
| `GET` | `/incidents` | analyst+ | List incidents (paginated) |
| `POST` | `/incidents` | analyst+ | Create incident |
| `GET` | `/incidents/{id}` | analyst+ | Incident with linked events |
| `POST` | `/tasks` | analyst+ | Create and assign task |
| `GET` | `/timeline/file/{file_id}` | analyst+ | File-scoped event timeline |
| `GET` | `/timeline/org` | analyst+ | Org-scoped event timeline |
| `GET` | `/timeline/file/{file_id}/graph` | analyst+ | Node-edge graph (≤120 nodes) |
| `POST` | `/feedback` | analyst+ | Submit AI output rating and suggestion |
| `GET` | `/feedback` | analyst+ | Retrieve feedback filtered by org |
| `POST` | `/rf/train` | admin | Trigger RandomForest training run |
| `POST` | `/rf/load-latest` | admin | Activate latest qualified model |
| `GET` | `/` | public | Health check |

Full interactive docs available at `/docs` (Swagger UI) when running locally.

**Structured error format:**
```json
{ "error": { "code": "...", "message": "...", "retriable": true, "request_id": "..." } }
```
Server-side errors (DATABASE_ERROR, STORAGE_ERROR, ANALYSIS_ERROR, RATE_LIMIT) set `retriable: true`. Client-side errors do not.

---

## Machine Learning

The RandomForest classifier is trained on the [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) and [CICIDS2019](https://www.unb.ca/cic/datasets/ids-2019.html) network traffic datasets.

| Parameter | Value |
|---|---|
| Algorithm | RandomForest + CalibratedClassifierCV (sigmoid) |
| Estimators | 150 |
| Max depth | 25 |
| Features | TF-IDF (800 max features, bigram) over 7 combined log fields |
| Dataset split | 70% train / 15% validation / 15% test (stratified, seed 42) |
| Categories | 10 security categories, 25+ attack types |
| Activation threshold | Weighted precision ≥ 0.80 |
| Max training rows | 120,000 |

**Evaluation on held-out test set (15%):**

| Metric | Score |
|---|---|
| Accuracy | 0.918 |
| Precision (weighted) | 0.915 |
| Recall (weighted) | 0.918 |
| F1 (weighted) | 0.915 |
| Precision (macro) | 0.874 |
| F1 (macro) | 0.866 |

Models below threshold are archived, not deployed. Artifacts stored as versioned pickles in Supabase Storage (`ml-models` bucket); metadata tracked in `model_versions` and `training_runs` tables.

**Trigger training (admin only):**
```bash
curl -X POST http://localhost:5001/rf/train \
  -H "Authorization: Bearer <admin_token>"
```

---

## Security Model

Five enforcement layers — failure of any one does not expose cross-tenant data:

| Layer | Mechanism |
|---|---|
| **1. Authentication** | Bearer token validated via `supabase_client.auth.get_user(token)` on every request; `GET /` exempt |
| **2. RBAC** | `_require_roles()` decorator; role read from `users` table, never trusted from client payload |
| **3. Org scope** | `_enforce_org_scope()` and `_enforce_file_scope()` check resource ownership at API layer before any DB query |
| **4. Row-Level Security** | RLS policies on 17 PostgreSQL tables; anon key (frontend) fully scoped; service role (backend) bypasses RLS for authorized writes only |
| **5. Operational security** | Structured `_error_response()` — no stack traces in production; `X-Request-ID` in all logs; `LOG_LEVEL` controls verbosity |

**Production hardening:**
- Rotate `SUPABASE_SERVICE_ROLE_KEY` before go-live
- Add Nginx + Let's Encrypt reverse proxy for HTTPS
- Run `docker-compose pull` regularly to update base images
- Conduct an independent penetration test before handling sensitive production logs

---

## Project Structure

```
AegisFA/
├── .devcontainer/                    # VS Code devcontainer config
├── .github/                          # GitHub Actions CI/CD
├── backend/                          # Flask application
│   ├── __init__.py                   # App factory; MAX_CONTENT_LENGTH = 120 MB
│   ├── routes.py                     # Blueprint + before_request middleware
│   ├── file_parser.py                # Multi-format parser (CSV, JSON, NDJSON, plain text)
│   ├── normalization.py              # Source-specific field normalization
│   ├── correlation_engine.py         # Rule-based event correlation
│   ├── log_classifier.py             # RandomForest + training pipeline
│   ├── rag_service.py                # Threat analysis + MITRE ATT&CK RAG
│   ├── insights_generator.py         # LLM insight/guide/remediation generation
│   ├── timeline_service.py           # Chronological event aggregation
│   ├── storage.py                    # Supabase Storage wrapper with retry
│   ├── logging_config.py             # structlog JSON config
│   └── requirements.txt
├── database/                         # PostgreSQL migrations (000-007)
│   ├── 000_db_implementation.sql     # Core tables
│   ├── 001_pgvector_mitre.sql        # pgvector + HNSW index + MITRE embeddings
│   ├── 002_correlation_engine.sql    # Correlation rules + detections
│   ├── 003_rls_implementation.sql    # RLS on 17 tables
│   ├── 004_log_analysis_results.sql  # log_files + analysis_results
│   ├── 005_analysis_job.sql          # Background job tracking
│   ├── 006_correlation_errors.sql    # Correlation audit table
│   └── 007_rf_training.sql           # model_versions + training_runs
├── frontend/                         # React 18 + Vite 5
│   ├── src/
│   │   ├── App.jsx                   # Routes + ProtectedRoute
│   │   ├── client.js                 # authenticatedFetch (token injection + 401 handling)
│   │   └── pages/
│   │       ├── dashboard.jsx         # Analyst dashboard + dual-mode upload
│   │       ├── admin-dashboard.jsx   # Model training + rule management
│   │       ├── collaborative-workspace.jsx
│   │       ├── homepage.jsx
│   │       ├── about.jsx
│   │       ├── support.jsx
│   │       ├── contact.jsx
│   │       ├── login.jsx
│   │       ├── privacy.jsx
│   │       └── terms.jsx
│   └── package.json
└── docker-compose.yml
```

---

## Troubleshooting

| Problem | Likely Cause | Solution |
|---|---|---|
| `401 Unauthorized` | Expired GitHub token | Log out and log back in |
| `403 Forbidden` | Insufficient role | Ask an admin to set your role to `analyst` or `admin` |
| Upload fails with `413` | File >110 MB without chunked upload | Chunked upload is automatic for large files; check browser console |
| `409 Conflict` | File already exists in storage | Rename the file or delete the previous version |
| Analysis hangs | OpenAI rate limit or network issue | Check `OPENAI_API_KEY` and connection; jobs retry automatically |
| ML model not loading | No activated model | Admin Panel → Train Model; wait for completion |
| High container memory | Large file + LLM context | Docker Settings → Resources → increase memory limit |

**Log access:**
- Backend: `docker logs aegis-backend-1` or `logs/` directory (manual)
- Frontend: browser developer console (F12)
- Database: Supabase Dashboard → Logs
- All error responses include `request_id` — include it when reporting issues

---

## Known Limitations

- No automated regression test suite (solo-developer capstone, no dedicated QA)
- LLM response variability — GPT-4o-mini occasionally returns malformed JSON despite temperature 0.2; fence-stripping fallback handles most cases
- ML training on CICIDS2017/2019 (simulated traffic) — real-world log accuracy may differ
- Supabase and OpenAI free tiers throttle under high concurrency; paid plans or self-hosted alternatives needed for production scale
- No independent security audit has been performed
- File-based batch analysis only — no real-time streaming ingestion
- No automated remediation execution (SOAR) — platform generates plans but does not act on them
- Container memory usage ~5.6–6.5 GB under load; optimizer opportunities exist in TF-IDF vectorization

---

## Future Work

- **Real-time streaming** — Syslog, WebSockets, or Kafka for continuous monitoring
- **SOAR integration** — automated containment (Shuffle, Tines, custom playbooks)
- **Horizontal scaling** — Celery + Redis for background jobs, load-balanced backend replicas
- **Third-party integrations** — Jira, ServiceNow, PagerDuty, Splunk, Microsoft Sentinel
- **Transformer-based classifier** — fine-tuned BERT for improved accuracy on novel attack types
- **Active learning** — analyst corrections feed back into training data
- **Export** — PDF/JSON/CSV analysis reports and forensic documentation
- **Compliance reporting** — PCI DSS, HIPAA, SOC 2 templates
- **Mobile/lightweight client** — read-only mobile view for on-call analysts

---

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

---

<p align="center">
  <strong>AegisFA</strong> — AI-Powered Forensic Assistant for Security Operations Centers<br>
  Built by <a href="https://github.com/jbvillegas">Joaquin Baltasar Villegas</a><br>
  Lander University · CIS 499 Capstone · Spring 2026<br>
  Faculty Advisor: Bahar Mahmud, Ph.D.
</p>
