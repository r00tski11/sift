# iOS Security Platform

A full-stack security analysis platform for iOS applications. Upload an IPA or xcarchive, get automated vulnerability findings with OWASP Mobile Top 10 mapping, severity scoring, and actionable remediation guidance.

## Features

- **Static Analysis** — Binary protections, ATS configuration, entitlements, privacy manifests
- **Secret Detection** — Hardcoded API keys, tokens, and credentials with entropy analysis
- **Crypto Auditing** — Weak algorithms (MD5, SHA-1, DES, ECB mode), hardcoded encryption keys
- **Source Code Scanning** — Semgrep-powered Swift/Objective-C analysis with custom rules
- **Custom Rule Engine** — YAML-based pattern matching for project-specific checks
- **Import Support** — Ingest MobSF reports and HAR files for consolidated analysis
- **Report Formats** — JSON, HTML, PDF, SARIF export for CI/CD integration
- **Real-time Progress** — WebSocket-based scan status updates
- **Scan Comparison** — Diff findings between two scans to track security posture over time
- **Dashboard** — Trends, OWASP distribution, top vulnerabilities at a glance

## Architecture

The platform consists of four main components:

- **Backend (FastAPI)** — REST API with JWT authentication, project/scan/finding CRUD, report generation, and WebSocket support. Uses Alembic for database migrations.
- **Analyzer (Python library)** — Modular detection pipeline. Each detector (binary, ATS, secrets, crypto, entitlements, privacy, URLs, deprecated APIs) implements a common interface and produces structured findings. Includes a custom YAML rule engine and Semgrep integration.
- **Frontend (React + TypeScript)** — SPA with dashboard, project management, scan results with filtering/pagination, scan comparison, and settings. Built with Vite, styled with Tailwind CSS.
- **Worker (Celery)** — Async scan execution. Receives jobs from Redis, runs the analyzer pipeline, stores results in PostgreSQL, and pushes progress via Redis pub/sub.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI, Pydantic, SQLAlchemy 2.0, Alembic |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Zustand, Recharts |
| Database | PostgreSQL 16 |
| Queue | Redis 7, Celery |
| Analysis | Custom detectors, Semgrep, macholib |
| Reports | Jinja2 (HTML), fpdf2 (PDF), SARIF |
| Infrastructure | Docker Compose, Nginx |

## Quick Start

```bash
# Clone and start all services
git clone <repo-url> && cd ios-security-platform
cp .env.example .env
docker compose up --build

# Services:
#   Frontend  → http://localhost
#   API       → http://localhost:8000
#   API docs  → http://localhost:8000/docs
```

Default database credentials are in `docker-compose.yml`. For production, set `SECRET_KEY` in your environment.

## Local Development

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e ../analyzer

# Start PostgreSQL and Redis (via Docker or locally)
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/ios_security
export REDIS_URL=redis://localhost:6379/0

alembic upgrade head
uvicorn app.main:app --reload
```

### Analyzer

```bash
cd analyzer
pip install -e ".[dev]"
pytest
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/register` | Register a new user |
| POST | `/api/v1/auth/login` | Authenticate and get tokens |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| GET | `/api/v1/auth/me` | Current user info |
| GET | `/api/v1/projects/` | List projects |
| POST | `/api/v1/projects/` | Create project |
| GET | `/api/v1/projects/{id}` | Get project |
| PUT | `/api/v1/projects/{id}` | Update project |
| DELETE | `/api/v1/projects/{id}` | Delete project |
| GET | `/api/v1/projects/{id}/scans` | List scans for project |
| POST | `/api/v1/scans/` | Upload file and start scan |
| GET | `/api/v1/scans/{id}` | Get scan details |
| GET | `/api/v1/scans/{id}/findings` | Get findings (filterable) |
| GET | `/api/v1/scans/{id}/report/{fmt}` | Download report (json/html/pdf/sarif) |
| GET | `/api/v1/scans/compare/` | Compare two scans |
| GET | `/api/v1/findings/{id}` | Get single finding |
| PATCH | `/api/v1/findings/{id}` | Update finding status |
| PATCH | `/api/v1/findings/bulk/update` | Bulk update findings |
| GET | `/api/v1/dashboard/overview` | Aggregate stats |
| GET | `/api/v1/dashboard/trends` | Scan trends over time |
| GET | `/api/v1/dashboard/top-vulnerabilities` | Most common findings |
| GET | `/api/v1/dashboard/owasp-distribution` | Findings by OWASP category |
| POST | `/api/v1/imports/mobsf` | Import MobSF report |
| POST | `/api/v1/imports/har` | Import HAR file |
| WS | `/api/v1/ws/scans/{id}` | Real-time scan progress |

Full API documentation: [docs/API.md](docs/API.md)

## Project Structure

```
ios-security-platform/
├── analyzer/                 # Security analysis library
│   ├── src/ipa_analyzer/
│   │   ├── core/             # Scanner, extractor, context
│   │   ├── detectors/        # 10 detector modules
│   │   ├── reporters/        # JSON, HTML, PDF, SARIF, console
│   │   ├── importers/        # MobSF, HAR importers
│   │   └── utils/            # Entropy, scoring, string extraction
│   ├── rules/                # YAML detection rules
│   ├── semgrep_rules/        # Semgrep rule definitions
│   └── tests/                # 229 analyzer tests
├── backend/
│   ├── app/
│   │   ├── api/              # Route handlers
│   │   ├── models/           # SQLAlchemy models
│   │   ├── schemas/          # Pydantic schemas
│   │   └── tasks/            # Celery task definitions
│   ├── alembic/              # Database migrations
│   └── tests/                # 32 backend tests
├── frontend/
│   └── src/
│       ├── components/       # Reusable UI components
│       ├── pages/            # Route pages
│       ├── api/              # API client
│       ├── stores/           # Zustand state
│       └── hooks/            # Custom React hooks
├── docker-compose.yml
├── Makefile
└── docs/
    ├── API.md
    └── ARCHITECTURE.md
```

## Testing

```bash
# Run all tests
make test

# Individual suites
make test-analyzer    # 229 tests
make test-backend     # 32 tests

# Lint
make lint
```

## License

MIT
