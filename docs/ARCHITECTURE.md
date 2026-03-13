# Architecture

## System Overview

```
┌─────────┐    ┌──────────┐    ┌────────────┐    ┌──────────┐
│ Frontend │───▶│ API      │───▶│ Worker     │───▶│ Analyzer │
│ (React)  │    │ (FastAPI)│    │ (Celery)   │    │ (Python) │
└─────────┘    └──────────┘    └────────────┘    └──────────┘
                    │                │
               ┌────┴────┐    ┌─────┴─────┐
               │PostgreSQL│    │   Redis    │
               └─────────┘    └───────────┘
```

## Components

### Frontend (React + TypeScript)

Single-page application built with Vite. Uses Zustand for state management, React Router for navigation, and Axios for API communication. Tailwind CSS for styling. Recharts for dashboard visualizations.

Key pages: Dashboard, Projects, Project Detail, New Scan, Scan Results, Comparison, Settings.

### API (FastAPI)

REST API with JWT authentication (access + refresh tokens). Six router modules handle auth, projects, scans, findings, dashboard analytics, and third-party imports. SQLAlchemy 2.0 async-style models with Alembic migrations. Pydantic schemas for request/response validation.

The API also serves a WebSocket endpoint at `/api/v1/ws/scans/{scan_id}` that subscribes to Redis pub/sub for real-time scan progress.

### Worker (Celery)

Celery worker process consuming jobs from Redis. When a scan is submitted, the API creates a database record, saves the uploaded file, and enqueues a Celery task. The worker installs the analyzer package, runs the detection pipeline, stores findings in PostgreSQL, and publishes progress events to Redis.

### Analyzer (ipa-analyzer)

Installable Python package (`pip install -e analyzer`). Core of the security analysis logic.

## Scan Flow (End-to-End)

1. **Upload** — User uploads an IPA/xcarchive via the frontend. The API saves the file to disk and creates a `Scan` record with status `pending`.

2. **Enqueue** — The API dispatches a Celery task with the scan ID. The scan status moves to `queued`.

3. **Extract** — The worker's task handler loads the scan record, creates an `AnalysisContext`, and extracts the IPA into a temporary directory. Status: `running`.

4. **Detect** — The `Scanner` iterates through all registered detectors. Each detector receives the `AnalysisContext` and returns a list of `Finding` objects. Progress updates are published to Redis pub/sub on each detector completion.

5. **Store** — Findings are bulk-inserted into the `findings` table. Severity counts and risk score are computed and saved on the `Scan` record. Status: `completed`.

6. **Notify** — A final Redis pub/sub message signals completion. The frontend's WebSocket connection receives this and refreshes the UI.

7. **Report** — Users can request reports in JSON, HTML, PDF, or SARIF format via the `/scans/{id}/report/{fmt}` endpoint, which runs the appropriate reporter on the stored findings.

## Detector Pipeline

All detectors implement `BaseDetector` with a single `analyze(context) -> list[Finding]` method. The `Scanner` class runs them sequentially and collects results.

**Built-in detectors:**

| Detector | What it checks |
|----------|---------------|
| BinaryProtectionsDetector | Code signing, PIE, debug symbols, stripping |
| ATSDetector | App Transport Security exceptions, cleartext HTTP |
| SecretsDetector | Hardcoded API keys, tokens, credentials (entropy-based) |
| EntitlementsDetector | Sensitive entitlements, debug provisioning |
| CryptoDetector | Weak algorithms (MD5, SHA-1, DES, ECB), hardcoded keys |
| PrivacyDetector | Privacy manifest compliance, tracking flags |
| URLEndpointDetector | Hardcoded URLs, localhost/dev endpoints |
| DeprecatedAPIDetector | Deprecated iOS API usage (UIWebView, old crypto) |
| CustomRuleDetector | YAML-defined pattern matching rules |
| SemgrepDetector | Semgrep-based source code analysis |

**Custom rules** are loaded from `analyzer/rules/*.yaml`. Each rule defines a regex pattern, severity, OWASP mapping, CWE ID, and remediation guidance.

**Semgrep rules** in `analyzer/semgrep_rules/` run against source code (when available) for deeper Swift/Objective-C analysis.

## Finding Model

Every finding contains:
- `detector` — Which detector produced it
- `severity` — CRITICAL, HIGH, MEDIUM, LOW, INFO
- `title` / `description` — Human-readable explanation
- `location` — File path within the app bundle
- `evidence` — Concrete proof (redacted for secrets)
- `owasp` — OWASP Mobile Top 10 category
- `cwe_id` — CWE identifier
- `remediation` — Actionable fix guidance

## Database Schema

Four tables managed by SQLAlchemy + Alembic:

- **users** — id, email, username, password_hash, timestamps
- **projects** — id, name, bundle_id, description, created_by (FK → users), timestamps
- **scans** — id, project_id (FK → projects), scan_type, status, input_filename, severity counts, risk_score, risk_grade, celery_task_id, timestamps
- **findings** — id, scan_id (FK → scans), uuid, detector, severity, title, description, location, evidence, owasp, cwe_id, remediation, status, is_false_positive, notes, timestamps

Cascade deletes: user → projects → scans → findings.

## Import Pipeline

Two importers convert external formats into the standard finding model:

- **MobSF** — Parses MobSF JSON reports, maps severity levels, and creates findings with appropriate OWASP/CWE mappings.
- **HAR** — Parses HTTP Archive files, extracts security-relevant observations (cleartext traffic, sensitive headers, authentication tokens in URLs).

Imported scans use `scan_type: "import"` and skip the detector pipeline.
