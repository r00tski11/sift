# API Reference

Base URL: `/api/v1`

All endpoints except auth require a Bearer token in the `Authorization` header.

---

## Auth

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | No | Register a new user |
| POST | `/auth/login` | No | Authenticate and receive access/refresh tokens |
| POST | `/auth/refresh` | No | Exchange refresh token for new token pair |
| GET | `/auth/me` | Yes | Get current user profile |

### POST /auth/register

**Request:**
```json
{ "email": "user@example.com", "username": "user", "password": "secret" }
```

**Response (201):**
```json
{ "access_token": "...", "refresh_token": "...", "user": { "id": 1, "email": "...", "username": "..." } }
```

### POST /auth/login

**Request:**
```json
{ "email": "user@example.com", "password": "secret" }
```

**Response (200):** Same shape as register.

### POST /auth/refresh

**Request:**
```json
{ "refresh_token": "..." }
```

**Response (200):**
```json
{ "access_token": "...", "refresh_token": "..." }
```

### GET /auth/me

**Response (200):**
```json
{ "id": 1, "email": "user@example.com", "username": "user", "created_at": "..." }
```

---

## Projects

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/projects/` | Yes | List all projects for current user |
| POST | `/projects/` | Yes | Create a new project |
| GET | `/projects/{project_id}` | Yes | Get project details |
| PUT | `/projects/{project_id}` | Yes | Update a project |
| DELETE | `/projects/{project_id}` | Yes | Delete project and all related data |
| GET | `/projects/{project_id}/scans` | Yes | List scans for a project |

### POST /projects/

**Request:**
```json
{ "name": "MyApp", "bundle_id": "com.example.myapp", "description": "..." }
```

**Response (201):**
```json
{ "id": 1, "name": "MyApp", "bundle_id": "com.example.myapp", "description": "...", "created_at": "..." }
```

---

## Scans

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/scans/` | Yes | Upload file and start scan |
| GET | `/scans/{scan_id}` | Yes | Get scan details and summary counts |
| GET | `/scans/{scan_id}/findings` | Yes | Get findings with filtering and pagination |
| GET | `/scans/{scan_id}/report/{fmt}` | Yes | Download report (json, html, pdf, sarif) |
| GET | `/scans/compare/` | Yes | Compare two scans side by side |

### POST /scans/

**Request:** `multipart/form-data`
- `project_id` (int) — Target project
- `scan_type` (string) — `static`, `source`, `dynamic`, or `import`
- `file` — IPA, xcarchive, or source archive

**Response (201):**
```json
{ "id": 1, "status": "pending", "celery_task_id": "..." }
```

### GET /scans/{scan_id}/findings

**Query parameters:**
- `severity` — Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `detector` — Filter by detector name
- `status` — Filter by status (open, resolved, false_positive)
- `page` — Page number (default: 1)
- `page_size` — Results per page (default: 50)

### GET /scans/compare/?a={id}&b={id}

**Response (200):**
```json
{
  "scan_a": { ... },
  "scan_b": { ... },
  "new_findings": [ ... ],
  "resolved_findings": [ ... ],
  "common_findings": [ ... ]
}
```

---

## Findings

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/findings/{finding_id}` | Yes | Get a single finding with full details |
| PATCH | `/findings/{finding_id}` | Yes | Update status, notes, or false-positive flag |
| PATCH | `/findings/bulk/update` | Yes | Bulk update multiple findings |

### PATCH /findings/{finding_id}

**Request:**
```json
{ "status": "resolved", "is_false_positive": false, "notes": "Fixed in v2.1" }
```

### PATCH /findings/bulk/update

**Request:**
```json
{ "finding_ids": [1, 2, 3], "status": "resolved" }
```

---

## Dashboard

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/dashboard/overview` | Yes | Aggregate stats across all user projects |
| GET | `/dashboard/trends` | Yes | Scan count and avg risk score per day |
| GET | `/dashboard/top-vulnerabilities` | Yes | Most common findings |
| GET | `/dashboard/owasp-distribution` | Yes | Finding counts by OWASP category |

### GET /dashboard/trends?days=30

**Response (200):**
```json
[{ "date": "2026-03-01", "scan_count": 3, "avg_risk_score": 62 }, ...]
```

---

## Imports

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/imports/mobsf` | Yes | Import a MobSF JSON report |
| POST | `/imports/har` | Yes | Import a HAR (HTTP Archive) file |

Both accept `multipart/form-data` with `project_id` (int) and `file`.

---

## WebSocket

| Path | Description |
|------|-------------|
| `/ws/scans/{scan_id}` | Real-time scan progress updates |

Connect via WebSocket. Messages are JSON:
```json
{ "status": "running", "progress": 45, "message": "Running crypto detector..." }
```

---

## Health

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Returns `{"status": "ok"}` |
