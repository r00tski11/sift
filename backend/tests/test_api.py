"""Backend API integration tests."""

from __future__ import annotations

import io
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.finding import FindingRecord
from app.models.scan import Scan


# ── Auth ──────────────────────────────────────────────────────────────────


class TestAuth:
    def test_register(self, client: TestClient):
        resp = client.post(
            "/api/v1/auth/register",
            json={"email": "new@example.com", "username": "newuser", "password": "password123"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data

    def test_register_duplicate_email(self, client: TestClient, auth_headers):
        resp = client.post(
            "/api/v1/auth/register",
            json={"email": "test@example.com", "username": "other", "password": "password123"},
        )
        assert resp.status_code == 409

    def test_register_duplicate_username(self, client: TestClient, auth_headers):
        resp = client.post(
            "/api/v1/auth/register",
            json={"email": "other@example.com", "username": "testuser", "password": "password123"},
        )
        assert resp.status_code == 409

    def test_login(self, client: TestClient, auth_headers):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "securepass123"},
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_wrong_password(self, client: TestClient, auth_headers):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "wrongpass"},
        )
        assert resp.status_code == 401

    def test_me(self, client: TestClient, auth_headers):
        resp = client.get("/api/v1/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"

    def test_me_no_auth(self, client: TestClient):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    def test_refresh_token(self, client: TestClient):
        reg = client.post(
            "/api/v1/auth/register",
            json={"email": "ref@example.com", "username": "refuser", "password": "password123"},
        )
        refresh_token = reg.json()["refresh_token"]
        resp = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()


# ── Projects ──────────────────────────────────────────────────────────────


class TestProjects:
    def test_create_project(self, client: TestClient, auth_headers):
        resp = client.post(
            "/api/v1/projects/",
            json={"name": "MyApp", "bundle_id": "com.my.app", "description": "Test project"},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "MyApp"
        assert data["bundle_id"] == "com.my.app"
        assert data["scan_count"] == 0

    def test_list_projects(self, client: TestClient, auth_headers, project_id):
        resp = client.get("/api/v1/projects/", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["id"] == project_id

    def test_get_project(self, client: TestClient, auth_headers, project_id):
        resp = client.get(f"/api/v1/projects/{project_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "TestApp"

    def test_update_project(self, client: TestClient, auth_headers, project_id):
        resp = client.put(
            f"/api/v1/projects/{project_id}",
            json={"name": "UpdatedApp"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "UpdatedApp"

    def test_delete_project(self, client: TestClient, auth_headers, project_id):
        resp = client.delete(f"/api/v1/projects/{project_id}", headers=auth_headers)
        assert resp.status_code == 204

        resp = client.get(f"/api/v1/projects/{project_id}", headers=auth_headers)
        assert resp.status_code == 404

    def test_project_not_found(self, client: TestClient, auth_headers):
        resp = client.get("/api/v1/projects/9999", headers=auth_headers)
        assert resp.status_code == 404

    def test_project_access_denied(self, client: TestClient, auth_headers, project_id):
        # Register second user
        resp = client.post(
            "/api/v1/auth/register",
            json={"email": "other@example.com", "username": "otheruser", "password": "password123"},
        )
        other_token = resp.json()["access_token"]
        other_headers = {"Authorization": f"Bearer {other_token}"}

        resp = client.get(f"/api/v1/projects/{project_id}", headers=other_headers)
        assert resp.status_code == 403

    def test_list_project_scans_empty(self, client: TestClient, auth_headers, project_id):
        resp = client.get(f"/api/v1/projects/{project_id}/scans", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["count"] == 0


# ── Scans ─────────────────────────────────────────────────────────────────


def _create_scan_record(db: Session, project_id: int, status: str = "completed") -> Scan:
    """Insert a scan record directly into the DB."""
    scan = Scan(
        project_id=project_id,
        scan_type="static",
        status=status,
        input_filename="test.ipa",
        input_type="ipa",
        app_name="TestApp",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _create_finding(db: Session, scan_id: int, **overrides) -> FindingRecord:
    """Insert a finding record directly into the DB."""
    defaults = {
        "scan_id": scan_id,
        "uuid": str(uuid.uuid4()),
        "detector": "test_detector",
        "severity": "HIGH",
        "title": "Test Finding",
        "description": "A test finding",
        "location": "TestClass.swift:10",
        "evidence": "some evidence",
        "owasp": "M1",
        "cwe_id": 200,
        "remediation": "Fix it",
        "scan_type": "static",
        "status": "open",
    }
    defaults.update(overrides)
    finding = FindingRecord(**defaults)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


class TestScans:
    def test_get_scan(self, client: TestClient, auth_headers, project_id, db: Session):
        scan = _create_scan_record(db, project_id)
        resp = client.get(f"/api/v1/scans/{scan.id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == scan.id
        assert resp.json()["status"] == "completed"

    def test_get_scan_not_found(self, client: TestClient, auth_headers):
        resp = client.get("/api/v1/scans/9999", headers=auth_headers)
        assert resp.status_code == 404

    def test_get_scan_findings(self, client: TestClient, auth_headers, project_id, db: Session):
        scan = _create_scan_record(db, project_id)
        _create_finding(db, scan.id, title="Finding A", severity="CRITICAL")
        _create_finding(db, scan.id, title="Finding B", severity="LOW")

        resp = client.get(f"/api/v1/scans/{scan.id}/findings", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["findings"]) == 2

    def test_get_scan_findings_filter_severity(
        self, client: TestClient, auth_headers, project_id, db: Session
    ):
        scan = _create_scan_record(db, project_id)
        _create_finding(db, scan.id, title="Crit", severity="CRITICAL")
        _create_finding(db, scan.id, title="Low", severity="LOW")

        resp = client.get(
            f"/api/v1/scans/{scan.id}/findings",
            params={"severity": "CRITICAL"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["findings"][0]["severity"] == "CRITICAL"

    def test_compare_scans(self, client: TestClient, auth_headers, project_id, db: Session):
        scan_a = _create_scan_record(db, project_id)
        scan_b = _create_scan_record(db, project_id)

        # Shared finding
        _create_finding(db, scan_a.id, title="Shared", detector="det1")
        _create_finding(db, scan_b.id, title="Shared", detector="det1")
        # Resolved in B
        _create_finding(db, scan_a.id, title="OldBug", detector="det2")
        # New in B
        _create_finding(db, scan_b.id, title="NewBug", detector="det3")

        resp = client.get(
            "/api/v1/scans/compare/",
            params={"a": scan_a.id, "b": scan_b.id},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["new_count"] == 1
        assert data["summary"]["resolved_count"] == 1
        assert data["summary"]["unchanged_count"] == 1


# ── Report Download ───────────────────────────────────────────────────────


class TestReportDownload:
    def test_download_json_report(self, client: TestClient, auth_headers, project_id, db: Session):
        scan = _create_scan_record(db, project_id)
        _create_finding(db, scan.id)

        resp = client.get(f"/api/v1/scans/{scan.id}/report/json", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"
        data = resp.json()
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_download_html_report(self, client: TestClient, auth_headers, project_id, db: Session):
        scan = _create_scan_record(db, project_id)
        _create_finding(db, scan.id)

        resp = client.get(f"/api/v1/scans/{scan.id}/report/html", headers=auth_headers)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "<html" in resp.text.lower()

    def test_download_sarif_report(self, client: TestClient, auth_headers, project_id, db: Session):
        scan = _create_scan_record(db, project_id)
        _create_finding(db, scan.id)

        resp = client.get(f"/api/v1/scans/{scan.id}/report/sarif", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 1

    def test_download_pdf_report(self, client: TestClient, auth_headers, project_id, db: Session):
        scan = _create_scan_record(db, project_id)
        _create_finding(db, scan.id)

        resp = client.get(f"/api/v1/scans/{scan.id}/report/pdf", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.content[:4] == b"%PDF"

    def test_download_invalid_format(self, client: TestClient, auth_headers, project_id, db: Session):
        scan = _create_scan_record(db, project_id)
        resp = client.get(f"/api/v1/scans/{scan.id}/report/csv", headers=auth_headers)
        assert resp.status_code == 400

    def test_download_report_not_found(self, client: TestClient, auth_headers):
        resp = client.get("/api/v1/scans/9999/report/json", headers=auth_headers)
        assert resp.status_code == 404


# ── Findings ──────────────────────────────────────────────────────────────


class TestFindings:
    def test_update_finding_status(self, client: TestClient, auth_headers, project_id, db: Session):
        scan = _create_scan_record(db, project_id)
        finding = _create_finding(db, scan.id)

        resp = client.patch(
            f"/api/v1/findings/{finding.id}",
            json={"status": "confirmed"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "confirmed"

    def test_mark_false_positive(self, client: TestClient, auth_headers, project_id, db: Session):
        scan = _create_scan_record(db, project_id)
        finding = _create_finding(db, scan.id)

        resp = client.patch(
            f"/api/v1/findings/{finding.id}",
            json={"is_false_positive": True, "notes": "Not a real issue"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["is_false_positive"] is True
        assert resp.json()["notes"] == "Not a real issue"


# ── Dashboard ─────────────────────────────────────────────────────────────


class TestDashboard:
    def test_overview(self, client: TestClient, auth_headers, project_id, db: Session):
        scan = _create_scan_record(db, project_id)
        _create_finding(db, scan.id, severity="CRITICAL")

        resp = client.get("/api/v1/dashboard/overview", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_projects"] == 1
        assert data["total_scans"] == 1

    def test_trends(self, client: TestClient, auth_headers):
        resp = client.get("/api/v1/dashboard/trends", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ── Health ────────────────────────────────────────────────────────────────


class TestHealth:
    def test_health(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"
