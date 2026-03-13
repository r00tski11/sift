"""Import routes for external scan results (MobSF, HAR)."""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.finding import FindingRecord
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import ScanResponse
from app.services.auth import get_current_user

# Ensure analyzer is importable
_analyzer_src = Path(__file__).resolve().parents[3] / "analyzer" / "src"
if str(_analyzer_src) not in sys.path:
    sys.path.insert(0, str(_analyzer_src))

router = APIRouter(prefix="/imports", tags=["imports"])


def _save_upload(file: UploadFile, suffix: str) -> Path:
    """Save uploaded file and return its path."""
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(file.filename or f"upload{suffix}").name
    dest = upload_dir / f"{uuid.uuid4().hex}_{safe_name}"
    content = file.file.read()
    dest.write_bytes(content)
    return dest


def _persist_findings(findings: list, scan: Scan, db: Session) -> None:
    """Persist imported findings and update scan record."""
    from ipa_analyzer.detectors.base import Severity

    severity_counts = {s: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity] += 1
        db.add(FindingRecord(
            scan_id=scan.id,
            uuid=f.uuid,
            detector=f.detector,
            severity=f.severity.name,
            title=f.title,
            description=f.description,
            location=f.location,
            evidence=f.evidence,
            owasp=f.owasp,
            cwe_id=f.cwe_id,
            remediation=f.remediation,
            scan_type=f.scan_type,
        ))

    from ipa_analyzer.utils.scoring import calculate_risk_score
    risk = calculate_risk_score(findings)

    scan.risk_score = risk.score
    scan.risk_grade = risk.grade
    scan.critical_count = severity_counts.get(Severity.CRITICAL, 0)
    scan.high_count = severity_counts.get(Severity.HIGH, 0)
    scan.medium_count = severity_counts.get(Severity.MEDIUM, 0)
    scan.low_count = severity_counts.get(Severity.LOW, 0)
    scan.info_count = severity_counts.get(Severity.INFO, 0)
    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()


@router.post("/mobsf", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def import_mobsf(
    project_id: int = Form(...),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Import a MobSF JSON report."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project or project.created_by != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    file_path = _save_upload(file, ".json")

    scan = Scan(
        project_id=project_id,
        scan_type="import",
        status="running",
        input_filename=Path(file.filename or "mobsf_report.json").name,
        input_type="mobsf_json",
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        from ipa_analyzer.importers.mobsf import MobSFImporter
        importer = MobSFImporter()
        findings = importer.import_report(file_path)
        _persist_findings(findings, scan, db)
    except Exception as e:
        scan.status = "failed"
        scan.error_message = str(e)
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Import failed: {e}")

    db.refresh(scan)
    return ScanResponse.model_validate(scan)


@router.post("/har", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def import_har(
    project_id: int = Form(...),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Import a HAR (HTTP Archive) file."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project or project.created_by != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    file_path = _save_upload(file, ".har")

    scan = Scan(
        project_id=project_id,
        scan_type="import",
        status="running",
        input_filename=Path(file.filename or "capture.har").name,
        input_type="har",
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        from ipa_analyzer.importers.har import HARImporter
        importer = HARImporter()
        findings = importer.import_har(file_path)
        _persist_findings(findings, scan, db)
    except Exception as e:
        scan.status = "failed"
        scan.error_message = str(e)
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Import failed: {e}")

    db.refresh(scan)
    return ScanResponse.model_validate(scan)
