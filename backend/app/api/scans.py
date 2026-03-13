"""Scan management API routes."""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.finding import FindingRecord
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import FindingResponse
from app.schemas.scan import ScanResponse
from app.services.auth import get_current_user
from app.tasks.scan_tasks import run_scan_task

MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB

router = APIRouter(prefix="/scans", tags=["scans"])


def _assert_project_access(project_id: int, user: User, db: Session) -> Project:
    """Verify the project exists and belongs to the user."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project.created_by != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return project


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    project_id: int = Form(...),
    scan_type: str = Form(default="static"),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Upload a file and start a new scan.

    Accepts multipart form data with project_id, scan_type, and file.
    """
    _assert_project_access(project_id, current_user, db)

    # Validate scan type
    valid_types = {"static", "source", "dynamic", "import"}
    if scan_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan_type. Must be one of: {', '.join(valid_types)}",
        )

    # Sanitize filename — strip directory components to prevent path traversal
    safe_name = Path(file.filename or "unknown").name
    suffix = Path(safe_name).suffix.lower()
    if suffix not in {".ipa", ".xcarchive", ".zip"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file type. Upload a .ipa, .xcarchive, or .zip file.",
        )

    # Determine input type
    input_type = "ipa" if suffix == ".ipa" else "xcarchive" if suffix == ".xcarchive" else "zip"

    # Save uploaded file with streaming write and size limit
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    file_path = upload_dir / unique_name

    total_size = 0
    with open(file_path, "wb") as f:
        while chunk := await file.read(1024 * 1024):  # 1 MB chunks
            total_size += len(chunk)
            if total_size > MAX_UPLOAD_BYTES:
                f.close()
                file_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File too large. Maximum size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
                )
            f.write(chunk)

    # Create scan record
    scan = Scan(
        project_id=project_id,
        scan_type=scan_type,
        status="pending",
        input_filename=safe_name,
        input_type=input_type,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Dispatch Celery task
    task = run_scan_task.delay(scan.id, str(file_path))
    scan.celery_task_id = task.id
    db.commit()
    db.refresh(scan)

    return ScanResponse.model_validate(scan)


# NOTE: /compare/ must be registered BEFORE /{scan_id} to avoid route shadowing.
@router.get("/compare/", response_model=dict)
def compare_scans(
    a: int = Query(..., description="First scan ID (baseline)"),
    b: int = Query(..., description="Second scan ID (current)"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Compare two scans: new, resolved, and unchanged findings.

    Findings are matched by title + detector combination.
    """
    scan_a = db.query(Scan).filter(Scan.id == a).first()
    scan_b = db.query(Scan).filter(Scan.id == b).first()
    if not scan_a or not scan_b:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both scans not found")

    _assert_project_access(scan_a.project_id, current_user, db)
    _assert_project_access(scan_b.project_id, current_user, db)

    findings_a = db.query(FindingRecord).filter(FindingRecord.scan_id == a).all()
    findings_b = db.query(FindingRecord).filter(FindingRecord.scan_id == b).all()

    def _key(f: FindingRecord) -> tuple[str, str]:
        return (f.title, f.detector)

    keys_a = {_key(f) for f in findings_a}
    keys_b = {_key(f) for f in findings_b}

    new_keys = keys_b - keys_a
    resolved_keys = keys_a - keys_b
    unchanged_keys = keys_a & keys_b

    new_findings = [FindingResponse.model_validate(f) for f in findings_b if _key(f) in new_keys]
    resolved_findings = [FindingResponse.model_validate(f) for f in findings_a if _key(f) in resolved_keys]
    unchanged_findings = [FindingResponse.model_validate(f) for f in findings_b if _key(f) in unchanged_keys]

    return {
        "scan_a_id": a,
        "scan_b_id": b,
        "new": new_findings,
        "resolved": resolved_findings,
        "unchanged": unchanged_findings,
        "summary": {
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "unchanged_count": len(unchanged_findings),
        },
    }


def _findings_to_analyzer(db_findings: list[FindingRecord]) -> list:
    """Convert DB FindingRecord rows to analyzer Finding dataclass instances."""
    from ipa_analyzer.detectors.base import Finding as AnalyzerFinding, Severity

    severity_map = {s.name: s for s in Severity}
    return [
        AnalyzerFinding(
            detector=f.detector,
            severity=severity_map.get(f.severity, Severity.INFO),
            title=f.title,
            description=f.description,
            location=f.location,
            evidence=f.evidence,
            owasp=f.owasp,
            remediation=f.remediation,
            cwe_id=f.cwe_id,
            uuid=f.uuid,
            scan_type=f.scan_type,
        )
        for f in db_findings
    ]


@router.get("/{scan_id}/report/{fmt}")
def download_report(
    scan_id: int,
    fmt: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    """Download a scan report in the specified format (json, html, pdf, sarif)."""
    valid_formats = {"json", "html", "pdf", "sarif"}
    if fmt not in valid_formats:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format. Must be one of: {', '.join(sorted(valid_formats))}",
        )

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    _assert_project_access(scan.project_id, current_user, db)

    db_findings = db.query(FindingRecord).filter(FindingRecord.scan_id == scan_id).all()
    analyzer_findings = _findings_to_analyzer(db_findings)

    # Build a stub AnalysisContext for the reporters
    from ipa_analyzer.core.context import AnalysisContext

    stub_context = AnalysisContext(
        ipa_path=Path(scan.input_filename or "unknown"),
        extracted_dir=Path("/tmp"),
        app_bundle_path=Path(scan.app_name or scan.input_filename or "App").with_suffix(".app"),
        info_plist={},
        binary_path=Path("/tmp/binary"),
    )

    if fmt == "json":
        from ipa_analyzer.reporters.json_reporter import JSONReporter

        content = JSONReporter().report(stub_context, analyzer_findings)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.json"'},
        )
    elif fmt == "html":
        from ipa_analyzer.reporters.html import HTMLReporter

        content = HTMLReporter().report(stub_context, analyzer_findings)
        return Response(
            content=content,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.html"'},
        )
    elif fmt == "sarif":
        from ipa_analyzer.reporters.sarif import SARIFReporter

        content = SARIFReporter().report(stub_context, analyzer_findings)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.sarif.json"'},
        )
    else:  # pdf
        from ipa_analyzer.reporters.pdf import PDFReporter

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            PDFReporter(output_path=tmp_path).report(stub_context, analyzer_findings)
            pdf_bytes = tmp_path.read_bytes()
        finally:
            tmp_path.unlink(missing_ok=True)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_report.pdf"'},
        )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Get a single scan by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    _assert_project_access(scan.project_id, current_user, db)
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/findings", response_model=dict)
def get_scan_findings(
    scan_id: int,
    severity: str | None = Query(default=None),
    detector: str | None = Query(default=None),
    finding_status: str | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Get findings for a scan with filtering and pagination."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    _assert_project_access(scan.project_id, current_user, db)

    query = db.query(FindingRecord).filter(FindingRecord.scan_id == scan_id)

    if severity:
        query = query.filter(FindingRecord.severity == severity.upper())
    if detector:
        query = query.filter(FindingRecord.detector == detector)
    if finding_status:
        query = query.filter(FindingRecord.status == finding_status)

    total = query.count()
    findings = (
        query.order_by(FindingRecord.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "findings": [FindingResponse.model_validate(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
    }
