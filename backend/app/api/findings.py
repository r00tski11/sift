"""Finding management API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import FindingRecord
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import BulkFindingUpdate, FindingResponse, FindingUpdate
from app.services.auth import get_current_user

router = APIRouter(prefix="/findings", tags=["findings"])


def _assert_finding_access(finding: FindingRecord, user: User, db: Session) -> None:
    """Verify the user owns the project that this finding belongs to."""
    scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    project = db.query(Project).filter(Project.id == scan.project_id).first()
    if not project or project.created_by != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FindingResponse:
    """Get a single finding by ID."""
    finding = db.query(FindingRecord).filter(FindingRecord.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    _assert_finding_access(finding, current_user, db)
    return FindingResponse.model_validate(finding)


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: int,
    body: FindingUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FindingResponse:
    """Update a finding's status, notes, or false-positive flag."""
    finding = db.query(FindingRecord).filter(FindingRecord.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    _assert_finding_access(finding, current_user, db)

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(finding, field, value)
    db.commit()
    db.refresh(finding)
    return FindingResponse.model_validate(finding)


@router.patch("/bulk/update", response_model=dict)
def bulk_update_findings(
    body: BulkFindingUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Bulk update multiple findings at once."""
    findings = (
        db.query(FindingRecord).filter(FindingRecord.id.in_(body.finding_ids)).all()
    )
    if not findings:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No findings found")

    # Verify access for all findings
    for finding in findings:
        _assert_finding_access(finding, current_user, db)

    update_data = body.model_dump(exclude_unset=True, exclude={"finding_ids"})
    updated_count = 0
    for finding in findings:
        for field, value in update_data.items():
            setattr(finding, field, value)
        updated_count += 1

    db.commit()
    return {"updated_count": updated_count}
