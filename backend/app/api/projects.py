"""Project management API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.project import ProjectCreate, ProjectResponse, ProjectUpdate
from app.schemas.scan import ScanListResponse, ScanResponse
from app.services.auth import get_current_user

router = APIRouter(prefix="/projects", tags=["projects"])


def _project_response(project: Project) -> ProjectResponse:
    """Build a ProjectResponse with computed scan_count."""
    return ProjectResponse(
        id=project.id,
        name=project.name,
        bundle_id=project.bundle_id,
        description=project.description,
        created_by=project.created_by,
        created_at=project.created_at,
        scan_count=len(project.scans),
    )


def _get_user_project(project_id: int, user: User, db: Session) -> Project:
    """Fetch a project ensuring it belongs to the current user."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    if project.created_by != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return project


@router.get("/", response_model=list[ProjectResponse])
def list_projects(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ProjectResponse]:
    """List all projects owned by the current user."""
    projects = (
        db.query(Project)
        .filter(Project.created_by == current_user.id)
        .order_by(Project.created_at.desc())
        .all()
    )
    return [_project_response(p) for p in projects]


@router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    body: ProjectCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProjectResponse:
    """Create a new project."""
    project = Project(
        name=body.name,
        bundle_id=body.bundle_id,
        description=body.description,
        created_by=current_user.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return _project_response(project)


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProjectResponse:
    """Get a single project by ID."""
    project = _get_user_project(project_id, current_user, db)
    return _project_response(project)


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: int,
    body: ProjectUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProjectResponse:
    """Update a project."""
    project = _get_user_project(project_id, current_user, db)
    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(project, field, value)
    db.commit()
    db.refresh(project)
    return _project_response(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a project and all its scans/findings."""
    project = _get_user_project(project_id, current_user, db)
    db.delete(project)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{project_id}/scans", response_model=ScanListResponse)
def list_project_scans(
    project_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanListResponse:
    """List all scans for a project."""
    _get_user_project(project_id, current_user, db)
    scans = (
        db.query(Scan)
        .filter(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    return ScanListResponse(
        scans=[ScanResponse.model_validate(s) for s in scans],
        count=len(scans),
    )
