"""Dashboard analytics API routes."""

from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import FindingRecord
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.dashboard import (
    DashboardOverview,
    OWASPDistribution,
    TrendPoint,
    VulnerabilityCount,
)
from app.schemas.scan import ScanResponse
from app.services.auth import get_current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _user_project_ids(user: User, db: Session) -> list[int]:
    """Get all project IDs belonging to a user."""
    rows = db.query(Project.id).filter(Project.created_by == user.id).all()
    return [r[0] for r in rows]


@router.get("/overview", response_model=DashboardOverview)
def overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DashboardOverview:
    """Aggregate statistics for the current user's projects."""
    project_ids = _user_project_ids(current_user, db)

    total_projects = len(project_ids)

    if not project_ids:
        return DashboardOverview(
            total_projects=0,
            total_scans=0,
            total_findings=0,
            critical_findings=0,
            avg_risk_score=0.0,
            recent_scans=[],
        )

    total_scans = db.query(func.count(Scan.id)).filter(Scan.project_id.in_(project_ids)).scalar() or 0

    scan_ids = [
        r[0] for r in db.query(Scan.id).filter(Scan.project_id.in_(project_ids)).all()
    ]

    total_findings = 0
    critical_findings = 0
    if scan_ids:
        total_findings = (
            db.query(func.count(FindingRecord.id))
            .filter(FindingRecord.scan_id.in_(scan_ids))
            .scalar()
            or 0
        )
        critical_findings = (
            db.query(func.count(FindingRecord.id))
            .filter(FindingRecord.scan_id.in_(scan_ids), FindingRecord.severity == "CRITICAL")
            .scalar()
            or 0
        )

    avg_risk_score = (
        db.query(func.avg(Scan.risk_score))
        .filter(Scan.project_id.in_(project_ids), Scan.risk_score.isnot(None))
        .scalar()
    ) or 0.0

    recent_scans = (
        db.query(Scan)
        .filter(Scan.project_id.in_(project_ids))
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    return DashboardOverview(
        total_projects=total_projects,
        total_scans=total_scans,
        total_findings=total_findings,
        critical_findings=critical_findings,
        avg_risk_score=round(float(avg_risk_score), 1),
        recent_scans=[ScanResponse.model_validate(s) for s in recent_scans],
    )


@router.get("/trends", response_model=list[TrendPoint])
def trends(
    days: int = Query(default=30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[TrendPoint]:
    """Scan count and average risk score per day for the last N days."""
    project_ids = _user_project_ids(current_user, db)
    if not project_ids:
        return []

    start_date = date.today() - timedelta(days=days)

    scans = (
        db.query(Scan)
        .filter(
            Scan.project_id.in_(project_ids),
            Scan.created_at >= start_date,
        )
        .all()
    )

    # Group by date
    by_date: dict[date, list[Scan]] = {}
    for scan in scans:
        d = scan.created_at.date()
        by_date.setdefault(d, []).append(scan)

    points: list[TrendPoint] = []
    current = start_date
    today = date.today()
    while current <= today:
        day_scans = by_date.get(current, [])
        scores = [s.risk_score for s in day_scans if s.risk_score is not None]
        points.append(
            TrendPoint(
                date=current,
                scan_count=len(day_scans),
                avg_score=round(sum(scores) / len(scores), 1) if scores else 0.0,
            )
        )
        current += timedelta(days=1)

    return points


@router.get("/top-vulnerabilities", response_model=list[VulnerabilityCount])
def top_vulnerabilities(
    limit: int = Query(default=10, ge=1, le=50),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[VulnerabilityCount]:
    """Most common findings across all user's scans."""
    project_ids = _user_project_ids(current_user, db)
    if not project_ids:
        return []

    scan_ids = [
        r[0] for r in db.query(Scan.id).filter(Scan.project_id.in_(project_ids)).all()
    ]
    if not scan_ids:
        return []

    rows = (
        db.query(
            FindingRecord.title,
            FindingRecord.severity,
            func.count(FindingRecord.id).label("cnt"),
        )
        .filter(FindingRecord.scan_id.in_(scan_ids))
        .group_by(FindingRecord.title, FindingRecord.severity)
        .order_by(func.count(FindingRecord.id).desc())
        .limit(limit)
        .all()
    )

    return [VulnerabilityCount(title=r.title, severity=r.severity, count=r.cnt) for r in rows]


@router.get("/owasp-distribution", response_model=list[OWASPDistribution])
def owasp_distribution(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[OWASPDistribution]:
    """Finding counts grouped by OWASP category."""
    project_ids = _user_project_ids(current_user, db)
    if not project_ids:
        return []

    scan_ids = [
        r[0] for r in db.query(Scan.id).filter(Scan.project_id.in_(project_ids)).all()
    ]
    if not scan_ids:
        return []

    rows = (
        db.query(
            FindingRecord.owasp,
            func.count(FindingRecord.id).label("cnt"),
        )
        .filter(FindingRecord.scan_id.in_(scan_ids))
        .group_by(FindingRecord.owasp)
        .order_by(func.count(FindingRecord.id).desc())
        .all()
    )

    return [OWASPDistribution(category=r.owasp, count=r.cnt) for r in rows]
