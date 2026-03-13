"""Dashboard schemas."""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel

from app.schemas.scan import ScanResponse


class DashboardOverview(BaseModel):
    total_projects: int
    total_scans: int
    total_findings: int
    critical_findings: int
    avg_risk_score: float
    recent_scans: list[ScanResponse]


class TrendPoint(BaseModel):
    date: date
    scan_count: int
    avg_score: float


class VulnerabilityCount(BaseModel):
    title: str
    count: int
    severity: str


class OWASPDistribution(BaseModel):
    category: str
    count: int
