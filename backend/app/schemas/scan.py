"""Scan schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ScanCreate(BaseModel):
    """Internal schema used when creating a scan record."""

    project_id: int
    scan_type: str


class ScanResponse(BaseModel):
    id: int
    project_id: int
    scan_type: str
    status: str
    input_filename: str
    input_type: str
    app_name: str | None
    risk_score: int | None
    risk_grade: str | None
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    error_message: str | None
    celery_task_id: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    count: int
