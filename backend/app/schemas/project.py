"""Project schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    bundle_id: str | None = None
    description: str | None = None


class ProjectUpdate(BaseModel):
    name: str | None = None
    bundle_id: str | None = None
    description: str | None = None


class ProjectResponse(BaseModel):
    id: int
    name: str
    bundle_id: str | None
    description: str | None
    created_by: int
    created_at: datetime
    scan_count: int = 0

    model_config = {"from_attributes": True}
