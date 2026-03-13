"""Finding schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class FindingResponse(BaseModel):
    id: int
    uuid: str
    scan_id: int
    detector: str
    severity: str
    title: str
    description: str
    location: str
    evidence: str
    owasp: str
    cwe_id: int
    remediation: str
    scan_type: str
    status: str
    is_false_positive: bool
    notes: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    status: str | None = None
    is_false_positive: bool | None = None
    notes: str | None = None


class BulkFindingUpdate(BaseModel):
    finding_ids: list[int]
    status: str | None = None
    is_false_positive: bool | None = None
    notes: str | None = None
