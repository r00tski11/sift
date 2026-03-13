"""Celery tasks for scan execution."""

from __future__ import annotations

from app.database import SessionLocal
from app.services.scan_service import run_static_scan
from app.tasks.celery_app import celery_app


@celery_app.task(name="app.tasks.scan_tasks.run_scan_task", bind=True, max_retries=2)
def run_scan_task(self, scan_id: int, file_path: str) -> dict:  # noqa: ANN001
    """Celery task wrapper for static scan execution.

    Args:
        scan_id: Database ID of the Scan record.
        file_path: Absolute path to the uploaded file.

    Returns:
        Dict with scan_id and status.
    """
    try:
        run_static_scan(scan_id, file_path, SessionLocal)
        return {"scan_id": scan_id, "status": "completed"}
    except Exception as exc:
        # Let Celery retry on transient failures.
        raise self.retry(exc=exc, countdown=30)
