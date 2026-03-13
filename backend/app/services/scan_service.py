"""Scan execution service — bridges the analyzer library with the database."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy.orm import Session, sessionmaker

from app.models.finding import FindingRecord
from app.models.scan import Scan

logger = logging.getLogger(__name__)

# Ensure the analyzer package is importable.
_analyzer_src = Path(__file__).resolve().parents[3] / "analyzer" / "src"
if str(_analyzer_src) not in sys.path:
    sys.path.insert(0, str(_analyzer_src))


def _publish_progress(scan_id: int, detector: str, current: int, total: int) -> None:
    """Publish scan progress to Redis for WebSocket consumers."""
    try:
        import redis as _redis

        from app.config import settings

        r = _redis.Redis.from_url(settings.REDIS_URL)
        r.publish(
            f"scan:{scan_id}",
            json.dumps(
                {
                    "type": "progress",
                    "detector": detector,
                    "current": current,
                    "total": total,
                }
            ),
        )
    except Exception:
        # Non-critical — don't break scans if Redis is down.
        logger.debug("Failed to publish scan progress to Redis", exc_info=True)


def run_static_scan(
    scan_id: int,
    file_path: str,
    db_session_factory: sessionmaker | Callable[[], Session],
) -> None:
    """Execute a static security scan and persist results.

    Args:
        scan_id: Database ID of the Scan record.
        file_path: Path to the uploaded IPA/xcarchive on disk.
        db_session_factory: Callable that returns a new SQLAlchemy Session.
    """
    from ipa_analyzer.core.scanner import Scanner
    from ipa_analyzer.detectors.base import Severity
    from ipa_analyzer.utils.scoring import calculate_risk_score

    db: Session = db_session_factory()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            logger.error("Scan %d not found in database", scan_id)
            return

        # Mark as running
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        # Publish initial status
        _publish_progress(scan_id, "starting", 0, 1)

        # Run the analyzer
        scanner = Scanner()
        ipa_path = Path(file_path)

        def progress_callback(detector_name: str, current: int, total: int) -> None:
            _publish_progress(scan_id, detector_name, current, total)

        findings, _ = scanner.scan(ipa_path, progress_callback=progress_callback)

        # Calculate risk score
        risk = calculate_risk_score(findings)

        # Severity counts
        severity_counts = {s: 0 for s in Severity}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        # Update scan record
        scan.risk_score = risk.score
        scan.risk_grade = risk.grade
        scan.critical_count = severity_counts.get(Severity.CRITICAL, 0)
        scan.high_count = severity_counts.get(Severity.HIGH, 0)
        scan.medium_count = severity_counts.get(Severity.MEDIUM, 0)
        scan.low_count = severity_counts.get(Severity.LOW, 0)
        scan.info_count = severity_counts.get(Severity.INFO, 0)
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)

        # Persist findings
        for f in findings:
            record = FindingRecord(
                scan_id=scan_id,
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
            )
            db.add(record)

        db.commit()

        # Publish completion
        try:
            import redis as _redis

            from app.config import settings

            r = _redis.Redis.from_url(settings.REDIS_URL)
            r.publish(
                f"scan:{scan_id}",
                json.dumps(
                    {
                        "type": "completed",
                        "risk_score": risk.score,
                        "risk_grade": risk.grade,
                        "total_findings": len(findings),
                    }
                ),
            )
        except Exception:
            logger.debug("Failed to publish scan completion to Redis", exc_info=True)

    except Exception as exc:
        logger.exception("Scan %d failed", scan_id)
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()

        # Publish failure
        try:
            import redis as _redis

            from app.config import settings

            r = _redis.Redis.from_url(settings.REDIS_URL)
            r.publish(
                f"scan:{scan_id}",
                json.dumps({"type": "failed", "error": str(exc)}),
            )
        except Exception:
            pass
    finally:
        db.close()
