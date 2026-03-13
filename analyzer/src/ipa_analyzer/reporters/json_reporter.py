"""JSON report formatter."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from ipa_analyzer import __version__
from ipa_analyzer.core.context import AnalysisContext
from ipa_analyzer.detectors.base import Finding, Severity
from ipa_analyzer.reporters.base import BaseReporter
from ipa_analyzer.utils.scoring import calculate_risk_score


class JSONReporter(BaseReporter):
    """Outputs analysis findings as structured JSON."""

    def report(
        self,
        context: AnalysisContext,
        findings: list[Finding],
    ) -> str | None:
        """Generate a JSON report.

        Args:
            context: The analysis context (for app metadata).
            findings: List of findings to report.

        Returns:
            JSON string with metadata, summary, and findings.
        """
        severity_counts = Counter(f.severity for f in findings)
        risk = calculate_risk_score(findings)

        data = {
            "metadata": {
                "app_name": context.app_name,
                "ipa_path": str(context.ipa_path),
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "analyzer_version": __version__,
            },
            "risk_score": {
                "score": risk.score,
                "grade": risk.grade,
                "breakdown": risk.breakdown,
            },
            "summary": {
                "total": len(findings),
                "by_severity": {sev.name: severity_counts.get(sev, 0) for sev in Severity},
            },
            "findings": [self._serialize_finding(f) for f in findings],
        }

        return json.dumps(data, indent=2)

    @staticmethod
    def _serialize_finding(finding: Finding) -> dict:
        return {
            "detector": finding.detector,
            "severity": finding.severity.name,
            "title": finding.title,
            "description": finding.description,
            "location": finding.location,
            "evidence": finding.evidence,
            "owasp": finding.owasp,
            "remediation": finding.remediation,
            "cwe_id": finding.cwe_id,
        }
