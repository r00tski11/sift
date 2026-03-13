"""HTML report formatter using Jinja2 templates."""

from __future__ import annotations

from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ipa_analyzer import __version__
from ipa_analyzer.core.context import AnalysisContext
from ipa_analyzer.detectors.base import Finding, Severity
from ipa_analyzer.reporters.base import BaseReporter
from ipa_analyzer.utils.scoring import calculate_risk_score

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _group_findings(findings: list[Finding]) -> list[dict]:
    """Group findings by severity and title for the accordion UI.

    Returns a list of severity sections, each containing grouped findings.
    Only severity levels with findings are included.
    """
    # Bucket findings by (severity, title)
    buckets: OrderedDict[tuple[Severity, str], list[Finding]] = OrderedDict()
    for f in sorted(findings, key=lambda f: (-f.severity.value, f.title)):
        key = (f.severity, f.title)
        buckets.setdefault(key, []).append(f)

    # Build severity sections
    sections: OrderedDict[Severity, list[dict]] = OrderedDict()
    for (severity, title), group_findings in buckets.items():
        first = group_findings[0]
        group = {
            "title": title,
            "description": first.description,
            "owasp": first.owasp,
            "cwe_id": first.cwe_id,
            "remediation": first.remediation,
            "severity": severity.name,
            "count": len(group_findings),
            "instances": [{"location": f.location, "evidence": f.evidence} for f in group_findings],
        }
        sections.setdefault(severity, []).append(group)

    return [{"severity": sev.name, "groups": groups} for sev, groups in sections.items()]


class HTMLReporter(BaseReporter):
    """Renders analysis findings as a styled HTML report."""

    def report(
        self,
        context: AnalysisContext,
        findings: list[Finding],
    ) -> str | None:
        """Generate an HTML report.

        Args:
            context: The analysis context (for app metadata).
            findings: List of findings to report.

        Returns:
            Rendered HTML string.
        """
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        template = env.get_template("report.html")

        severity_counts = Counter(f.severity for f in findings)
        grouped = _group_findings(findings)
        unique_count = sum(len(s["groups"]) for s in grouped)
        risk = calculate_risk_score(findings)

        return template.render(
            app_name=context.app_name,
            ipa_path=str(context.ipa_path),
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            version=__version__,
            total_findings=len(findings),
            unique_count=unique_count,
            severity_counts={sev.name: severity_counts.get(sev, 0) for sev in Severity},
            grouped_findings=grouped,
            risk_score=risk.score,
            risk_grade=risk.grade,
        )
