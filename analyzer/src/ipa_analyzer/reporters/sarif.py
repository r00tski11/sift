"""SARIF 2.1.0 report formatter for GitHub Security integration."""

from __future__ import annotations

import json
import re

from ipa_analyzer import __version__
from ipa_analyzer.core.context import AnalysisContext
from ipa_analyzer.detectors.base import Finding, Severity
from ipa_analyzer.reporters.base import BaseReporter
from ipa_analyzer.utils.scoring import calculate_risk_score

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _slugify(text: str) -> str:
    """Convert text to a URL-safe slug for rule IDs."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


class SARIFReporter(BaseReporter):
    """Outputs analysis findings in SARIF 2.1.0 format."""

    def report(
        self,
        context: AnalysisContext,
        findings: list[Finding],
    ) -> str | None:
        """Generate a SARIF 2.1.0 report.

        Args:
            context: The analysis context (for app metadata).
            findings: List of findings to report.

        Returns:
            SARIF JSON string.
        """
        rules: dict[str, dict] = {}
        results: list[dict] = []

        for finding in findings:
            rule_id = f"{finding.detector}/{_slugify(finding.title)}"

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {
                        "text": finding.remediation,
                        "markdown": f"**Remediation:** {finding.remediation}",
                    },
                    "properties": {
                        "owasp": finding.owasp,
                        "cwe": f"CWE-{finding.cwe_id}",
                    },
                }

            results.append(
                {
                    "ruleId": rule_id,
                    "level": SEVERITY_TO_LEVEL[finding.severity],
                    "message": {"text": finding.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": finding.location,
                                },
                            },
                        }
                    ],
                    "properties": {
                        "evidence": finding.evidence,
                        "severity": finding.severity.name,
                    },
                }
            )

        risk = calculate_risk_score(findings)

        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ipa-analyzer",
                            "version": __version__,
                            "informationUri": "https://github.com/ipa-analyzer",
                            "rules": list(rules.values()),
                        },
                    },
                    "results": results,
                    "properties": {
                        "riskScore": risk.score,
                        "riskGrade": risk.grade,
                    },
                }
            ],
        }

        return json.dumps(sarif, indent=2)
