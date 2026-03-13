"""Custom YAML rules detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ipa_analyzer.detectors.base import BaseDetector, Finding
from ipa_analyzer.utils.rules import CustomRule

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext


class CustomRulesDetector(BaseDetector):
    """Applies user-defined detection rules from YAML configuration."""

    name = "custom_rules"
    description = "User-defined detection rules from YAML configuration"
    owasp_category = "N/A"

    def __init__(self, rules: list[CustomRule]) -> None:
        self.rules = rules

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Scan binary strings against custom rule patterns.

        Args:
            context: Analysis context with binary_strings populated.

        Returns:
            List of findings for matched rules.
        """
        findings: list[Finding] = []
        location = f"Payload/{context.app_bundle_path.name}/{context.binary_path.name}"

        for rule in self.rules:
            matched = False
            for string in context.binary_strings:
                if rule.pattern.search(string):
                    matched = True
                    break

            if matched:
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=rule.severity,
                        title=rule.name,
                        description=rule.description,
                        location=location,
                        evidence=f"Pattern matched: {rule.pattern.pattern}",
                        owasp=rule.owasp,
                        remediation=rule.remediation,
                        cwe_id=rule.cwe_id,
                    )
                )

        return findings
