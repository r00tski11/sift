"""MobSF JSON report importer — converts MobSF output to Finding objects."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ipa_analyzer.detectors.base import Finding, Severity

_SEVERITY_MAP = {
    "high": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.INFO,
    "good": Severity.INFO,
    "secure": Severity.INFO,
}


class MobSFImporter:
    """Import findings from a MobSF JSON report."""

    def import_report(self, json_path: Path) -> list[Finding]:
        with open(json_path) as f:
            data = json.load(f)

        findings: list[Finding] = []

        # Code analysis findings
        for category, items in data.get("code_analysis", {}).items():
            if isinstance(items, dict):
                for rule_id, detail in items.items():
                    if not isinstance(detail, dict):
                        continue
                    sev_str = detail.get("level", "info").lower()
                    severity = _SEVERITY_MAP.get(sev_str, Severity.INFO)
                    findings.append(
                        Finding(
                            detector="mobsf_import",
                            severity=severity,
                            title=detail.get("metadata", {}).get("description", rule_id),
                            description=detail.get("metadata", {}).get("description", ""),
                            location=(
                                ", ".join(detail.get("files", {}).keys())[:500]
                                if detail.get("files")
                                else "N/A"
                            ),
                            evidence=str(detail.get("metadata", {}).get("input_case", ""))[:500],
                            owasp=detail.get("metadata", {}).get("masvs", "N/A"),
                            remediation=detail.get("metadata", {}).get(
                                "description", "Review the finding."
                            ),
                            cwe_id=_parse_cwe(detail.get("metadata", {}).get("cwe", "")),
                            scan_type="import",
                        )
                    )

        # Binary analysis
        for item in data.get("binary_analysis", []):
            if isinstance(item, dict):
                sev_str = item.get("severity", "info").lower()
                severity = _SEVERITY_MAP.get(sev_str, Severity.INFO)
                findings.append(
                    Finding(
                        detector="mobsf_import",
                        severity=severity,
                        title=item.get("title", "Binary Analysis Finding"),
                        description=item.get("description", ""),
                        location="Binary",
                        evidence=item.get("detailed_desc", "")[:500],
                        owasp=item.get("masvs", "N/A"),
                        remediation=item.get("description", "Review binary protections."),
                        cwe_id=_parse_cwe(item.get("cwe", "")),
                        scan_type="import",
                    )
                )

        return findings


def _parse_cwe(cwe_str: str) -> int:
    """Extract numeric CWE ID from string like 'CWE-798' or 'cwe-798'."""
    if not cwe_str:
        return 0
    match = re.search(r"(\d+)", str(cwe_str))
    return int(match.group(1)) if match else 0
