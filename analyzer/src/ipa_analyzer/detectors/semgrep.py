"""Semgrep-based source code security detector for iOS Swift projects."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from ipa_analyzer.detectors.base import BaseDetector, Finding, Severity

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext

logger = logging.getLogger(__name__)

# Default rules directory relative to this file
_DEFAULT_RULES_DIR = Path(__file__).resolve().parents[2] / "semgrep_rules"

# Map Semgrep severity levels to our Severity enum
_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepDetector(BaseDetector):
    """Runs Semgrep against Swift/iOS source code and converts SARIF results to Findings."""

    name = "semgrep"
    description = "Source code analysis using Semgrep rules for iOS/Swift security"
    owasp_category = "M7 - Code Quality"

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_dir = rules_dir or _DEFAULT_RULES_DIR

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Run Semgrep on source_dir if available, return findings."""
        if context.source_dir is None:
            return []

        if not context.source_dir.is_dir():
            logger.warning("source_dir %s is not a directory", context.source_dir)
            return []

        if not self.rules_dir.is_dir():
            logger.warning("Semgrep rules directory not found: %s", self.rules_dir)
            return []

        sarif = self._run_semgrep(context.source_dir)
        if sarif is None:
            return []

        return self._parse_sarif(sarif)

    def _run_semgrep(self, source_dir: Path) -> dict | None:
        """Execute semgrep CLI and return parsed SARIF output."""
        cmd = [
            "semgrep", "scan",
            "--config", str(self.rules_dir),
            "--sarif",
            "--quiet",
            "--no-git-ignore",
            str(source_dir),
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode not in (0, 1):
                # 0 = no findings, 1 = findings found, other = error
                logger.error("Semgrep failed (exit %d): %s", result.returncode, result.stderr)
                return None
            return json.loads(result.stdout)
        except FileNotFoundError:
            logger.info("Semgrep is not installed — skipping source code scan")
            return None
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out after 300 seconds")
            return None
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Semgrep SARIF output: %s", e)
            return None

    def _parse_sarif(self, sarif: dict) -> list[Finding]:
        """Convert SARIF JSON to list of Finding objects."""
        findings: list[Finding] = []

        for run in sarif.get("runs", []):
            rules_by_id: dict[str, dict] = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rules_by_id[rule["id"]] = rule

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule_meta = rules_by_id.get(rule_id, {})

                # Severity
                level = result.get("level", "WARNING").upper()
                severity = _SEVERITY_MAP.get(level, Severity.MEDIUM)

                # Location
                locations = result.get("locations", [])
                location = "unknown"
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {}).get("uri", "unknown")
                    region = phys.get("region", {})
                    line = region.get("startLine", 0)
                    location = f"{artifact}:{line}" if line else artifact

                # Evidence (the matched code snippet)
                evidence = ""
                if locations:
                    region = locations[0].get("physicalLocation", {}).get("region", {})
                    snippet = region.get("snippet", {})
                    evidence = snippet.get("text", "")

                # Message
                message = result.get("message", {}).get("text", rule_id)

                # Rule metadata
                rule_name = rule_meta.get("shortDescription", {}).get("text", rule_id)
                description = rule_meta.get("fullDescription", {}).get("text", message)
                help_text = rule_meta.get("help", {}).get("text", "")

                # Extract OWASP and CWE from rule properties/tags
                properties = rule_meta.get("properties", {})
                tags = properties.get("tags", [])
                owasp = _extract_owasp(tags)
                cwe_id = _extract_cwe(tags)

                findings.append(
                    Finding(
                        detector=self.name,
                        severity=severity,
                        title=rule_name,
                        description=description,
                        location=location,
                        evidence=evidence[:500] if evidence else "",
                        owasp=owasp,
                        remediation=help_text or "Review and fix the flagged code pattern.",
                        cwe_id=cwe_id,
                        scan_type="source",
                    )
                )

        return findings


def _extract_owasp(tags: list[str]) -> str:
    """Extract OWASP category from Semgrep rule tags."""
    for tag in tags:
        if "owasp" in tag.lower():
            return tag
    return "M7 - Code Quality"


def _extract_cwe(tags: list[str]) -> int:
    """Extract CWE ID from Semgrep rule tags."""
    for tag in tags:
        tag_upper = tag.upper()
        if tag_upper.startswith("CWE-"):
            try:
                return int(tag_upper.split("-")[1].split(":")[0])
            except (IndexError, ValueError):
                continue
    return 0
