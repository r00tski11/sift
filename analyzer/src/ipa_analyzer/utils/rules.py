"""Custom YAML rules loader and parser."""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass
from pathlib import Path

import yaml

from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.utils.exceptions import IPAAnalyzerError

REQUIRED_FIELDS = {
    "id",
    "name",
    "pattern",
    "severity",
    "description",
    "owasp",
    "cwe_id",
    "remediation",
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@dataclass
class CustomRule:
    """A user-defined detection rule loaded from YAML."""

    id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    description: str
    owasp: str
    cwe_id: int
    remediation: str


def load_rules(rules_path: Path) -> list[CustomRule]:
    """Load and validate custom detection rules from a YAML file.

    Args:
        rules_path: Path to the YAML rules file.

    Returns:
        List of parsed CustomRule objects.

    Raises:
        IPAAnalyzerError: If the YAML is invalid or rules are malformed.
    """
    try:
        with open(rules_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise IPAAnalyzerError(f"Invalid YAML in rules file: {e}") from e

    if not isinstance(data, dict) or "rules" not in data:
        raise IPAAnalyzerError("Rules file must contain a top-level 'rules' key")

    rules_data = data["rules"]
    if not isinstance(rules_data, list):
        raise IPAAnalyzerError("'rules' must be a list")

    rules: list[CustomRule] = []
    for i, rule_data in enumerate(rules_data):
        if not isinstance(rule_data, dict):
            raise IPAAnalyzerError(f"Rule {i} must be a mapping")

        missing = REQUIRED_FIELDS - set(rule_data.keys())
        if missing:
            raise IPAAnalyzerError(f"Rule {i} missing required fields: {missing}")

        severity_str = str(rule_data["severity"]).lower()
        if severity_str not in SEVERITY_MAP:
            raise IPAAnalyzerError(
                f"Rule {i} has invalid severity '{rule_data['severity']}'. "
                f"Must be one of: {', '.join(SEVERITY_MAP.keys())}"
            )

        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("error", category=DeprecationWarning)
                pattern = re.compile(rule_data["pattern"])
        except (re.error, DeprecationWarning) as e:
            raise IPAAnalyzerError(
                f"Rule {i} ('{rule_data['id']}') has invalid regex pattern: {e}"
            ) from e

        rules.append(
            CustomRule(
                id=str(rule_data["id"]),
                name=str(rule_data["name"]),
                pattern=pattern,
                severity=SEVERITY_MAP[severity_str],
                description=str(rule_data["description"]),
                owasp=str(rule_data["owasp"]),
                cwe_id=int(rule_data["cwe_id"]),
                remediation=str(rule_data["remediation"]),
            )
        )

    return rules
