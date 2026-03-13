"""Tests for the YAML rules loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.utils.exceptions import IPAAnalyzerError
from ipa_analyzer.utils.rules import load_rules


def _write_rules(tmp_path: Path, content: str) -> Path:
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(content)
    return rules_file


class TestLoadRules:
    def test_valid_rules(self, tmp_path):
        path = _write_rules(
            tmp_path,
            """
rules:
  - id: test_001
    name: "Test Rule"
    pattern: "test_pattern"
    severity: high
    description: "A test rule"
    owasp: "M9"
    cwe_id: 798
    remediation: "Fix it"
""",
        )
        rules = load_rules(path)
        assert len(rules) == 1
        assert rules[0].name == "Test Rule"
        assert rules[0].severity == Severity.HIGH
        assert rules[0].cwe_id == 798

    def test_invalid_yaml(self, tmp_path):
        path = _write_rules(tmp_path, "invalid: yaml: content: [")
        with pytest.raises(IPAAnalyzerError, match="Invalid YAML"):
            load_rules(path)

    def test_missing_rules_key(self, tmp_path):
        path = _write_rules(tmp_path, "something_else: true")
        with pytest.raises(IPAAnalyzerError, match="rules"):
            load_rules(path)

    def test_missing_required_field(self, tmp_path):
        path = _write_rules(
            tmp_path,
            """
rules:
  - id: test_001
    name: "Incomplete"
""",
        )
        with pytest.raises(IPAAnalyzerError, match="missing required"):
            load_rules(path)

    def test_invalid_severity(self, tmp_path):
        path = _write_rules(
            tmp_path,
            """
rules:
  - id: test_001
    name: "Test"
    pattern: "test"
    severity: extreme
    description: "d"
    owasp: "M1"
    cwe_id: 1
    remediation: "r"
""",
        )
        with pytest.raises(IPAAnalyzerError, match="invalid severity"):
            load_rules(path)

    def test_severity_case_insensitive(self, tmp_path):
        path = _write_rules(
            tmp_path,
            """
rules:
  - id: test_001
    name: "Test"
    pattern: "test"
    severity: HIGH
    description: "d"
    owasp: "M1"
    cwe_id: 1
    remediation: "r"
""",
        )
        rules = load_rules(path)
        assert rules[0].severity == Severity.HIGH

    def test_invalid_regex(self, tmp_path):
        path = _write_rules(
            tmp_path,
            """
rules:
  - id: test_001
    name: "Test"
    pattern: "[invalid"
    severity: low
    description: "d"
    owasp: "M1"
    cwe_id: 1
    remediation: "r"
""",
        )
        with pytest.raises(IPAAnalyzerError, match="invalid regex"):
            load_rules(path)
