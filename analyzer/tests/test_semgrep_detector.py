"""Tests for the Semgrep source code detector."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.detectors.semgrep import SemgrepDetector, _extract_cwe, _extract_owasp


@pytest.fixture
def sample_sarif():
    """Minimal SARIF output as Semgrep would produce."""
    return {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semgrep",
                        "rules": [
                            {
                                "id": "swift-hardcoded-password",
                                "shortDescription": {"text": "Hardcoded Password"},
                                "fullDescription": {"text": "A hardcoded password was found."},
                                "help": {"text": "Use Keychain instead."},
                                "properties": {
                                    "tags": ["CWE-798", "owasp-m9"]
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "swift-hardcoded-password",
                        "level": "error",
                        "message": {"text": "Hardcoded password found"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "Sources/Auth.swift"},
                                    "region": {
                                        "startLine": 42,
                                        "snippet": {"text": 'let password = "hunter2"'},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }


@pytest.fixture
def detector(tmp_path):
    """Create a SemgrepDetector with a temp rules dir."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yaml").write_text("rules: []")
    return SemgrepDetector(rules_dir=rules_dir)


@pytest.fixture
def context_with_source(tmp_path):
    """Create a mock AnalysisContext with source_dir set."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "test.swift").write_text('let password = "secret"')

    ctx = MagicMock()
    ctx.source_dir = source_dir
    return ctx


class TestSemgrepDetector:
    def test_returns_empty_when_no_source_dir(self, detector):
        ctx = MagicMock()
        ctx.source_dir = None
        assert detector.analyze(ctx) == []

    def test_returns_empty_when_source_dir_not_exists(self, detector, tmp_path):
        ctx = MagicMock()
        ctx.source_dir = tmp_path / "nonexistent"
        assert detector.analyze(ctx) == []

    @patch("ipa_analyzer.detectors.semgrep.subprocess.run")
    def test_parses_sarif_results(self, mock_run, detector, context_with_source, sample_sarif):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps(sample_sarif),
            stderr="",
        )
        findings = detector.analyze(context_with_source)
        assert len(findings) == 1

        f = findings[0]
        assert f.detector == "semgrep"
        assert f.severity == Severity.HIGH  # ERROR maps to HIGH
        assert f.title == "Hardcoded Password"
        assert f.location == "Sources/Auth.swift:42"
        assert f.scan_type == "source"
        assert f.cwe_id == 798
        assert "owasp" in f.owasp.lower()

    @patch("ipa_analyzer.detectors.semgrep.subprocess.run")
    def test_handles_semgrep_not_installed(self, mock_run, detector, context_with_source):
        mock_run.side_effect = FileNotFoundError("semgrep not found")
        findings = detector.analyze(context_with_source)
        assert findings == []

    @patch("ipa_analyzer.detectors.semgrep.subprocess.run")
    def test_handles_timeout(self, mock_run, detector, context_with_source):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=300)
        findings = detector.analyze(context_with_source)
        assert findings == []

    @patch("ipa_analyzer.detectors.semgrep.subprocess.run")
    def test_handles_bad_json(self, mock_run, detector, context_with_source):
        mock_run.return_value = MagicMock(returncode=0, stdout="not json", stderr="")
        findings = detector.analyze(context_with_source)
        assert findings == []

    @patch("ipa_analyzer.detectors.semgrep.subprocess.run")
    def test_severity_mapping(self, mock_run, detector, context_with_source, sample_sarif):
        # Test WARNING level
        sample_sarif["runs"][0]["results"][0]["level"] = "warning"
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps(sample_sarif),
            stderr="",
        )
        findings = detector.analyze(context_with_source)
        assert findings[0].severity == Severity.MEDIUM

    @patch("ipa_analyzer.detectors.semgrep.subprocess.run")
    def test_no_results(self, mock_run, detector, context_with_source):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}),
            stderr="",
        )
        findings = detector.analyze(context_with_source)
        assert findings == []

    def test_returns_empty_when_rules_dir_missing(self, tmp_path):
        det = SemgrepDetector(rules_dir=tmp_path / "no-such-dir")
        ctx = MagicMock()
        ctx.source_dir = tmp_path
        assert det.analyze(ctx) == []


class TestHelpers:
    def test_extract_owasp_found(self):
        assert "owasp" in _extract_owasp(["CWE-798", "owasp-m9"]).lower()

    def test_extract_owasp_default(self):
        assert _extract_owasp(["CWE-798"]) == "M7 - Code Quality"

    def test_extract_cwe_found(self):
        assert _extract_cwe(["CWE-798", "owasp-m9"]) == 798

    def test_extract_cwe_not_found(self):
        assert _extract_cwe(["owasp-m9"]) == 0

    def test_extract_cwe_with_description(self):
        assert _extract_cwe(["CWE-798:Use of Hard-coded Credentials"]) == 798
