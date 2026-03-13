"""Tests for the SARIF reporter."""

from __future__ import annotations

import json

from ipa_analyzer.detectors.base import Finding, Severity
from ipa_analyzer.reporters.sarif import SARIFReporter


class TestSARIFReporter:
    def setup_method(self):
        self.reporter = SARIFReporter()

    def test_valid_sarif_structure(self, sample_context):
        result = self.reporter.report(sample_context, [])
        data = json.loads(result)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1

    def test_empty_findings(self, sample_context):
        result = self.reporter.report(sample_context, [])
        data = json.loads(result)
        assert data["runs"][0]["results"] == []

    def test_finding_mapped_to_result(self, sample_context):
        finding = Finding(
            detector="ats",
            severity=Severity.HIGH,
            title="ATS Disabled",
            description="ATS is disabled globally",
            location="Info.plist",
            evidence="NSAllowsArbitraryLoads = true",
            owasp="M5",
            remediation="Enable ATS",
            cwe_id=319,
        )
        result = self.reporter.report(sample_context, [finding])
        data = json.loads(result)
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["level"] == "error"
        assert "ATS" in results[0]["message"]["text"]

    def test_severity_level_mapping(self, sample_context):
        findings = [
            Finding("t", Severity.CRITICAL, "F1", "d", "l", "e", "o", "r", 1),
            Finding("t", Severity.MEDIUM, "F2", "d", "l", "e", "o", "r", 1),
            Finding("t", Severity.LOW, "F3", "d", "l", "e", "o", "r", 1),
        ]
        result = self.reporter.report(sample_context, findings)
        data = json.loads(result)
        levels = [r["level"] for r in data["runs"][0]["results"]]
        assert levels == ["error", "warning", "note"]

    def test_tool_info(self, sample_context):
        result = self.reporter.report(sample_context, [])
        data = json.loads(result)
        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "ipa-analyzer"
        assert "version" in tool
