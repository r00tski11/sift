"""Tests for the JSON reporter."""

from __future__ import annotations

import json

from ipa_analyzer.detectors.base import Finding, Severity
from ipa_analyzer.reporters.json_reporter import JSONReporter


class TestJSONReporter:
    def setup_method(self):
        self.reporter = JSONReporter()

    def test_empty_findings(self, sample_context):
        result = self.reporter.report(sample_context, [])
        data = json.loads(result)
        assert data["summary"]["total"] == 0
        assert data["findings"] == []

    def test_single_finding(self, sample_context):
        finding = Finding(
            detector="test",
            severity=Severity.HIGH,
            title="Test Finding",
            description="A test finding",
            location="test/path",
            evidence="test evidence",
            owasp="M1",
            remediation="Fix it",
            cwe_id=123,
        )
        result = self.reporter.report(sample_context, [finding])
        data = json.loads(result)
        assert data["summary"]["total"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "HIGH"
        assert data["findings"][0]["title"] == "Test Finding"

    def test_metadata_fields(self, sample_context):
        result = self.reporter.report(sample_context, [])
        data = json.loads(result)
        assert data["metadata"]["app_name"] == "Test"
        assert "scan_timestamp" in data["metadata"]
        assert "analyzer_version" in data["metadata"]

    def test_severity_counts(self, sample_context):
        findings = [
            Finding("t", Severity.HIGH, "F1", "d", "l", "e", "o", "r", 1),
            Finding("t", Severity.HIGH, "F2", "d", "l", "e", "o", "r", 1),
            Finding("t", Severity.LOW, "F3", "d", "l", "e", "o", "r", 1),
        ]
        result = self.reporter.report(sample_context, findings)
        data = json.loads(result)
        assert data["summary"]["by_severity"]["HIGH"] == 2
        assert data["summary"]["by_severity"]["LOW"] == 1

    def test_output_is_valid_json(self, sample_context):
        finding = Finding("t", Severity.MEDIUM, "F", "d", "l", "e", "o", "r", 1)
        result = self.reporter.report(sample_context, [finding])
        # Should not raise
        json.loads(result)
