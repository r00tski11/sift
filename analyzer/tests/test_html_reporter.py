"""Tests for the HTML reporter."""

from __future__ import annotations

from ipa_analyzer.detectors.base import Finding, Severity
from ipa_analyzer.reporters.html import HTMLReporter


class TestHTMLReporter:
    def setup_method(self):
        self.reporter = HTMLReporter()

    def test_report_contains_app_name(self, sample_context):
        result = self.reporter.report(sample_context, [])
        assert "Test" in result
        assert "<html" in result

    def test_empty_findings_message(self, sample_context):
        result = self.reporter.report(sample_context, [])
        assert "No security findings detected" in result

    def test_finding_rendered(self, sample_context):
        finding = Finding(
            detector="test",
            severity=Severity.HIGH,
            title="Test Finding Title",
            description="A detailed description",
            location="test/path",
            evidence="some evidence",
            owasp="M5 - Insecure Communication",
            remediation="Fix the issue",
            cwe_id=319,
        )
        result = self.reporter.report(sample_context, [finding])
        assert "Test Finding Title" in result
        assert "HIGH" in result
        assert "CWE-319" in result

    def test_severity_badge_present(self, sample_context):
        finding = Finding("t", Severity.CRITICAL, "F", "d", "l", "e", "o", "r", 1)
        result = self.reporter.report(sample_context, [finding])
        assert "CRITICAL" in result
        assert "badge critical" in result

    def test_duplicate_findings_grouped(self, sample_context):
        """Multiple findings with the same title should be grouped into one accordion."""
        findings = [
            Finding("s", Severity.HIGH, "Same Title", "desc", "loc1", "ev1", "o", "r", 1),
            Finding("s", Severity.HIGH, "Same Title", "desc", "loc2", "ev2", "o", "r", 1),
            Finding("s", Severity.HIGH, "Same Title", "desc", "loc3", "ev3", "o", "r", 1),
        ]
        result = self.reporter.report(sample_context, findings)
        # Title should appear as a group, not 3 separate cards
        assert "accordion-header" in result
        # Count badge should show 3
        assert ">3<" in result
        # All evidence values should be in the instances table
        assert "ev1" in result
        assert "ev2" in result
        assert "ev3" in result

    def test_unique_count_displayed(self, sample_context):
        """The summary should show unique type count vs total instances."""
        findings = [
            Finding("s", Severity.HIGH, "Title A", "d", "l", "e", "o", "r", 1),
            Finding("s", Severity.HIGH, "Title A", "d", "l", "e", "o", "r", 1),
            Finding("s", Severity.MEDIUM, "Title B", "d", "l", "e", "o", "r", 1),
        ]
        result = self.reporter.report(sample_context, findings)
        assert "2 unique types" in result
        assert "3 instances" in result
