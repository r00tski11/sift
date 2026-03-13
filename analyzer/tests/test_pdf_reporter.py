"""Tests for the PDF reporter."""

from __future__ import annotations

from ipa_analyzer.detectors.base import Finding, Severity
from ipa_analyzer.reporters.pdf import PDFReporter


def _finding(severity: Severity = Severity.HIGH, title: str = "Test") -> Finding:
    return Finding(
        detector="test",
        severity=severity,
        title=title,
        description="Test description",
        location="Payload/Test.app/Test",
        evidence="test evidence",
        owasp="M1",
        remediation="Fix it",
        cwe_id=100,
    )


class TestPDFReporter:
    def test_returns_none(self, sample_context, tmp_path):
        out = tmp_path / "report.pdf"
        reporter = PDFReporter(output_path=out)
        result = reporter.report(sample_context, [_finding()])
        assert result is None

    def test_creates_valid_pdf(self, sample_context, tmp_path):
        out = tmp_path / "report.pdf"
        reporter = PDFReporter(output_path=out)
        reporter.report(sample_context, [_finding()])
        assert out.exists()
        content = out.read_bytes()
        assert content[:5] == b"%PDF-"

    def test_empty_findings(self, sample_context, tmp_path):
        out = tmp_path / "report.pdf"
        reporter = PDFReporter(output_path=out)
        reporter.report(sample_context, [])
        assert out.exists()
        assert out.read_bytes()[:5] == b"%PDF-"

    def test_multiple_severities(self, sample_context, tmp_path):
        out = tmp_path / "report.pdf"
        reporter = PDFReporter(output_path=out)
        findings = [
            _finding(Severity.CRITICAL, "Critical issue"),
            _finding(Severity.HIGH, "High issue"),
            _finding(Severity.MEDIUM, "Medium issue"),
            _finding(Severity.LOW, "Low issue"),
            _finding(Severity.INFO, "Info issue"),
        ]
        reporter.report(sample_context, findings)
        assert out.exists()
        assert out.stat().st_size > 0
