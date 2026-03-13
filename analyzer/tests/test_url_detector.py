"""Tests for the URL endpoint detector."""

from __future__ import annotations

from ipa_analyzer.detectors.url_detector import URLEndpointDetector


class TestURLEndpointDetector:
    def setup_method(self):
        self.detector = URLEndpointDetector()

    def test_https_url_no_finding(self, strings_context):
        context = strings_context(["https://api.example.com/v1/users"])
        findings = self.detector.analyze(context)
        assert len(findings) == 0

    def test_http_url_flagged(self, strings_context):
        context = strings_context(["http://api.example.com/v1/data"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert findings[0].title == "Insecure HTTP URLs found in binary"
        assert findings[0].severity.name == "MEDIUM"

    def test_staging_url_flagged(self, strings_context):
        context = strings_context(["https://staging.example.com/api"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert "Staging" in findings[0].title
        assert findings[0].severity.name == "HIGH"

    def test_dev_url_flagged(self, strings_context):
        context = strings_context(["https://dev.example.com/api"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert findings[0].severity.name == "HIGH"

    def test_private_ip_flagged(self, strings_context):
        context = strings_context(["https://192.168.1.100:8080/api"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert "Private IP" in findings[0].title
        assert findings[0].severity.name == "HIGH"

    def test_localhost_flagged(self, strings_context):
        context = strings_context(["http://localhost:3000/debug"])
        findings = self.detector.analyze(context)
        assert any("Localhost" in f.title for f in findings)

    def test_deduplication(self, strings_context):
        context = strings_context(
            [
                "http://api.example.com/a",
                "http://api.example.com/a",
            ]
        )
        findings = self.detector.analyze(context)
        assert len(findings) == 1

    def test_mixed_urls(self, strings_context):
        context = strings_context(
            [
                "https://api.example.com/v1",
                "https://staging.example.com/api",
                "http://example.com/insecure",
                "https://10.0.0.1:8080/internal",
            ]
        )
        findings = self.detector.analyze(context)
        # staging (HIGH) + private IP (HIGH) + http (MEDIUM)
        assert len(findings) == 3

    def test_no_urls_no_findings(self, strings_context):
        context = strings_context(["just a regular string with no URLs"])
        findings = self.detector.analyze(context)
        assert len(findings) == 0
