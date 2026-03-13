"""Tests for the ATS (App Transport Security) detector."""

from __future__ import annotations

from ipa_analyzer.detectors.ats import ATSDetector
from ipa_analyzer.detectors.base import Severity


class TestATSDetector:
    def setup_method(self):
        self.detector = ATSDetector()

    def test_no_ats_key_returns_no_findings(self, sample_context):
        """No NSAppTransportSecurity key means secure defaults."""
        sample_context.info_plist.pop("NSAppTransportSecurity", None)
        findings = self.detector.analyze(sample_context)
        assert len(findings) == 0

    def test_allows_arbitrary_loads(self, ats_context):
        """NSAllowsArbitraryLoads = true should produce a HIGH finding."""
        context = ats_context({"NSAllowsArbitraryLoads": True})
        findings = self.detector.analyze(context)

        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_findings) == 1
        assert "disabled globally" in high_findings[0].title.lower()

    def test_allows_arbitrary_loads_false(self, ats_context):
        """NSAllowsArbitraryLoads = false should produce no HIGH findings."""
        context = ats_context({"NSAllowsArbitraryLoads": False})
        findings = self.detector.analyze(context)

        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_findings) == 0

    def test_allows_arbitrary_loads_in_web_content(self, ats_context):
        """NSAllowsArbitraryLoadsInWebContent = true should produce MEDIUM."""
        context = ats_context({"NSAllowsArbitraryLoadsInWebContent": True})
        findings = self.detector.analyze(context)

        medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium_findings) == 1
        assert "web content" in medium_findings[0].title.lower()

    def test_exception_domain_insecure_http(self, ats_context):
        """Per-domain NSExceptionAllowsInsecureHTTPLoads should produce MEDIUM."""
        context = ats_context(
            {
                "NSExceptionDomains": {
                    "example.com": {"NSExceptionAllowsInsecureHTTPLoads": True},
                }
            }
        )
        findings = self.detector.analyze(context)

        medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium_findings) == 1
        assert "example.com" in medium_findings[0].title

    def test_third_party_exception_insecure_http(self, ats_context):
        """NSThirdPartyExceptionAllowsInsecureHTTPLoads should produce LOW."""
        context = ats_context(
            {
                "NSExceptionDomains": {
                    "cdn.example.com": {
                        "NSThirdPartyExceptionAllowsInsecureHTTPLoads": True,
                    },
                }
            }
        )
        findings = self.detector.analyze(context)

        low_findings = [f for f in findings if f.severity == Severity.LOW]
        assert len(low_findings) == 1
        assert "cdn.example.com" in low_findings[0].title

    def test_allows_local_networking(self, ats_context):
        """NSAllowsLocalNetworking = true should produce INFO."""
        context = ats_context({"NSAllowsLocalNetworking": True})
        findings = self.detector.analyze(context)

        info_findings = [f for f in findings if f.severity == Severity.INFO]
        assert len(info_findings) == 1
        assert "local" in info_findings[0].title.lower()

    def test_multiple_issues(self, ats_context):
        """Multiple ATS misconfigurations should produce multiple findings."""
        context = ats_context(
            {
                "NSAllowsArbitraryLoads": True,
                "NSAllowsLocalNetworking": True,
                "NSExceptionDomains": {
                    "api.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True},
                },
            }
        )
        findings = self.detector.analyze(context)
        assert len(findings) == 3
