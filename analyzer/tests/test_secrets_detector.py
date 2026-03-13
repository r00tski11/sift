"""Tests for the secrets detector."""

from __future__ import annotations

from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.detectors.secrets import SecretsDetector, _redact


class TestSecretsDetector:
    def setup_method(self):
        self.detector = SecretsDetector()

    def test_aws_access_key(self, strings_context):
        context = strings_context(["AKIAIOSFODNN7EXAMPLE"])
        findings = self.detector.analyze(context)
        aws = [f for f in findings if "AWS Access Key" in f.title]
        assert len(aws) == 1
        assert aws[0].severity == Severity.CRITICAL

    def test_google_api_key(self, strings_context):
        context = strings_context(["AIzaSyA1234567890abcdefghijklmnopqrstuv"])
        findings = self.detector.analyze(context)
        google = [f for f in findings if "Google API Key" in f.title]
        assert len(google) == 1

    def test_firebase_url(self, strings_context):
        context = strings_context(["https://myapp-12345.firebaseio.com"])
        findings = self.detector.analyze(context)
        firebase = [f for f in findings if "Firebase URL" in f.title]
        assert len(firebase) == 1
        assert firebase[0].severity == Severity.HIGH

    def test_github_token(self, strings_context):
        context = strings_context(["ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"])
        findings = self.detector.analyze(context)
        gh = [f for f in findings if "GitHub Token" in f.title]
        assert len(gh) == 1

    def test_private_key(self, strings_context):
        context = strings_context(["-----BEGIN RSA PRIVATE KEY-----"])
        findings = self.detector.analyze(context)
        pk = [f for f in findings if "Private Key" in f.title]
        assert len(pk) == 1

    def test_jwt_token(self, strings_context):
        context = strings_context(
            ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"]
        )
        findings = self.detector.analyze(context)
        jwt = [f for f in findings if "JWT Token" in f.title]
        assert len(jwt) == 1

    def test_clean_strings_no_findings(self, strings_context):
        context = strings_context(["Hello World", "normal string", "version 1.0"])
        findings = self.detector.analyze(context)
        assert len(findings) == 0

    def test_evidence_is_redacted(self, strings_context):
        context = strings_context(["AKIAIOSFODNN7EXAMPLE"])
        findings = self.detector.analyze(context)
        assert len(findings) >= 1
        # Full key should NOT appear in evidence
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].evidence
        # But first 4 chars should
        assert "AKIA" in findings[0].evidence

    def test_generic_secret_with_context(self, strings_context):
        """High-entropy string near a context indicator should be flagged."""
        context = strings_context(["api_key=aB3xZ9kL7mN2pQ4rS6tU8vW0yA1cE3g"])
        findings = self.detector.analyze(context)
        generic = [f for f in findings if "Potential hardcoded secret" in f.title]
        assert len(generic) >= 1

    def test_high_entropy_without_context_not_flagged(self, strings_context):
        """High-entropy string without context indicator should NOT be flagged."""
        context = strings_context(["aB3xZ9kL7mN2pQ4rS6tU8vW0yA1cE3g"])
        findings = self.detector.analyze(context)
        generic = [f for f in findings if "Potential hardcoded secret" in f.title]
        assert len(generic) == 0

    def test_deduplication(self, strings_context):
        """Same secret appearing multiple times should produce one finding."""
        context = strings_context(["AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"])
        findings = self.detector.analyze(context)
        aws = [f for f in findings if "AWS Access Key" in f.title]
        assert len(aws) == 1


class TestRedact:
    def test_short_string(self):
        assert _redact("AKIA1234") == "AKIA****"

    def test_long_string(self):
        result = _redact("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKIA")
        assert result.endswith("MPLE")
        assert "****" in result or "*" in result
