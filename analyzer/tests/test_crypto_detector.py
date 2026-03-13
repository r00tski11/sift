"""Tests for the crypto detector."""

from __future__ import annotations

from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.detectors.crypto import CryptoDetector


class TestCryptoDetector:
    def setup_method(self):
        self.detector = CryptoDetector()

    def test_md5_usage(self, strings_context):
        """CC_MD5 in strings should produce MEDIUM finding."""
        context = strings_context(["CC_MD5"])
        findings = self.detector.analyze(context)
        md5 = [f for f in findings if "MD5" in f.title]
        assert len(md5) == 1
        assert md5[0].severity == Severity.MEDIUM

    def test_sha1_usage(self, strings_context):
        """SHA1 symbols should produce MEDIUM finding."""
        context = strings_context(["CC_SHA1"])
        findings = self.detector.analyze(context)
        sha1 = [f for f in findings if "SHA-1" in f.title]
        assert len(sha1) == 1
        assert sha1[0].severity == Severity.MEDIUM

    def test_des_usage(self, strings_context):
        """DES algorithm usage should produce HIGH finding."""
        context = strings_context(["kCCAlgorithmDES"])
        findings = self.detector.analyze(context)
        des = [f for f in findings if "DES" in f.title]
        assert len(des) == 1
        assert des[0].severity == Severity.HIGH

    def test_ecb_mode(self, strings_context):
        """ECB mode usage should produce HIGH finding."""
        context = strings_context(["kCCOptionECBMode"])
        findings = self.detector.analyze(context)
        ecb = [f for f in findings if "ECB" in f.title]
        assert len(ecb) == 1
        assert ecb[0].severity == Severity.HIGH

    def test_clean_strings(self, strings_context):
        """Strings with only strong crypto should produce no findings."""
        context = strings_context(["kCCAlgorithmAES128", "SHA256", "AES-256-GCM"])
        findings = self.detector.analyze(context)
        weak = [f for f in findings if "Weak" in f.title]
        assert len(weak) == 0

    def test_deduplication(self, strings_context):
        """Same crypto category appearing multiple times -> one finding."""
        context = strings_context(["CC_MD5", "MD5_Init", "MD5_Final"])
        findings = self.detector.analyze(context)
        md5 = [f for f in findings if "MD5" in f.title]
        assert len(md5) == 1
        # Evidence should list multiple symbols
        assert "CC_MD5" in md5[0].evidence

    def test_hardcoded_key_detection(self, strings_context):
        """High-entropy string near crypto context should flag as hardcoded key."""
        context = strings_context(
            [
                "kCCAlgorithmAES128",
                "aB3xZ9kL7mN2pQ4r",  # high entropy, 16+ chars
            ]
        )
        findings = self.detector.analyze(context)
        key_findings = [f for f in findings if "hardcoded" in f.title.lower()]
        assert len(key_findings) >= 1
        assert key_findings[0].severity == Severity.HIGH

    def test_no_hardcoded_key_without_context(self, strings_context):
        """High-entropy string without crypto context should not flag."""
        context = strings_context(
            [
                "Hello World",
                "aB3xZ9kL7mN2pQ4r",
            ]
        )
        findings = self.detector.analyze(context)
        key_findings = [f for f in findings if "hardcoded" in f.title.lower()]
        assert len(key_findings) == 0
