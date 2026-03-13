"""Tests for the privacy detector."""

from __future__ import annotations

from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.detectors.privacy import PrivacyDetector


class TestPrivacyDetector:
    def setup_method(self):
        self.detector = PrivacyDetector()

    def test_missing_privacy_manifest(self, sample_context):
        """Missing PrivacyInfo.xcprivacy should produce MEDIUM finding."""
        findings = self.detector.analyze(sample_context)
        manifest = [f for f in findings if "privacy manifest" in f.title.lower()]
        assert len(manifest) == 1
        assert manifest[0].severity == Severity.MEDIUM

    def test_present_privacy_manifest(self, sample_context):
        """Present PrivacyInfo.xcprivacy should not produce manifest finding."""
        (sample_context.app_bundle_path / "PrivacyInfo.xcprivacy").write_text(
            '<?xml version="1.0"?><plist></plist>'
        )
        findings = self.detector.analyze(sample_context)
        manifest = [f for f in findings if "privacy manifest" in f.title.lower()]
        assert len(manifest) == 0

    def test_empty_usage_description(self, sample_context):
        """Empty NS*UsageDescription should produce LOW finding."""
        sample_context.info_plist["NSCameraUsageDescription"] = ""
        findings = self.detector.analyze(sample_context)
        desc = [f for f in findings if "usage description" in f.title.lower()]
        assert len(desc) == 1
        assert desc[0].severity == Severity.LOW
        assert "Camera" in desc[0].title

    def test_short_usage_description(self, sample_context):
        """Very short description should produce LOW finding."""
        sample_context.info_plist["NSCameraUsageDescription"] = "Camera"
        findings = self.detector.analyze(sample_context)
        desc = [f for f in findings if "Camera" in f.title]
        assert len(desc) == 1
        assert desc[0].severity == Severity.LOW

    def test_proper_usage_description(self, sample_context):
        """Proper description should not produce finding."""
        sample_context.info_plist["NSCameraUsageDescription"] = (
            "We need camera access to scan QR codes for login"
        )
        findings = self.detector.analyze(sample_context)
        desc = [f for f in findings if "Camera" in f.title]
        assert len(desc) == 0

    def test_no_usage_descriptions_no_findings(self, sample_context):
        """No NS*UsageDescription keys means no description findings."""
        findings = self.detector.analyze(sample_context)
        desc = [f for f in findings if "usage description" in f.title.lower()]
        assert len(desc) == 0

    def test_multiple_empty_descriptions(self, sample_context):
        """Multiple empty descriptions should produce multiple findings."""
        sample_context.info_plist["NSCameraUsageDescription"] = ""
        sample_context.info_plist["NSMicrophoneUsageDescription"] = "Mic"
        findings = self.detector.analyze(sample_context)
        desc = [f for f in findings if "usage description" in f.title.lower()]
        assert len(desc) == 2
