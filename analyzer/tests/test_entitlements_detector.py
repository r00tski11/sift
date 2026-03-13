"""Tests for the entitlements detector."""

from __future__ import annotations

import plistlib

from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.detectors.entitlements import EntitlementsDetector


def _write_mobileprovision(app_dir, entitlements: dict) -> None:
    """Write a fake mobileprovision with embedded entitlements plist."""
    plist_data = {"Entitlements": entitlements}
    plist_bytes = plistlib.dumps(plist_data)
    # Wrap in fake CMS envelope
    provision_data = b"\x00\x00CMS_HEADER\x00" + plist_bytes + b"\x00\x00CMS_FOOTER"
    (app_dir / "embedded.mobileprovision").write_bytes(provision_data)


class TestEntitlementsDetector:
    def setup_method(self):
        self.detector = EntitlementsDetector()

    def test_missing_mobileprovision(self, sample_context):
        """Missing mobileprovision should produce INFO finding."""
        findings = self.detector.analyze(sample_context)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "mobileprovision" in findings[0].title.lower()

    def test_get_task_allow_true(self, sample_context):
        """get-task-allow = true should produce HIGH finding."""
        _write_mobileprovision(
            sample_context.app_bundle_path,
            {"get-task-allow": True},
        )
        findings = self.detector.analyze(sample_context)
        debug = [f for f in findings if "Debug" in f.title or "debug" in f.title.lower()]
        assert len(debug) == 1
        assert debug[0].severity == Severity.HIGH

    def test_get_task_allow_false(self, sample_context):
        """get-task-allow = false should not produce debug finding."""
        _write_mobileprovision(
            sample_context.app_bundle_path,
            {"get-task-allow": False},
        )
        findings = self.detector.analyze(sample_context)
        debug = [f for f in findings if "Debug" in f.title or "debug" in f.title.lower()]
        assert len(debug) == 0

    def test_wildcard_keychain_access(self, sample_context):
        """Wildcard keychain access group should produce MEDIUM finding."""
        _write_mobileprovision(
            sample_context.app_bundle_path,
            {"keychain-access-groups": ["com.test.*"]},
        )
        findings = self.detector.analyze(sample_context)
        keychain = [f for f in findings if "keychain" in f.title.lower()]
        assert len(keychain) == 1
        assert keychain[0].severity == Severity.MEDIUM

    def test_specific_keychain_access(self, sample_context):
        """Specific keychain access group should not produce finding."""
        _write_mobileprovision(
            sample_context.app_bundle_path,
            {"keychain-access-groups": ["com.test.app"]},
        )
        findings = self.detector.analyze(sample_context)
        keychain = [f for f in findings if "keychain" in f.title.lower()]
        assert len(keychain) == 0

    def test_sensitive_entitlement(self, sample_context):
        """Sensitive entitlement should produce LOW finding."""
        _write_mobileprovision(
            sample_context.app_bundle_path,
            {"com.apple.security.network.server": True},
        )
        findings = self.detector.analyze(sample_context)
        sensitive = [f for f in findings if f.severity == Severity.LOW]
        assert len(sensitive) == 1
        assert "Network server" in sensitive[0].title

    def test_clean_entitlements(self, sample_context):
        """Clean entitlements should produce no findings."""
        _write_mobileprovision(
            sample_context.app_bundle_path,
            {"application-identifier": "com.test.app"},
        )
        findings = self.detector.analyze(sample_context)
        assert len(findings) == 0

    def test_invalid_mobileprovision(self, sample_context):
        """Unparseable mobileprovision should produce INFO finding."""
        (sample_context.app_bundle_path / "embedded.mobileprovision").write_bytes(
            b"not a valid provision file"
        )
        findings = self.detector.analyze(sample_context)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "parse" in findings[0].title.lower()
