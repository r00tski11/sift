"""Tests for the deprecated API detector."""

from __future__ import annotations

from ipa_analyzer.detectors.api_detector import DeprecatedAPIDetector


class TestDeprecatedAPIDetector:
    def setup_method(self):
        self.detector = DeprecatedAPIDetector()

    def test_no_deprecated_apis(self, strings_context):
        context = strings_context(["safe_function_call", "WKWebView"])
        findings = self.detector.analyze(context)
        assert len(findings) == 0

    def test_banned_c_functions(self, strings_context):
        context = strings_context(["_strcpy", "_strcat"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert findings[0].title == "Banned C string functions detected"
        assert findings[0].severity.name == "MEDIUM"
        assert "_strcpy" in findings[0].evidence
        assert "_strcat" in findings[0].evidence

    def test_weak_rng(self, strings_context):
        context = strings_context(["_rand", "_srand"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert "Weak random" in findings[0].title
        assert findings[0].cwe_id == 330

    def test_deprecated_uiwebview(self, strings_context):
        context = strings_context(["_OBJC_CLASS_$_UIWebView"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert "UIWebView" in findings[0].title
        assert findings[0].severity.name == "MEDIUM"

    def test_deprecated_addressbook(self, strings_context):
        context = strings_context(["ABAddressBookCreate"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert "AddressBook" in findings[0].title
        assert findings[0].severity.name == "LOW"

    def test_unsafe_alloca(self, strings_context):
        context = strings_context(["_alloca"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert "alloca" in findings[0].title
        assert findings[0].severity.name == "LOW"

    def test_banned_scanf(self, strings_context):
        context = strings_context(["_scanf", "_sscanf"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert "scanf" in findings[0].title

    def test_multiple_categories(self, strings_context):
        context = strings_context(
            [
                "_strcpy",
                "_rand",
                "UIWebView",
                "_alloca",
            ]
        )
        findings = self.detector.analyze(context)
        # banned_c_functions + weak_rng + deprecated_uiwebview + unsafe_alloca
        assert len(findings) == 4

    def test_deduplication_within_category(self, strings_context):
        context = strings_context(["_strcpy", "_strcpy", "_strcat", "_strcat"])
        findings = self.detector.analyze(context)
        assert len(findings) == 1
        assert "_strcpy" in findings[0].evidence
        assert "_strcat" in findings[0].evidence
