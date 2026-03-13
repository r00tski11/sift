"""Tests for the custom rules detector."""

from __future__ import annotations

import re

from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.detectors.custom import CustomRulesDetector
from ipa_analyzer.utils.rules import CustomRule


def _make_rule(**kwargs) -> CustomRule:
    defaults = {
        "id": "test_001",
        "name": "Test Rule",
        "pattern": re.compile("test_pattern"),
        "severity": Severity.MEDIUM,
        "description": "A test rule",
        "owasp": "M9",
        "cwe_id": 798,
        "remediation": "Fix it",
    }
    defaults.update(kwargs)
    return CustomRule(**defaults)


class TestCustomRulesDetector:
    def test_matching_rule(self, strings_context):
        rule = _make_rule(pattern=re.compile(r"internal\.api\.com"))
        detector = CustomRulesDetector(rules=[rule])
        context = strings_context(["https://internal.api.com/v2"])
        findings = detector.analyze(context)
        assert len(findings) == 1
        assert findings[0].title == "Test Rule"

    def test_non_matching_rule(self, strings_context):
        rule = _make_rule(pattern=re.compile(r"internal\.api\.com"))
        detector = CustomRulesDetector(rules=[rule])
        context = strings_context(["https://public.api.com/v2"])
        findings = detector.analyze(context)
        assert len(findings) == 0

    def test_multiple_rules(self, strings_context):
        rule1 = _make_rule(id="r1", name="Rule 1", pattern=re.compile(r"secret"))
        rule2 = _make_rule(id="r2", name="Rule 2", pattern=re.compile(r"password"))
        rule3 = _make_rule(id="r3", name="Rule 3", pattern=re.compile(r"missing"))
        detector = CustomRulesDetector(rules=[rule1, rule2, rule3])
        context = strings_context(["my_secret_value", "user_password_hash"])
        findings = detector.analyze(context)
        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert "Rule 1" in titles
        assert "Rule 2" in titles

    def test_empty_rules(self, strings_context):
        detector = CustomRulesDetector(rules=[])
        context = strings_context(["anything"])
        findings = detector.analyze(context)
        assert len(findings) == 0
