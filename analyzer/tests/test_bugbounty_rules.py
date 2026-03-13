"""Tests for the bug bounty ruleset."""

from __future__ import annotations

from pathlib import Path

from ipa_analyzer.utils.rules import load_rules

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "ios_bugbounty.yaml"
BASE_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "ios_security.yaml"


class TestBugBountyRulesLoad:
    def test_all_rules_load_successfully(self):
        rules = load_rules(RULES_PATH)
        assert len(rules) >= 70, f"Expected >=70 rules, got {len(rules)}"

    def test_all_rules_have_unique_ids(self):
        rules = load_rules(RULES_PATH)
        ids = [r.id for r in rules]
        dupes = [x for x in ids if ids.count(x) > 1]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {dupes}"

    def test_no_overlap_with_base_rules(self):
        base_rules = load_rules(BASE_RULES_PATH)
        bb_rules = load_rules(RULES_PATH)
        base_ids = {r.id for r in base_rules}
        bb_ids = {r.id for r in bb_rules}
        overlap = base_ids & bb_ids
        assert not overlap, f"Overlapping IDs: {overlap}"

    def test_all_severity_levels_present(self):
        rules = load_rules(RULES_PATH)
        severities = {r.severity.name for r in rules}
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert level in severities, f"Missing severity: {level}"


class TestBugBountyRulesPatterns:
    @classmethod
    def setup_class(cls):
        rules = load_rules(RULES_PATH)
        cls.rules = {r.id: r for r in rules}

    def test_aws_access_key(self):
        rule = self.rules["bb_aws_access_key"]
        assert rule.pattern.search("AKIAIOSFODNN7EXAMPLE")
        assert not rule.pattern.search("AKIASHORT")

    def test_gcp_api_key(self):
        rule = self.rules["bb_gcp_api_key"]
        assert rule.pattern.search("AIzaSyA1234567890abcdefghijklmnopqrstuv")

    def test_firebase_url(self):
        rule = self.rules["bb_firebase_db_url"]
        assert rule.pattern.search("https://myapp-12345.firebaseio.com")

    def test_pem_private_key(self):
        rule = self.rules["bb_private_key_pem"]
        assert rule.pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert rule.pattern.search("-----BEGIN PRIVATE KEY-----")

    def test_jwt_hardcoded(self):
        rule = self.rules["bb_jwt_hardcoded"]
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        assert rule.pattern.search(jwt)

    def test_ssl_selfsigned(self):
        rule = self.rules["bb_ssl_selfsigned_accept"]
        assert rule.pattern.search("allowInvalidCertificates")
        assert rule.pattern.search("trustAllCertificates")

    def test_webview_universal_access(self):
        rule = self.rules["bb_webview_universal_file_access"]
        assert rule.pattern.search("allowUniversalAccessFromFileURLs")

    def test_file_protection_none(self):
        rule = self.rules["bb_file_protection_none"]
        assert rule.pattern.search("NSFileProtectionNone")
        assert rule.pattern.search(".noFileProtection")

    def test_biometric_bool_bypass(self):
        rule = self.rules["bb_biometric_bool_bypass"]
        assert rule.pattern.search("LAContext().evaluatePolicy")

    def test_graphql_endpoint(self):
        rule = self.rules["bb_graphql_endpoint"]
        assert rule.pattern.search("/graphql")
        assert rule.pattern.search("introspectionQuery")

    def test_connection_string(self):
        rule = self.rules["bb_connection_string"]
        assert rule.pattern.search("mongodb://user:pass@host:27017/db")
        assert rule.pattern.search("redis://localhost:6379")

    def test_ptrace_antidebug(self):
        rule = self.rules["bb_antidebug_ptrace"]
        assert rule.pattern.search("ptrace(PT_DENY_ATTACH")

    def test_hardcoded_pin(self):
        rule = self.rules["bb_hardcoded_pin_otp"]
        assert rule.pattern.search("pin = '1234'")
        assert rule.pattern.search("otp: '123456'")

    def test_non_matching_clean_string(self):
        for rule in self.rules.values():
            assert not rule.pattern.search("completely normal safe string")
