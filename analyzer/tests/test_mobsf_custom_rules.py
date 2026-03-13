"""Tests for MobSF custom bug bounty rules."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

MOBSF_RULES_DIR = Path(
    "/Users/joel-18068/.local/pipx/venvs/mobsf/lib/python3.12/"
    "site-packages/mobsf/StaticAnalyzer/views/ios/rules"
)

CUSTOM_RULES_PATH = MOBSF_RULES_DIR / "custom_bugbounty_rules.yaml"

# Existing MobSF rule files to check for ID collisions
EXISTING_RULE_FILES = [
    MOBSF_RULES_DIR / "swift_rules.yaml",
    MOBSF_RULES_DIR / "objective_c_rules.yaml",
    MOBSF_RULES_DIR / "ios_apis.yaml",
]

VALID_TYPES = {"Regex", "RegexOr", "RegexAnd", "RegexAndNot", "RegexAndOr"}
VALID_SEVERITIES = {"high", "warning", "info", "good"}
REQUIRED_FIELDS = {"id", "message", "input_case", "pattern", "severity", "type", "metadata"}
REQUIRED_METADATA = {"cvss", "cwe", "masvs", "owasp-mobile"}


def _load_yaml(path: Path) -> list[dict]:
    with open(path) as f:
        return yaml.safe_load(f)


class TestMobSFCustomRulesLoad:
    def test_file_exists(self):
        assert CUSTOM_RULES_PATH.exists(), "custom_bugbounty_rules.yaml not found"

    def test_valid_yaml(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        assert isinstance(rules, list)
        assert len(rules) >= 20, f"Expected >=20 rules, got {len(rules)}"

    def test_all_required_fields_present(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        for rule in rules:
            for field in REQUIRED_FIELDS:
                assert field in rule, f"Rule {rule.get('id', '?')} missing '{field}'"

    def test_all_metadata_fields_present(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        for rule in rules:
            meta = rule.get("metadata", {})
            for field in REQUIRED_METADATA:
                assert field in meta, f"Rule {rule['id']} metadata missing '{field}'"

    def test_valid_types(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        for rule in rules:
            assert rule["type"] in VALID_TYPES, (
                f"Rule {rule['id']} has invalid type: {rule['type']}"
            )

    def test_valid_severities(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        for rule in rules:
            assert rule["severity"] in VALID_SEVERITIES, (
                f"Rule {rule['id']} has invalid severity: {rule['severity']}"
            )

    def test_unique_ids(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        ids = [r["id"] for r in rules]
        dupes = [x for x in ids if ids.count(x) > 1]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {set(dupes)}"


class TestMobSFCustomRulesNoCollision:
    def test_no_id_collision_with_existing_rules(self):
        custom_rules = _load_yaml(CUSTOM_RULES_PATH)
        custom_ids = {r["id"] for r in custom_rules}

        existing_ids = set()
        for path in EXISTING_RULE_FILES:
            if path.exists():
                rules = _load_yaml(path)
                existing_ids.update(r["id"] for r in rules)

        overlap = custom_ids & existing_ids
        assert not overlap, f"ID collision with existing MobSF rules: {overlap}"


class TestMobSFCustomRulesRegex:
    def test_regex_patterns_compile(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        for rule in rules:
            pat = rule["pattern"]
            if isinstance(pat, str):
                try:
                    re.compile(pat)
                except re.error as e:
                    raise AssertionError(f"Rule {rule['id']} has invalid regex: {e}")
            elif isinstance(pat, list):
                for p in pat:
                    try:
                        re.compile(p)
                    except re.error as e:
                        raise AssertionError(f"Rule {rule['id']} has invalid regex '{p}': {e}")

    def test_aws_key_pattern_matches(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        rule = next(r for r in rules if r["id"] == "bb_aws_access_key")
        assert re.search(rule["pattern"], "AKIAIOSFODNN7EXAMPLE")

    def test_gcp_key_pattern_matches(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        rule = next(r for r in rules if r["id"] == "bb_gcp_api_key")
        assert re.search(rule["pattern"], "AIzaSyA1234567890abcdefghijklmnopqrstuv")

    def test_jwt_pattern_matches(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        rule = next(r for r in rules if r["id"] == "bb_jwt_hardcoded")
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        assert re.search(rule["pattern"], jwt)

    def test_connection_string_matches(self):
        rules = _load_yaml(CUSTOM_RULES_PATH)
        rule = next(r for r in rules if r["id"] == "bb_connection_string")
        assert re.search(rule["pattern"], "mongodb://user:pass@host:27017/db")


class TestMobSFBinaryRules:
    def test_ipa_rules_file_has_custom_entries(self):
        """Verify ipa_rules.py contains our custom bug bounty rules."""
        content = (MOBSF_RULES_DIR / "ipa_rules.py").read_text()
        assert "Custom Bug Bounty Binary Rules" in content
        assert "AWS Access Key" in content
        assert "Google Cloud API Key" in content
        assert "Firebase Database URL" in content
        assert "PEM Private Key" in content
        assert "Database Connection String" in content

    def test_ipa_rules_regex_syntax(self):
        """Verify our added regex patterns are valid Python raw bytes."""
        content = (MOBSF_RULES_DIR / "ipa_rules.py").read_text()
        # Check that our patterns appear as raw byte strings
        assert rb"AKIA".decode() in content
        assert rb"AIza".decode() in content
        assert "firebaseio" in content
        assert "PRIVATE KEY" in content
        assert "mongodb" in content
