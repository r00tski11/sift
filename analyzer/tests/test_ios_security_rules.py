"""Tests for the iOS security expert ruleset."""

from __future__ import annotations

from pathlib import Path

from ipa_analyzer.utils.rules import load_rules

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "ios_security.yaml"


class TestIOSSecurityRulesLoad:
    def test_all_rules_load_successfully(self):
        rules = load_rules(RULES_PATH)
        assert len(rules) >= 45

    def test_all_rules_have_unique_ids(self):
        rules = load_rules(RULES_PATH)
        ids = [r.id for r in rules]
        dupes = [x for x in ids if ids.count(x) > 1]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {dupes}"

    def test_all_severity_levels_present(self):
        rules = load_rules(RULES_PATH)
        severities = {r.severity.name for r in rules}
        assert "CRITICAL" in severities
        assert "HIGH" in severities
        assert "MEDIUM" in severities
        assert "LOW" in severities
        assert "INFO" in severities


class TestIOSSecurityRulesPatterns:
    """Test representative patterns from each category."""

    def setup_method(self):
        self.rules = {r.id: r for r in load_rules(RULES_PATH)}

    def test_slack_webhook_matches(self):
        rule = self.rules["cred_slack_webhook"]
        # Build test URL from parts to avoid GitHub push protection false positive
        webhook_url = "https://hooks.slack.com/services/" + "T" + "X" * 9 + "/" + "B" + "X" * 9 + "/" + "X" * 24
        assert rule.pattern.search(webhook_url)

    def test_stripe_secret_matches(self):
        rule = self.rules["cred_stripe_secret"]
        # Build test key from parts to avoid GitHub push protection false positive
        test_key = "sk" + "_live_" + "X" * 24
        assert rule.pattern.search(test_key)

    def test_sendgrid_matches(self):
        rule = self.rules["cred_sendgrid"]
        sample = "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz01234567890abcdef"
        assert rule.pattern.search(sample)

    def test_staging_url_matches(self):
        rule = self.rules["url_staging"]
        assert rule.pattern.search("https://staging.example.com/api")
        assert rule.pattern.search("http://staging-api.example.com")

    def test_localhost_matches(self):
        rule = self.rules["url_localhost"]
        assert rule.pattern.search("http://localhost:8080/api")
        assert not rule.pattern.search("https://example.com/localhost")

    def test_nslog_sensitive_matches(self):
        rule = self.rules["log_nslog_sensitive"]
        assert rule.pattern.search('NSLog(@"User password: %@", password)')

    def test_strcpy_matches(self):
        rule = self.rules["api_strcpy"]
        assert rule.pattern.search("_strcpy")

    def test_weak_rng_matches(self):
        rule = self.rules["api_weak_rng"]
        assert rule.pattern.search("_random")
        assert rule.pattern.search("_srandom")

    def test_nsuserdefaults_sensitive_matches(self):
        rule = self.rules["storage_nsuserdefaults"]
        assert rule.pattern.search('NSUserDefaults setObject:password forKey:@"user_token"')

    def test_facebook_sdk_matches(self):
        rule = self.rules["sdk_facebook"]
        assert rule.pattern.search("FBSDKCoreKit")

    def test_cydia_detection_matches(self):
        rule = self.rules["security_jailbreak_cydia"]
        assert rule.pattern.search("/Applications/Cydia.app")

    def test_trustkit_matches(self):
        rule = self.rules["security_trustkit"]
        assert rule.pattern.search("TrustKit")

    def test_uiwebview_matches(self):
        rule = self.rules["api_uiwebview"]
        assert rule.pattern.search("UIWebView")
        assert rule.pattern.search("_OBJC_CLASS_$_UIWebView")

    def test_non_matching_clean_string(self):
        """A clean string should not match credential rules."""
        for rule_id in ["cred_slack_webhook", "cred_stripe_secret", "cred_sendgrid"]:
            rule = self.rules[rule_id]
            assert not rule.pattern.search("Hello, this is a clean string with no secrets")
