"""Hardcoded secrets and API key detector."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ipa_analyzer.detectors.base import BaseDetector, Finding, Severity
from ipa_analyzer.utils.entropy import shannon_entropy

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext

# Known secret patterns: (compiled regex, human-readable name, remediation)
KNOWN_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "AWS Access Key": (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Rotate the exposed AWS access key immediately",
    ),
    "AWS Secret Key": (
        re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]"),
        "Remove hardcoded AWS secret key; use environment variables or AWS Secrets Manager",
    ),
    "Google API Key": (
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "Restrict or rotate the Google API key",
    ),
    "Firebase URL": (
        re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
        "Configure Firebase security rules to restrict access",
    ),
    "GitHub Token": (
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "Revoke and rotate the exposed GitHub token",
    ),
    "Private Key": (
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "Remove private keys from the app bundle; use secure key storage",
    ),
    "JWT Token": (
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "Remove hardcoded JWT tokens; fetch tokens at runtime",
    ),
}

# Context indicators for generic high-entropy secret detection
SECRET_CONTEXT_INDICATORS = re.compile(
    r"(?i)(secret|password|passwd|api_key|apikey|access_token|auth_token|"
    r"credentials|private_key|encryption_key|client_secret)"
)

ENTROPY_THRESHOLD = 4.5
GENERIC_SECRET_MIN_LENGTH = 16


def _redact(value: str) -> str:
    """Redact a secret value, showing only first 4 and last 4 characters."""
    if len(value) <= 12:
        return value[:4] + "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


class SecretsDetector(BaseDetector):
    """Detect hardcoded secrets and API keys in binary strings."""

    name = "secrets"
    description = "Detects hardcoded secrets, API keys, and credentials"
    owasp_category = "M9"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Scan binary strings for known secret patterns and high-entropy secrets.

        Args:
            context: Analysis context with binary_strings populated.

        Returns:
            List of findings for detected secrets.
        """
        findings: list[Finding] = []
        seen: set[str] = set()
        location = f"Payload/{context.app_bundle_path.name}/{context.binary_path.name}"

        for string in context.binary_strings:
            self._check_known_patterns(string, location, findings, seen)
            self._check_generic_secrets(string, location, findings, seen)

        return findings

    def _check_known_patterns(
        self,
        string: str,
        location: str,
        findings: list[Finding],
        seen: set[str],
    ) -> None:
        for pattern_name, (pattern, remediation) in KNOWN_PATTERNS.items():
            for match in pattern.finditer(string):
                matched = match.group()
                dedup_key = f"{pattern_name}:{matched}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.CRITICAL if "Key" in pattern_name else Severity.HIGH,
                        title=f"{pattern_name} found in binary",
                        description=f"Hardcoded {pattern_name.lower()} detected in the app binary.",
                        location=location,
                        evidence=_redact(matched),
                        owasp="M9 - Insecure Data Storage",
                        remediation=remediation,
                        cwe_id=798,
                    )
                )

    def _check_generic_secrets(
        self,
        string: str,
        location: str,
        findings: list[Finding],
        seen: set[str],
    ) -> None:
        if not SECRET_CONTEXT_INDICATORS.search(string):
            return

        # Split on common delimiters to find potential secret values
        parts = re.split(r'[=:"\'\s]+', string)
        for part in parts:
            if len(part) < GENERIC_SECRET_MIN_LENGTH:
                continue
            if part in seen:
                continue
            entropy = shannon_entropy(part)
            if entropy >= ENTROPY_THRESHOLD:
                seen.add(part)
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.HIGH,
                        title="Potential hardcoded secret detected",
                        description=(
                            f"High-entropy string found near a secret context indicator "
                            f"(entropy: {entropy:.2f})."
                        ),
                        location=location,
                        evidence=_redact(part),
                        owasp="M9 - Insecure Data Storage",
                        remediation="Move secrets to secure storage; do not hardcode them",
                        cwe_id=798,
                    )
                )
