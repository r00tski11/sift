"""Weak cryptography and hardcoded encryption key detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ipa_analyzer.detectors.base import BaseDetector, Finding, Severity
from ipa_analyzer.utils.entropy import shannon_entropy

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext

# Weak crypto indicators: category -> (symbols, severity, remediation)
WEAK_CRYPTO_INDICATORS: dict[str, tuple[list[str], Severity, str]] = {
    "MD5": (
        ["CC_MD5", "MD5_Init", "MD5_Update", "MD5_Final", "kCCHmacAlgMD5"],
        Severity.MEDIUM,
        "Replace MD5 with SHA-256 or SHA-3 for security-sensitive operations",
    ),
    "SHA-1": (
        ["CC_SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final", "kCCHmacAlgSHA1"],
        Severity.MEDIUM,
        "Replace SHA-1 with SHA-256 or SHA-3",
    ),
    "DES": (
        ["kCCAlgorithmDES", "DES_ecb_encrypt", "kCCAlgorithm3DES"],
        Severity.HIGH,
        "Replace DES/3DES with AES-256",
    ),
    "ECB Mode": (
        ["kCCOptionECBMode"],
        Severity.HIGH,
        "Use CBC or GCM mode instead of ECB; ECB does not provide semantic security",
    ),
}

# Context indicators for hardcoded encryption keys
CRYPTO_CONTEXT_KEYWORDS = [
    "encrypt",
    "decrypt",
    "cipher",
    "aes",
    "key",
    "crypto",
    "kCCAlgorithm",
    "CCCrypt",
    "SecKey",
]

KEY_ENTROPY_THRESHOLD = 4.0
KEY_MIN_LENGTH = 16


class CryptoDetector(BaseDetector):
    """Detects weak cryptography usage and hardcoded encryption keys."""

    name = "crypto"
    description = "Checks for weak crypto algorithms and hardcoded encryption keys"
    owasp_category = "M10"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Scan binary strings for weak crypto and hardcoded keys.

        Args:
            context: Analysis context with binary_strings populated.

        Returns:
            List of findings for crypto issues.
        """
        findings: list[Finding] = []
        location = f"Payload/{context.app_bundle_path.name}/{context.binary_path.name}"

        self._check_weak_crypto(context.binary_strings, location, findings)
        self._check_hardcoded_keys(context.binary_strings, location, findings)

        return findings

    def _check_weak_crypto(
        self,
        strings: list[str],
        location: str,
        findings: list[Finding],
    ) -> None:
        # Track which categories have been found to deduplicate
        found_categories: dict[str, list[str]] = {}

        for string in strings:
            for category, (symbols, _, _) in WEAK_CRYPTO_INDICATORS.items():
                if category in found_categories:
                    # Already found this category, just track extra symbols
                    for symbol in symbols:
                        if symbol in string and symbol not in found_categories[category]:
                            found_categories[category].append(symbol)
                else:
                    for symbol in symbols:
                        if symbol in string:
                            found_categories[category] = [symbol]
                            break

        for category, matched_symbols in found_categories.items():
            _, severity, remediation = WEAK_CRYPTO_INDICATORS[category]
            findings.append(
                Finding(
                    detector=self.name,
                    severity=severity,
                    title=f"Weak cryptography: {category} usage detected",
                    description=(
                        f"The binary contains references to {category}, which is "
                        f"considered cryptographically weak for security purposes."
                    ),
                    location=location,
                    evidence=f"Symbols found: {', '.join(matched_symbols)}",
                    owasp="M10 - Insufficient Cryptography",
                    remediation=remediation,
                    cwe_id=327,
                )
            )

    def _check_hardcoded_keys(
        self,
        strings: list[str],
        location: str,
        findings: list[Finding],
    ) -> None:
        seen_keys: set[str] = set()

        for i, string in enumerate(strings):
            lower = string.lower()
            has_crypto_context = any(kw in lower for kw in CRYPTO_CONTEXT_KEYWORDS)
            if not has_crypto_context:
                continue

            # Check nearby strings (current and next few) for high-entropy values
            for nearby in strings[max(0, i - 2) : i + 3]:
                if len(nearby) < KEY_MIN_LENGTH or nearby in seen_keys:
                    continue
                entropy = shannon_entropy(nearby)
                if entropy >= KEY_ENTROPY_THRESHOLD:
                    # Skip if it looks like a function name or common symbol
                    if nearby.startswith("_") or " " in nearby:
                        continue
                    seen_keys.add(nearby)
                    redacted = nearby[:4] + "****" + nearby[-4:] if len(nearby) > 12 else nearby
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity=Severity.HIGH,
                            title="Potential hardcoded encryption key",
                            description=(
                                f"High-entropy string (entropy: {entropy:.2f}) found "
                                f"near cryptographic function references."
                            ),
                            location=location,
                            evidence=f"Suspected key: {redacted}",
                            owasp="M10 - Insufficient Cryptography",
                            remediation=(
                                "Store encryption keys in the iOS Keychain or use "
                                "a key derivation function; never hardcode keys"
                            ),
                            cwe_id=321,
                        )
                    )
