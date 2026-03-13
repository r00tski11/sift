"""Deprecated and unsafe API usage detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ipa_analyzer.detectors.base import BaseDetector, Finding, Severity

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext

# category -> (symbols, severity, title, description, owasp, remediation, cwe_id)
DEPRECATED_API_CATEGORIES: dict[str, tuple[list[str], Severity, str, str, str, str, int]] = {
    "banned_c_functions": (
        ["_strcpy", "_strcat", "_sprintf", "_gets", "_stpcpy", "_strncpy"],
        Severity.MEDIUM,
        "Banned C string functions detected",
        (
            "The binary contains references to unsafe C string functions "
            "that can cause buffer overflows (strcpy, strcat, sprintf, gets)."
        ),
        "M4 - Insufficient Input/Output Validation",
        "Replace with bounds-checked variants: strlcpy, strlcat, snprintf.",
        120,
    ),
    "banned_scanf": (
        ["_scanf", "_sscanf", "_fscanf", "_vscanf"],
        Severity.MEDIUM,
        "Banned scanf family functions detected",
        (
            "The binary uses scanf-family functions which can cause "
            "buffer overflows when used without width specifiers."
        ),
        "M4 - Insufficient Input/Output Validation",
        "Use fgets + parsing, or add explicit width limits to format strings.",
        676,
    ),
    "weak_rng": (
        ["_rand", "_srand", "_random", "_srandom", "_arc4random_stir"],
        Severity.MEDIUM,
        "Weak random number generator usage",
        (
            "The binary references weak/predictable random number generators. "
            "These must not be used for security-sensitive operations."
        ),
        "M7 - Insufficient Binary Protections",
        "Use SecRandomCopyBytes or arc4random_uniform for cryptographic randomness.",
        330,
    ),
    "deprecated_uiwebview": (
        ["UIWebView", "_OBJC_CLASS_$_UIWebView"],
        Severity.MEDIUM,
        "Deprecated UIWebView usage detected",
        (
            "UIWebView is deprecated since iOS 12 and has known security issues "
            "including XSS vulnerabilities and lack of modern security features."
        ),
        "M7 - Insufficient Binary Protections",
        "Migrate to WKWebView which provides better security and performance.",
        477,
    ),
    "deprecated_addressbook": (
        ["ABAddressBookCreate", "ABAddressBookCopyArrayOfAllPeople", "ABPersonCopyImageData"],
        Severity.LOW,
        "Deprecated AddressBook framework usage",
        (
            "The binary uses the legacy AddressBook framework, deprecated since iOS 9. "
            "The legacy framework lacks modern privacy protections."
        ),
        "M4 - Insufficient Input/Output Validation",
        "Migrate to the Contacts framework (CNContact) for modern privacy controls.",
        477,
    ),
    "unsafe_alloca": (
        ["_alloca", "__builtin_alloca"],
        Severity.LOW,
        "Unsafe stack allocation (alloca) detected",
        (
            "The binary uses alloca for dynamic stack allocation, which can "
            "cause stack overflow with attacker-controlled sizes."
        ),
        "M7 - Insufficient Binary Protections",
        "Use heap allocation (malloc/calloc) or fixed-size stack buffers.",
        676,
    ),
}


class DeprecatedAPIDetector(BaseDetector):
    """Detects deprecated, banned, and unsafe API usage in binaries."""

    name = "deprecated_apis"
    description = "Checks for deprecated frameworks, banned C functions, and weak RNG"
    owasp_category = "M7"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        location = f"Payload/{context.app_bundle_path.name}/{context.binary_path.name}"

        for category, (
            symbols,
            severity,
            title,
            description,
            owasp,
            remediation,
            cwe_id,
        ) in DEPRECATED_API_CATEGORIES.items():
            matched = []
            for string in context.binary_strings:
                for symbol in symbols:
                    if symbol in string and symbol not in matched:
                        matched.append(symbol)

            if matched:
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=severity,
                        title=title,
                        description=description,
                        location=location,
                        evidence=f"Symbols found: {', '.join(matched)}",
                        owasp=owasp,
                        remediation=remediation,
                        cwe_id=cwe_id,
                    )
                )

        return findings
