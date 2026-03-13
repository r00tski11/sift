"""App Transport Security (ATS) detector - analyzes Info.plist ATS configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ipa_analyzer.detectors.base import BaseDetector, Finding, Severity

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext


class ATSDetector(BaseDetector):
    """Analyzes App Transport Security configuration in Info.plist."""

    name = "ats"
    description = "Checks App Transport Security settings for insecure configurations"
    owasp_category = "M5"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Analyze ATS configuration from Info.plist.

        Args:
            context: Analysis context with parsed info_plist.

        Returns:
            List of findings for insecure ATS configurations.
        """
        findings: list[Finding] = []
        plist = context.info_plist
        base_location = "Info.plist > NSAppTransportSecurity"

        ats = plist.get("NSAppTransportSecurity")
        if ats is None:
            # ATS is enabled by default on iOS 9+; no config means secure defaults.
            return findings

        if ats.get("NSAllowsArbitraryLoads"):
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="App Transport Security is disabled globally",
                    description=(
                        "NSAllowsArbitraryLoads is set to true, which disables ATS "
                        "for all network connections. This allows plaintext HTTP traffic "
                        "and connections to servers with invalid certificates."
                    ),
                    location=f"{base_location} > NSAllowsArbitraryLoads",
                    evidence="NSAllowsArbitraryLoads = true",
                    owasp="M5 - Insecure Communication",
                    remediation=(
                        "Remove NSAllowsArbitraryLoads or set to false. "
                        "Use NSExceptionDomains for specific domains that require HTTP."
                    ),
                    cwe_id=319,
                )
            )

        if ats.get("NSAllowsArbitraryLoadsInWebContent"):
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    title="ATS disabled for web content",
                    description=(
                        "NSAllowsArbitraryLoadsInWebContent is set to true, disabling "
                        "ATS for content loaded in web views. This allows web views to "
                        "load insecure HTTP content."
                    ),
                    location=f"{base_location} > NSAllowsArbitraryLoadsInWebContent",
                    evidence="NSAllowsArbitraryLoadsInWebContent = true",
                    owasp="M5 - Insecure Communication",
                    remediation="Remove NSAllowsArbitraryLoadsInWebContent or set to false",
                    cwe_id=319,
                )
            )

        if ats.get("NSAllowsLocalNetworking"):
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.INFO,
                    title="Local networking allowed without ATS",
                    description=(
                        "NSAllowsLocalNetworking is enabled. This is common in debug builds "
                        "but should be removed for production releases."
                    ),
                    location=f"{base_location} > NSAllowsLocalNetworking",
                    evidence="NSAllowsLocalNetworking = true",
                    owasp="M5 - Insecure Communication",
                    remediation="Remove NSAllowsLocalNetworking for production builds",
                    cwe_id=319,
                )
            )

        # Check per-domain exceptions
        exception_domains = ats.get("NSExceptionDomains", {})
        for domain, config in exception_domains.items():
            if not isinstance(config, dict):
                continue

            if config.get("NSExceptionAllowsInsecureHTTPLoads"):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.MEDIUM,
                        title=f"Insecure HTTP allowed for domain: {domain}",
                        description=(
                            f"NSExceptionAllowsInsecureHTTPLoads is true for '{domain}', "
                            f"allowing plaintext HTTP connections to this domain."
                        ),
                        location=f"{base_location} > NSExceptionDomains > {domain}",
                        evidence=f"NSExceptionAllowsInsecureHTTPLoads = true for {domain}",
                        owasp="M5 - Insecure Communication",
                        remediation=f"Use HTTPS for {domain} and remove the exception",
                        cwe_id=319,
                    )
                )

            if config.get("NSThirdPartyExceptionAllowsInsecureHTTPLoads"):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.LOW,
                        title=f"Third-party insecure HTTP allowed for domain: {domain}",
                        description=(
                            f"NSThirdPartyExceptionAllowsInsecureHTTPLoads is true for "
                            f"'{domain}', allowing third-party frameworks to use HTTP."
                        ),
                        location=f"{base_location} > NSExceptionDomains > {domain}",
                        evidence=(
                            f"NSThirdPartyExceptionAllowsInsecureHTTPLoads = true for {domain}"
                        ),
                        owasp="M5 - Insecure Communication",
                        remediation=f"Ensure {domain} supports HTTPS and remove the exception",
                        cwe_id=319,
                    )
                )

        return findings
