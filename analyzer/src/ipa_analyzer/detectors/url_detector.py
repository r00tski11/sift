"""URL and endpoint analyzer detector."""

from __future__ import annotations

import re
from ipaddress import IPv4Address, ip_address, ip_network
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ipa_analyzer.detectors.base import BaseDetector, Finding, Severity

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext

URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")

PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
]

STAGING_PATTERN = re.compile(
    r"^(staging|dev|development|test|qa|uat|sandbox|internal|debug|preprod)\.",
    re.IGNORECASE,
)


def _is_private_ip(hostname: str) -> bool:
    """Check if a hostname is a private/reserved IP address."""
    try:
        addr = ip_address(hostname)
        if not isinstance(addr, IPv4Address):
            return False
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


class URLEndpointDetector(BaseDetector):
    """Extracts and classifies URLs found in binary strings."""

    name = "url_endpoints"
    description = "Analyzes URLs for insecure schemes, staging endpoints, and private IPs"
    owasp_category = "M5"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        location = f"Payload/{context.app_bundle_path.name}/{context.binary_path.name}"

        urls: set[str] = set()
        for string in context.binary_strings:
            urls.update(URL_PATTERN.findall(string))

        http_urls: list[str] = []
        staging_urls: list[str] = []
        private_ip_urls: list[str] = []
        localhost_urls: list[str] = []

        for url in urls:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            if hostname in ("localhost", "127.0.0.1"):
                localhost_urls.append(url)
            elif _is_private_ip(hostname):
                private_ip_urls.append(url)
            elif STAGING_PATTERN.match(hostname):
                staging_urls.append(url)
            elif parsed.scheme == "http":
                http_urls.append(url)

        if staging_urls:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Staging/development URLs leaked in binary",
                    description=(
                        f"Found {len(staging_urls)} staging or development URL(s) in the binary. "
                        "These expose internal infrastructure to attackers."
                    ),
                    location=location,
                    evidence="; ".join(sorted(staging_urls)[:5]),
                    owasp="M8 - Security Misconfiguration",
                    remediation=(
                        "Use build configurations to inject environment URLs. "
                        "Strip non-production URLs from release builds."
                    ),
                    cwe_id=200,
                )
            )

        if private_ip_urls:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Private IP addresses leaked in binary",
                    description=(
                        f"Found {len(private_ip_urls)} URL(s) referencing private IP addresses. "
                        "This reveals internal network topology."
                    ),
                    location=location,
                    evidence="; ".join(sorted(private_ip_urls)[:5]),
                    owasp="M8 - Security Misconfiguration",
                    remediation="Remove private IP references from production builds.",
                    cwe_id=200,
                )
            )

        if localhost_urls:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    title="Localhost references in binary",
                    description=(
                        f"Found {len(localhost_urls)} localhost URL(s). "
                        "These are likely debug artifacts left in the release build."
                    ),
                    location=location,
                    evidence="; ".join(sorted(localhost_urls)[:5]),
                    owasp="M8 - Security Misconfiguration",
                    remediation="Remove localhost references from production builds.",
                    cwe_id=200,
                )
            )

        if http_urls:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    title="Insecure HTTP URLs found in binary",
                    description=(
                        f"Found {len(http_urls)} HTTP (non-HTTPS) URL(s). "
                        "Data sent over HTTP is vulnerable to interception."
                    ),
                    location=location,
                    evidence="; ".join(sorted(http_urls)[:5]),
                    owasp="M5 - Insecure Communication",
                    remediation="Use HTTPS for all network communication.",
                    cwe_id=319,
                )
            )

        return findings
