"""HAR file importer — analyzes HTTP Archive files for security issues."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ipa_analyzer.detectors.base import Finding, Severity

_SENSITIVE_HEADERS = {"authorization", "x-api-key", "cookie", "set-cookie", "x-auth-token"}
_API_KEY_PATTERN = re.compile(
    r"(?:api[_-]?key|token|secret|password|auth)=([^&\s]{8,})",
    re.IGNORECASE,
)


class HARImporter:
    """Import security findings from HAR (HTTP Archive) files."""

    def import_har(self, har_path: Path) -> list[Finding]:
        with open(har_path) as f:
            data = json.load(f)

        findings: list[Finding] = []
        entries = data.get("log", {}).get("entries", [])

        seen_hosts: set[str] = set()

        for entry in entries:
            request = entry.get("request", {})
            url = request.get("url", "")
            method = request.get("method", "GET")

            # Check for HTTP (non-HTTPS) connections
            if url.startswith("http://"):
                host = url.split("/")[2] if len(url.split("/")) > 2 else url
                if host not in seen_hosts:
                    seen_hosts.add(host)
                    findings.append(
                        Finding(
                            detector="har_import",
                            severity=Severity.MEDIUM,
                            title=f"Insecure HTTP connection to {host}",
                            description=(
                                "The app communicates over unencrypted HTTP,"
                                " exposing data to interception."
                            ),
                            location=url[:500],
                            evidence=f"{method} {url}"[:500],
                            owasp="M3 - Insecure Communication",
                            remediation="Use HTTPS for all network communications.",
                            cwe_id=319,
                            scan_type="import",
                        )
                    )

            # Check for sensitive data in headers
            headers = request.get("headers", [])
            for header in headers:
                name = header.get("name", "").lower()
                value = header.get("value", "")
                if name in _SENSITIVE_HEADERS and value:
                    findings.append(
                        Finding(
                            detector="har_import",
                            severity=Severity.HIGH,
                            title=f"Sensitive header '{name}' exposed in request",
                            description=(
                                f"The '{name}' header contains sensitive"
                                " data that could be intercepted."
                            ),
                            location=url[:500],
                            evidence=(
                                f"{name}: {value[:20]}..."[:500]
                                if len(value) > 20
                                else f"{name}: {value}"
                            ),
                            owasp="M3 - Insecure Communication",
                            remediation="Ensure sensitive headers are only sent over HTTPS.",
                            cwe_id=200,
                            scan_type="import",
                        )
                    )

            # Check for API keys in URLs
            match = _API_KEY_PATTERN.search(url)
            if match:
                findings.append(
                    Finding(
                        detector="har_import",
                        severity=Severity.HIGH,
                        title="API key or token exposed in URL",
                        description=(
                            "Sensitive credentials found in URL query"
                            " parameters, visible in logs and browser history."
                        ),
                        location=url[:500],
                        evidence=f"Found: {match.group(0)[:30]}..."[:500],
                        owasp="M9 - Reverse Engineering",
                        remediation="Pass API keys in headers, not URL parameters.",
                        cwe_id=598,
                        scan_type="import",
                    )
                )

        return findings
