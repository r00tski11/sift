"""Entitlements and provisioning profile detector."""

from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from ipa_analyzer.detectors.base import BaseDetector, Finding, Severity

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext

# Entitlements that are sensitive in production
SENSITIVE_ENTITLEMENTS = {
    "com.apple.security.network.server": "Network server capability",
    "com.apple.security.files.all": "Access to all files",
    "com.apple.security.device.audio-input": "Audio input access",
    "com.apple.security.personal-information.addressbook": "Address book access",
    "com.apple.security.personal-information.calendars": "Calendar access",
    "com.apple.security.personal-information.location": "Location access",
    "com.apple.security.personal-information.photos-library": "Photos library access",
}


def _extract_plist_from_mobileprovision(data: bytes) -> dict | None:
    """Extract the embedded plist from a CMS-signed mobileprovision file.

    The mobileprovision file is a CMS/PKCS7 envelope containing an
    unencrypted XML plist. We extract it by finding the XML markers.

    Args:
        data: Raw bytes of the mobileprovision file.

    Returns:
        Parsed plist dict, or None if extraction fails.
    """
    try:
        xml_start = data.index(b"<?xml")
        xml_end = data.index(b"</plist>") + len(b"</plist>")
        plist_bytes = data[xml_start:xml_end]
        return plistlib.loads(plist_bytes)
    except (ValueError, plistlib.InvalidFileException):
        return None


class EntitlementsDetector(BaseDetector):
    """Checks entitlements and provisioning profile for security issues."""

    name = "entitlements"
    description = "Analyzes app entitlements for debug flags and excessive permissions"
    owasp_category = "M1"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Analyze embedded.mobileprovision for entitlement issues.

        Args:
            context: Analysis context with app_bundle_path.

        Returns:
            List of findings for entitlement issues.
        """
        findings: list[Finding] = []
        provision_path = context.app_bundle_path / "embedded.mobileprovision"

        if not provision_path.exists():
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.INFO,
                    title="No embedded.mobileprovision found",
                    description=(
                        "The app bundle does not contain embedded.mobileprovision. "
                        "This is normal for App Store signed apps (where it gets "
                        "stripped) but unusual for enterprise or ad-hoc builds."
                    ),
                    location=f"Payload/{context.app_bundle_path.name}/",
                    evidence="embedded.mobileprovision missing",
                    owasp="M1 - Improper Platform Usage",
                    remediation="Verify the app signing configuration if unexpected",
                    cwe_id=489,
                )
            )
            return findings

        provision_data = provision_path.read_bytes()
        plist = _extract_plist_from_mobileprovision(provision_data)

        if plist is None:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.INFO,
                    title="Unable to parse mobileprovision",
                    description="Could not extract plist from embedded.mobileprovision.",
                    location=f"Payload/{context.app_bundle_path.name}/embedded.mobileprovision",
                    evidence="Plist extraction failed",
                    owasp="M1 - Improper Platform Usage",
                    remediation="Check if the mobileprovision file is valid",
                    cwe_id=489,
                )
            )
            return findings

        entitlements = plist.get("Entitlements", {})
        base_location = f"Payload/{context.app_bundle_path.name}/embedded.mobileprovision"

        # Check for debug entitlements
        if entitlements.get("get-task-allow"):
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Debug entitlements enabled",
                    description=(
                        "get-task-allow is set to true, which allows debugger "
                        "attachment. This should never be enabled in production "
                        "builds as it allows runtime inspection and manipulation."
                    ),
                    location=f"{base_location} > Entitlements > get-task-allow",
                    evidence="get-task-allow = true",
                    owasp="M1 - Improper Platform Usage",
                    remediation="Use a production provisioning profile without get-task-allow",
                    cwe_id=489,
                )
            )

        # Check for wildcard keychain access
        keychain_groups = entitlements.get("keychain-access-groups", [])
        if isinstance(keychain_groups, list):
            for group in keychain_groups:
                if isinstance(group, str) and group.endswith("*"):
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity=Severity.MEDIUM,
                            title="Wildcard keychain access group",
                            description=(
                                f"Keychain access group '{group}' uses a wildcard, "
                                f"which may expose keychain items to other apps."
                            ),
                            location=f"{base_location} > Entitlements > keychain-access-groups",
                            evidence=f"keychain-access-groups contains '{group}'",
                            owasp="M1 - Improper Platform Usage",
                            remediation="Use specific keychain access group identifiers",
                            cwe_id=250,
                        )
                    )

        # Check for other sensitive entitlements
        for ent_key, ent_desc in SENSITIVE_ENTITLEMENTS.items():
            if entitlements.get(ent_key):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.LOW,
                        title=f"Sensitive entitlement: {ent_desc}",
                        description=(
                            f"The app requests the '{ent_key}' entitlement. "
                            f"Verify this permission is necessary for app functionality."
                        ),
                        location=f"{base_location} > Entitlements > {ent_key}",
                        evidence=f"{ent_key} = true",
                        owasp="M1 - Improper Platform Usage",
                        remediation=f"Remove '{ent_key}' if not required",
                        cwe_id=250,
                    )
                )

        return findings
