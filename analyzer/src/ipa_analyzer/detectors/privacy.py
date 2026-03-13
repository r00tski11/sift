"""Privacy manifest and usage description detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ipa_analyzer.detectors.base import BaseDetector, Finding, Severity

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext

# Common NS*UsageDescription keys and their human-readable names
PRIVACY_DESCRIPTION_KEYS: dict[str, str] = {
    "NSCameraUsageDescription": "Camera",
    "NSMicrophoneUsageDescription": "Microphone",
    "NSLocationWhenInUseUsageDescription": "Location (When In Use)",
    "NSLocationAlwaysUsageDescription": "Location (Always)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Location (Always and When In Use)",
    "NSPhotoLibraryUsageDescription": "Photo Library",
    "NSPhotoLibraryAddUsageDescription": "Photo Library (Add Only)",
    "NSContactsUsageDescription": "Contacts",
    "NSCalendarsUsageDescription": "Calendars",
    "NSFaceIDUsageDescription": "Face ID",
    "NSHealthShareUsageDescription": "HealthKit",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth",
    "NSMotionUsageDescription": "Motion",
    "NSSpeechRecognitionUsageDescription": "Speech Recognition",
    "NSAppleMusicUsageDescription": "Media Library",
}

MIN_DESCRIPTION_LENGTH = 10


class PrivacyDetector(BaseDetector):
    """Checks privacy manifest and usage description compliance."""

    name = "privacy"
    description = "Validates privacy manifest and usage description quality"
    owasp_category = "M6"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Check for privacy manifest and usage description issues.

        Args:
            context: Analysis context with info_plist and app_bundle_path.

        Returns:
            List of findings for privacy issues.
        """
        findings: list[Finding] = []

        self._check_privacy_manifest(context, findings)
        self._check_usage_descriptions(context, findings)

        return findings

    def _check_privacy_manifest(
        self,
        context: AnalysisContext,
        findings: list[Finding],
    ) -> None:
        """Check for the presence of PrivacyInfo.xcprivacy."""
        privacy_files = list(context.app_bundle_path.rglob("PrivacyInfo.xcprivacy"))
        if not privacy_files:
            findings.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    title="Missing privacy manifest (PrivacyInfo.xcprivacy)",
                    description=(
                        "No PrivacyInfo.xcprivacy file found in the app bundle. "
                        "Apple requires a privacy manifest for apps that use "
                        "certain APIs or third-party SDKs."
                    ),
                    location=f"Payload/{context.app_bundle_path.name}/",
                    evidence="PrivacyInfo.xcprivacy not found",
                    owasp="M6 - Inadequate Privacy Controls",
                    remediation=(
                        "Add a PrivacyInfo.xcprivacy file declaring the app's "
                        "data collection and usage practices"
                    ),
                    cwe_id=359,
                )
            )

    def _check_usage_descriptions(
        self,
        context: AnalysisContext,
        findings: list[Finding],
    ) -> None:
        """Check that present NS*UsageDescription values are meaningful."""
        plist = context.info_plist

        for key, permission_name in PRIVACY_DESCRIPTION_KEYS.items():
            value = plist.get(key)
            if value is None:
                # Not present means the app doesn't request this permission
                continue

            if not isinstance(value, str) or len(value.strip()) < MIN_DESCRIPTION_LENGTH:
                findings.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.LOW,
                        title=f"Insufficient usage description for {permission_name}",
                        description=(
                            f"The {key} value is empty or too short. iOS requires "
                            f"a meaningful description explaining why the app needs "
                            f"access to {permission_name.lower()}."
                        ),
                        location=f"Info.plist > {key}",
                        evidence=f'{key} = "{value}"' if value else f"{key} = (empty)",
                        owasp="M6 - Inadequate Privacy Controls",
                        remediation=(
                            f"Provide a clear, user-facing description for {key} "
                            f"explaining why {permission_name.lower()} access is needed"
                        ),
                        cwe_id=359,
                    )
                )
