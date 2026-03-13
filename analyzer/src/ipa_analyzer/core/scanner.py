"""Scanner orchestration - ties extraction, detection, and reporting together."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from ipa_analyzer.core.extractor import create_extractor
from ipa_analyzer.detectors.api_detector import DeprecatedAPIDetector
from ipa_analyzer.detectors.ats import ATSDetector
from ipa_analyzer.detectors.base import BaseDetector, Finding, Severity
from ipa_analyzer.detectors.binary import BinaryProtectionsDetector
from ipa_analyzer.detectors.crypto import CryptoDetector
from ipa_analyzer.detectors.entitlements import EntitlementsDetector
from ipa_analyzer.detectors.privacy import PrivacyDetector
from ipa_analyzer.detectors.secrets import SecretsDetector
from ipa_analyzer.detectors.url_detector import URLEndpointDetector
from ipa_analyzer.reporters.base import BaseReporter


class Scanner:
    """Orchestrates the IPA analysis pipeline.

    Extracts the IPA, runs all registered detectors, and reports findings.
    """

    def __init__(self, detectors: list[BaseDetector] | None = None) -> None:
        self.detectors = detectors or self._default_detectors()

    @staticmethod
    def _default_detectors() -> list[BaseDetector]:
        return [
            BinaryProtectionsDetector(),
            ATSDetector(),
            SecretsDetector(),
            EntitlementsDetector(),
            CryptoDetector(),
            PrivacyDetector(),
            URLEndpointDetector(),
            DeprecatedAPIDetector(),
        ]

    def scan(
        self,
        ipa_path: Path,
        reporter: BaseReporter | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
    ) -> tuple[list[Finding], str | None]:
        """Run a full security scan on an IPA or xcarchive.

        Args:
            ipa_path: Path to the .ipa file or .xcarchive directory.
            reporter: Optional reporter to render findings.
            progress_callback: Optional callback(detector_name, current, total)
                for reporting scan progress.

        Returns:
            Tuple of (findings list, report content string or None).
        """
        with create_extractor(ipa_path) as context:
            findings: list[Finding] = []
            total = len(self.detectors)

            for i, detector in enumerate(self.detectors):
                if progress_callback:
                    progress_callback(detector.name, i + 1, total)
                try:
                    findings.extend(detector.analyze(context))
                except Exception as e:
                    findings.append(
                        Finding(
                            detector=detector.name,
                            severity=Severity.INFO,
                            title=f"Detector '{detector.name}' encountered an error",
                            description=str(e),
                            location="N/A",
                            evidence=type(e).__name__,
                            owasp="N/A",
                            remediation="Check the IPA file integrity and try again",
                            cwe_id=0,
                        )
                    )

            report_content: str | None = None
            if reporter:
                report_content = reporter.report(context, findings)

            return findings, report_content
