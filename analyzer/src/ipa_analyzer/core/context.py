"""Analysis context holding extracted IPA data."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AnalysisContext:
    """Shared context passed to all detectors during analysis.

    Holds paths to extracted IPA contents and parsed metadata.
    """

    ipa_path: Path
    extracted_dir: Path
    app_bundle_path: Path
    info_plist: dict
    binary_path: Path
    binary_strings: list[str] = field(default_factory=list)
    input_type: str = "ipa"
    source_dir: Path | None = None

    @property
    def app_name(self) -> str:
        """Return the app bundle name (e.g. 'MyApp' from 'MyApp.app')."""
        return self.app_bundle_path.stem
