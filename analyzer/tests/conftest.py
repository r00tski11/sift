"""Shared test fixtures for IPA Analyzer tests."""

from __future__ import annotations

import plistlib
from pathlib import Path

import pytest

from ipa_analyzer.core.context import AnalysisContext


@pytest.fixture
def sample_context(tmp_path: Path) -> AnalysisContext:
    """Create a minimal AnalysisContext for testing."""
    app_dir = tmp_path / "Payload" / "Test.app"
    app_dir.mkdir(parents=True)

    plist_data = {
        "CFBundleExecutable": "Test",
        "CFBundleIdentifier": "com.test.app",
    }
    plist_path = app_dir / "Info.plist"
    with open(plist_path, "wb") as f:
        plistlib.dump(plist_data, f)

    binary_path = app_dir / "Test"
    binary_path.write_bytes(b"\x00" * 100)

    return AnalysisContext(
        ipa_path=tmp_path / "test.ipa",
        extracted_dir=tmp_path,
        app_bundle_path=app_dir,
        info_plist=plist_data,
        binary_path=binary_path,
    )


@pytest.fixture
def ats_context(sample_context: AnalysisContext):
    """Factory fixture for creating contexts with specific ATS configurations."""

    def _make(ats_config: dict) -> AnalysisContext:
        sample_context.info_plist["NSAppTransportSecurity"] = ats_config
        return sample_context

    return _make


@pytest.fixture
def strings_context(sample_context: AnalysisContext):
    """Factory fixture for creating contexts with specific binary_strings."""

    def _make(strings: list[str]) -> AnalysisContext:
        sample_context.binary_strings = strings
        return sample_context

    return _make
