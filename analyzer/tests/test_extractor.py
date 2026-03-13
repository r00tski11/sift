"""Tests for the IPA extractor."""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

import pytest

from ipa_analyzer.core.extractor import IPAExtractor
from ipa_analyzer.utils.exceptions import InvalidIPAError


def _create_ipa(
    ipa_path: Path,
    *,
    include_payload: bool = True,
    include_app: bool = True,
    include_plist: bool = True,
    include_binary: bool = True,
    plist_data: dict | None = None,
    app_name: str = "Test",
) -> None:
    """Helper to create a synthetic IPA zip file."""
    if plist_data is None:
        plist_data = {
            "CFBundleExecutable": app_name,
            "CFBundleIdentifier": "com.test.app",
        }

    with zipfile.ZipFile(ipa_path, "w") as zf:
        if include_payload and include_app:
            app_dir = f"Payload/{app_name}.app/"
            zf.writestr(f"{app_dir}.placeholder", "")

            if include_plist:
                plist_bytes = plistlib.dumps(plist_data)
                zf.writestr(f"{app_dir}Info.plist", plist_bytes)

            if include_binary:
                zf.writestr(f"{app_dir}{app_name}", b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        elif include_payload:
            zf.writestr("Payload/.placeholder", "")


class TestIPAExtractor:
    def test_extract_valid_ipa(self, tmp_path):
        """Valid IPA should extract successfully."""
        ipa_path = tmp_path / "valid.ipa"
        _create_ipa(ipa_path)

        with IPAExtractor(ipa_path) as context:
            assert context.app_name == "Test"
            assert context.info_plist["CFBundleIdentifier"] == "com.test.app"
            assert context.binary_path.exists()
            assert context.app_bundle_path.name == "Test.app"
            assert isinstance(context.binary_strings, list)

    def test_extract_nonexistent_file(self, tmp_path):
        """Nonexistent IPA should raise InvalidIPAError."""
        ipa_path = tmp_path / "nonexistent.ipa"

        with pytest.raises(InvalidIPAError, match="not found"):
            with IPAExtractor(ipa_path) as _:
                pass

    def test_extract_invalid_zip(self, tmp_path):
        """Non-zip file should raise InvalidIPAError."""
        ipa_path = tmp_path / "invalid.ipa"
        ipa_path.write_text("this is not a zip file")

        with pytest.raises(InvalidIPAError, match="not a valid zip"):
            with IPAExtractor(ipa_path) as _:
                pass

    def test_extract_missing_payload(self, tmp_path):
        """IPA without Payload/ should raise InvalidIPAError."""
        ipa_path = tmp_path / "nopayload.ipa"
        with zipfile.ZipFile(ipa_path, "w") as zf:
            zf.writestr("SomeOtherDir/file.txt", "content")

        with pytest.raises(InvalidIPAError, match="missing Payload"):
            with IPAExtractor(ipa_path) as _:
                pass

    def test_extract_missing_app_bundle(self, tmp_path):
        """Payload/ without .app bundle should raise InvalidIPAError."""
        ipa_path = tmp_path / "noapp.ipa"
        _create_ipa(ipa_path, include_app=False)

        with pytest.raises(InvalidIPAError, match="No .app bundle"):
            with IPAExtractor(ipa_path) as _:
                pass

    def test_extract_missing_info_plist(self, tmp_path):
        """App without Info.plist should raise InvalidIPAError."""
        ipa_path = tmp_path / "noplist.ipa"
        _create_ipa(ipa_path, include_plist=False)

        with pytest.raises(InvalidIPAError, match="Info.plist"):
            with IPAExtractor(ipa_path) as _:
                pass

    def test_extract_missing_binary(self, tmp_path):
        """App referencing nonexistent binary should raise InvalidIPAError."""
        ipa_path = tmp_path / "nobinary.ipa"
        _create_ipa(ipa_path, include_binary=False)

        with pytest.raises(InvalidIPAError, match="Main binary"):
            with IPAExtractor(ipa_path) as _:
                pass

    def test_cleanup_on_exit(self, tmp_path):
        """Temp directory should be cleaned up after context exit."""
        ipa_path = tmp_path / "cleanup.ipa"
        _create_ipa(ipa_path)

        extracted_dir = None
        with IPAExtractor(ipa_path) as context:
            extracted_dir = context.extracted_dir
            assert extracted_dir.exists()

        assert not extracted_dir.exists()
