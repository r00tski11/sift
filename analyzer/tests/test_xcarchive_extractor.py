"""Tests for the XCArchive extractor and create_extractor factory."""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

import pytest

from ipa_analyzer.core.extractor import (
    IPAExtractor,
    XCArchiveExtractor,
    create_extractor,
)
from ipa_analyzer.utils.exceptions import InvalidIPAError


def _create_xcarchive(
    base_path: Path,
    *,
    include_products: bool = True,
    include_app: bool = True,
    include_plist: bool = True,
    include_binary: bool = True,
    app_name: str = "TestApp",
) -> Path:
    """Helper to create a synthetic .xcarchive directory structure."""
    archive_path = base_path / f"{app_name}.xcarchive"
    archive_path.mkdir(parents=True, exist_ok=True)

    if include_products:
        apps_dir = archive_path / "Products" / "Applications"
        apps_dir.mkdir(parents=True, exist_ok=True)

        if include_app:
            app_dir = apps_dir / f"{app_name}.app"
            app_dir.mkdir(parents=True, exist_ok=True)

            if include_plist:
                plist_data = {
                    "CFBundleExecutable": app_name,
                    "CFBundleIdentifier": "com.test.xcarchive",
                }
                plist_path = app_dir / "Info.plist"
                with open(plist_path, "wb") as f:
                    plistlib.dump(plist_data, f)

            if include_binary:
                binary_path = app_dir / app_name
                binary_path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

    # Also create dSYMs directory (common in xcarchives)
    dsyms_dir = archive_path / "dSYMs"
    dsyms_dir.mkdir(exist_ok=True)

    return archive_path


def _create_ipa(ipa_path: Path, app_name: str = "Test") -> None:
    """Helper to create a minimal valid IPA."""
    plist_data = {
        "CFBundleExecutable": app_name,
        "CFBundleIdentifier": "com.test.app",
    }
    with zipfile.ZipFile(ipa_path, "w") as zf:
        app_dir = f"Payload/{app_name}.app/"
        zf.writestr(f"{app_dir}.placeholder", "")
        plist_bytes = plistlib.dumps(plist_data)
        zf.writestr(f"{app_dir}Info.plist", plist_bytes)
        zf.writestr(f"{app_dir}{app_name}", b"\xcf\xfa\xed\xfe" + b"\x00" * 100)


class TestXCArchiveExtractor:
    def test_extract_valid_xcarchive(self, tmp_path):
        """Valid xcarchive should extract successfully."""
        archive = _create_xcarchive(tmp_path)

        with XCArchiveExtractor(archive) as context:
            assert context.app_name == "TestApp"
            assert context.info_plist["CFBundleIdentifier"] == "com.test.xcarchive"
            assert context.binary_path.exists()
            assert context.input_type == "xcarchive"
            assert isinstance(context.binary_strings, list)

    def test_missing_products_directory(self, tmp_path):
        """Missing Products/ directory should raise error."""
        archive = _create_xcarchive(tmp_path, include_products=False)

        with pytest.raises(InvalidIPAError, match="Products/Applications"):
            with XCArchiveExtractor(archive) as _:
                pass

    def test_no_app_bundle(self, tmp_path):
        """Products/Applications/ without .app should raise error."""
        archive = _create_xcarchive(tmp_path, include_app=False)

        with pytest.raises(InvalidIPAError, match="No .app bundle"):
            with XCArchiveExtractor(archive) as _:
                pass

    def test_missing_info_plist(self, tmp_path):
        """App without Info.plist should raise error."""
        archive = _create_xcarchive(tmp_path, include_plist=False)

        with pytest.raises(InvalidIPAError, match="Info.plist"):
            with XCArchiveExtractor(archive) as _:
                pass

    def test_missing_binary(self, tmp_path):
        """App without main binary should raise error."""
        archive = _create_xcarchive(tmp_path, include_binary=False)

        with pytest.raises(InvalidIPAError, match="Main binary"):
            with XCArchiveExtractor(archive) as _:
                pass

    def test_not_a_directory(self, tmp_path):
        """File (not directory) should raise error."""
        fake = tmp_path / "NotADir.xcarchive"
        fake.write_text("not a directory")

        with pytest.raises(InvalidIPAError, match="not a directory"):
            with XCArchiveExtractor(fake) as _:
                pass

    def test_no_cleanup_needed(self, tmp_path):
        """xcarchive should persist after context exit (no temp dir)."""
        archive = _create_xcarchive(tmp_path)

        with XCArchiveExtractor(archive) as context:
            app_path = context.app_bundle_path

        # xcarchive should still exist after exiting
        assert archive.exists()
        assert app_path.exists()


class TestCreateExtractorFactory:
    def test_ipa_file_returns_ipa_extractor(self, tmp_path):
        """Factory should return IPAExtractor for .ipa files."""
        ipa_path = tmp_path / "app.ipa"
        _create_ipa(ipa_path)
        extractor = create_extractor(ipa_path)
        assert isinstance(extractor, IPAExtractor)

    def test_xcarchive_dir_returns_xcarchive_extractor(self, tmp_path):
        """Factory should return XCArchiveExtractor for .xcarchive dirs."""
        archive = _create_xcarchive(tmp_path)
        extractor = create_extractor(archive)
        assert isinstance(extractor, XCArchiveExtractor)

    def test_unknown_file_raises_error(self, tmp_path):
        """Unknown file type should raise error."""
        unknown = tmp_path / "app.tar.gz"
        unknown.write_text("not an ipa")
        with pytest.raises(InvalidIPAError, match="Unsupported input"):
            create_extractor(unknown)

    def test_directory_without_xcarchive_suffix(self, tmp_path):
        """Directory without .xcarchive suffix should raise error."""
        some_dir = tmp_path / "mydir"
        some_dir.mkdir()
        with pytest.raises(InvalidIPAError, match="not a .xcarchive"):
            create_extractor(some_dir)

    def test_factory_ipa_works_end_to_end(self, tmp_path):
        """Factory-created IPA extractor should work as context manager."""
        ipa_path = tmp_path / "app.ipa"
        _create_ipa(ipa_path)
        with create_extractor(ipa_path) as context:
            assert context.input_type == "ipa"
            assert context.app_name == "Test"

    def test_factory_xcarchive_works_end_to_end(self, tmp_path):
        """Factory-created xcarchive extractor should work as context manager."""
        archive = _create_xcarchive(tmp_path)
        with create_extractor(archive) as context:
            assert context.input_type == "xcarchive"
            assert context.app_name == "TestApp"
