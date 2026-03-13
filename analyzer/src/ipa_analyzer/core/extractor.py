"""IPA and xcarchive extraction and validation."""

from __future__ import annotations

import plistlib
import tempfile
import zipfile
from pathlib import Path

from ipa_analyzer.core.context import AnalysisContext
from ipa_analyzer.utils.exceptions import InvalidIPAError
from ipa_analyzer.utils.strings import extract_strings


def _parse_info_plist(app_bundle: Path) -> dict:
    """Parse the Info.plist from an app bundle.

    Args:
        app_bundle: Path to the .app directory.

    Returns:
        Parsed plist as a dictionary.

    Raises:
        InvalidIPAError: If Info.plist is missing or invalid.
    """
    plist_path = app_bundle / "Info.plist"
    if not plist_path.exists():
        raise InvalidIPAError(f"Info.plist not found in {app_bundle.name}")

    try:
        with open(plist_path, "rb") as f:
            return plistlib.load(f)
    except Exception as e:
        raise InvalidIPAError(f"Failed to parse Info.plist in {app_bundle.name}: {e}") from e


def _find_main_binary(app_bundle: Path, plist: dict) -> Path:
    """Locate the main executable binary.

    Args:
        app_bundle: Path to the .app directory.
        plist: Parsed Info.plist dictionary.

    Returns:
        Path to the main binary.

    Raises:
        InvalidIPAError: If CFBundleExecutable is missing or binary not found.
    """
    executable_name = plist.get("CFBundleExecutable")
    if not executable_name:
        raise InvalidIPAError(f"CFBundleExecutable not found in Info.plist for {app_bundle.name}")

    binary_path = app_bundle / executable_name
    if not binary_path.exists():
        raise InvalidIPAError(f"Main binary '{executable_name}' not found in {app_bundle.name}")
    return binary_path


class IPAExtractor:
    """Extracts and validates iOS IPA files.

    Use as a context manager to ensure temp directory cleanup:

        with IPAExtractor(Path("app.ipa")) as context:
            # context is an AnalysisContext
            ...
    """

    def __init__(self, ipa_path: Path) -> None:
        self.ipa_path = ipa_path
        self._temp_dir: tempfile.TemporaryDirectory | None = None

    def __enter__(self) -> AnalysisContext:
        self._temp_dir = tempfile.TemporaryDirectory()
        dest = Path(self._temp_dir.name)
        self._unzip(dest)
        app_bundle = self._locate_app_bundle(dest)
        info_plist = _parse_info_plist(app_bundle)
        binary_path = _find_main_binary(app_bundle, info_plist)
        binary_strings = extract_strings(binary_path)
        return AnalysisContext(
            ipa_path=self.ipa_path,
            extracted_dir=dest,
            app_bundle_path=app_bundle,
            info_plist=info_plist,
            binary_path=binary_path,
            binary_strings=binary_strings,
            input_type="ipa",
        )

    def __exit__(self, *args: object) -> None:
        if self._temp_dir:
            self._temp_dir.cleanup()

    def _unzip(self, dest: Path) -> None:
        """Extract IPA (zip) contents to destination directory.

        Args:
            dest: Directory to extract into.

        Raises:
            InvalidIPAError: If the file is not a valid zip or lacks Payload/.
        """
        if not self.ipa_path.exists():
            raise InvalidIPAError(f"IPA file not found: {self.ipa_path}")

        try:
            with zipfile.ZipFile(self.ipa_path, "r") as zf:
                zf.extractall(dest)
        except zipfile.BadZipFile as e:
            raise InvalidIPAError(
                f"Invalid IPA file (not a valid zip archive): {self.ipa_path}"
            ) from e

        payload_dir = dest / "Payload"
        if not payload_dir.is_dir():
            found = [p.name for p in dest.iterdir()]
            raise InvalidIPAError(
                f"Invalid IPA structure: missing Payload directory. "
                f"Found top-level entries: {found}"
            )

    def _locate_app_bundle(self, extracted_dir: Path) -> Path:
        """Find the .app bundle inside Payload/.

        Args:
            extracted_dir: Root of extracted IPA contents.

        Returns:
            Path to the .app directory.

        Raises:
            InvalidIPAError: If no .app bundle is found.
        """
        payload_dir = extracted_dir / "Payload"
        app_bundles = list(payload_dir.glob("*.app"))
        if not app_bundles:
            raise InvalidIPAError(
                f"No .app bundle found in Payload/. "
                f"Contents: {[p.name for p in payload_dir.iterdir()]}"
            )
        return app_bundles[0]


class XCArchiveExtractor:
    """Extracts and validates .xcarchive build directories.

    An .xcarchive contains Products/Applications/MyApp.app/ which is
    structurally identical to the .app bundle inside an IPA's Payload/.

    Use as a context manager:

        with XCArchiveExtractor(Path("MyApp.xcarchive")) as context:
            # context is an AnalysisContext
            ...
    """

    def __init__(self, archive_path: Path) -> None:
        self.archive_path = archive_path

    def __enter__(self) -> AnalysisContext:
        app_bundle = self._locate_app_bundle()
        info_plist = _parse_info_plist(app_bundle)
        binary_path = _find_main_binary(app_bundle, info_plist)
        binary_strings = extract_strings(binary_path)
        return AnalysisContext(
            ipa_path=self.archive_path,
            extracted_dir=self.archive_path,
            app_bundle_path=app_bundle,
            info_plist=info_plist,
            binary_path=binary_path,
            binary_strings=binary_strings,
            input_type="xcarchive",
        )

    def __exit__(self, *args: object) -> None:
        # No temp dir to clean up — xcarchive is already on disk
        pass

    def _locate_app_bundle(self) -> Path:
        """Find the .app bundle inside Products/Applications/.

        Returns:
            Path to the .app directory.

        Raises:
            InvalidIPAError: If the expected structure is missing.
        """
        if not self.archive_path.is_dir():
            raise InvalidIPAError(f"xcarchive path is not a directory: {self.archive_path}")

        products_dir = self.archive_path / "Products" / "Applications"
        if not products_dir.is_dir():
            raise InvalidIPAError(
                f"Invalid xcarchive structure: missing Products/Applications/ "
                f"in {self.archive_path.name}"
            )

        app_bundles = list(products_dir.glob("*.app"))
        if not app_bundles:
            raise InvalidIPAError(
                f"No .app bundle found in Products/Applications/ of {self.archive_path.name}"
            )
        return app_bundles[0]


class SourceExtractor:
    """Extracts a .zip archive of Swift/iOS source code for static analysis.

    Creates a minimal AnalysisContext with source_dir set, suitable for
    source-only detectors like SemgrepDetector.

    Use as a context manager:

        with SourceExtractor(Path("project.zip")) as context:
            # context.source_dir points to extracted source
            ...
    """

    def __init__(self, zip_path: Path) -> None:
        self.zip_path = zip_path
        self._temp_dir: tempfile.TemporaryDirectory | None = None

    def __enter__(self) -> AnalysisContext:
        if not self.zip_path.exists():
            raise InvalidIPAError(f"Source zip not found: {self.zip_path}")

        self._temp_dir = tempfile.TemporaryDirectory()
        dest = Path(self._temp_dir.name)

        try:
            with zipfile.ZipFile(self.zip_path, "r") as zf:
                zf.extractall(dest)
        except zipfile.BadZipFile as e:
            raise InvalidIPAError(
                f"Invalid zip archive: {self.zip_path}"
            ) from e

        # If the zip contains a single top-level directory, use that as source_dir
        top_entries = [p for p in dest.iterdir() if not p.name.startswith(".")]
        if len(top_entries) == 1 and top_entries[0].is_dir():
            source_dir = top_entries[0]
        else:
            source_dir = dest

        return AnalysisContext(
            ipa_path=self.zip_path,
            extracted_dir=dest,
            app_bundle_path=dest,
            info_plist={},
            binary_path=self.zip_path,
            binary_strings=[],
            input_type="source",
            source_dir=source_dir,
        )

    def __exit__(self, *args: object) -> None:
        if self._temp_dir:
            self._temp_dir.cleanup()


def create_extractor(input_path: Path) -> IPAExtractor | XCArchiveExtractor | SourceExtractor:
    """Factory function to create the appropriate extractor based on input type.

    Args:
        input_path: Path to an .ipa file, .xcarchive directory, or .zip source archive.

    Returns:
        An IPAExtractor, XCArchiveExtractor, or SourceExtractor instance.

    Raises:
        InvalidIPAError: If the input type cannot be determined.
    """
    if input_path.is_dir() and input_path.suffix == ".xcarchive":
        return XCArchiveExtractor(input_path)
    if input_path.is_file() and input_path.suffix == ".ipa":
        return IPAExtractor(input_path)
    if input_path.is_file() and input_path.suffix == ".zip":
        return SourceExtractor(input_path)
    # Try to be helpful about what went wrong
    if input_path.is_dir():
        raise InvalidIPAError(
            f"Directory '{input_path.name}' is not a .xcarchive bundle. "
            f"Expected a .xcarchive directory, .ipa file, or .zip source archive."
        )
    raise InvalidIPAError(
        f"Unsupported input: '{input_path.name}'. "
        f"Provide a .ipa file, .xcarchive directory, or .zip source archive."
    )
