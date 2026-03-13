"""Tests for binary string extraction."""

from __future__ import annotations

from pathlib import Path

from ipa_analyzer.utils.strings import extract_strings


class TestExtractStrings:
    def test_extracts_embedded_strings(self, tmp_path: Path):
        """Strings surrounded by null bytes should be extracted."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x00\x00Hello World\x00\x00")
        result = extract_strings(binary)
        assert "Hello World" in result

    def test_min_length_filtering(self, tmp_path: Path):
        """Strings shorter than min_length should be excluded."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x00ab\x00abcdef\x00")
        result = extract_strings(binary, min_length=4)
        assert "ab" not in result
        assert "abcdef" in result

    def test_empty_file(self, tmp_path: Path):
        """Empty file should return no strings."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"")
        result = extract_strings(binary)
        assert result == []

    def test_all_printable(self, tmp_path: Path):
        """Entirely printable file should return one string."""
        binary = tmp_path / "test_binary"
        content = b"This is all printable text"
        binary.write_bytes(content)
        result = extract_strings(binary)
        assert len(result) == 1
        assert result[0] == "This is all printable text"

    def test_multiple_strings(self, tmp_path: Path):
        """Multiple strings separated by non-printable bytes."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"first string\x00\x01second string\x00third string")
        result = extract_strings(binary)
        assert "first string" in result
        assert "second string" in result
        assert "third string" in result

    def test_chunk_boundary_spanning(self, tmp_path: Path):
        """Strings spanning chunk boundaries should be extracted intact."""
        from ipa_analyzer.utils.strings import CHUNK_SIZE

        binary = tmp_path / "test_binary"
        # Place a string right at the chunk boundary
        padding = b"\x00" * (CHUNK_SIZE - 5)
        test_string = b"ABCDEFGHIJ"  # 10 bytes, spans the boundary
        binary.write_bytes(padding + test_string + b"\x00")
        result = extract_strings(binary)
        assert "ABCDEFGHIJ" in result

    def test_only_short_strings(self, tmp_path: Path):
        """File with only short strings should return empty list."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x00ab\x00cd\x00ef\x00")
        result = extract_strings(binary, min_length=4)
        assert result == []
