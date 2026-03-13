"""Extract printable strings from binary files."""

from __future__ import annotations

from pathlib import Path

MIN_STRING_LENGTH = 4
CHUNK_SIZE = 65536


def extract_strings(
    binary_path: Path,
    min_length: int = MIN_STRING_LENGTH,
) -> list[str]:
    """Extract printable ASCII strings from a binary file.

    Reads the file in chunks to avoid loading the entire binary into
    memory. Strings that span chunk boundaries are handled by carrying
    over partial matches.

    Args:
        binary_path: Path to the binary file.
        min_length: Minimum string length to include.

    Returns:
        List of extracted printable strings.
    """
    strings: list[str] = []
    current: list[str] = []

    with open(binary_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            for byte in chunk:
                if 32 <= byte <= 126:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append("".join(current))
                    current.clear()

    # Flush any remaining buffer
    if len(current) >= min_length:
        strings.append("".join(current))

    return strings
