"""Tests for the binary protections detector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.detectors.binary import (
    MH_ALLOW_STACK_EXECUTION,
    MH_NO_HEAP_EXECUTION,
    MH_PIE,
    BinaryProtectionsDetector,
)


def _mock_macho(flags: int):
    """Create a mock MachO object with given flags."""
    mock_header = MagicMock()
    mock_header.header.flags = flags
    mock_macho = MagicMock()
    mock_macho.headers = [mock_header]
    return mock_macho


class TestBinaryProtectionsDetector:
    def setup_method(self):
        self.detector = BinaryProtectionsDetector()

    @patch("ipa_analyzer.detectors.binary.MachO")
    def test_missing_pie(self, mock_macho_cls, sample_context):
        """Binary without PIE should produce a HIGH finding."""
        mock_macho_cls.return_value = _mock_macho(0)

        findings = self.detector.analyze(sample_context)

        pie_findings = [f for f in findings if "PIE" in f.title]
        assert len(pie_findings) == 1
        assert pie_findings[0].severity == Severity.HIGH

    @patch("ipa_analyzer.detectors.binary.MachO")
    def test_pie_enabled(self, mock_macho_cls, sample_context):
        """Binary with PIE should not produce a PIE finding."""
        mock_macho_cls.return_value = _mock_macho(MH_PIE)

        findings = self.detector.analyze(sample_context)

        pie_findings = [f for f in findings if "PIE" in f.title]
        assert len(pie_findings) == 0

    @patch("ipa_analyzer.detectors.binary.MachO")
    def test_stack_execution_allowed(self, mock_macho_cls, sample_context):
        """Binary with stack execution allowed should produce HIGH finding."""
        mock_macho_cls.return_value = _mock_macho(MH_PIE | MH_ALLOW_STACK_EXECUTION)

        findings = self.detector.analyze(sample_context)

        stack_findings = [f for f in findings if "Stack" in f.title or "stack" in f.title]
        assert len(stack_findings) == 1
        assert stack_findings[0].severity == Severity.HIGH

    @patch("ipa_analyzer.detectors.binary.MachO")
    def test_heap_execution_not_disabled(self, mock_macho_cls, sample_context):
        """Binary without MH_NO_HEAP_EXECUTION should produce MEDIUM finding."""
        mock_macho_cls.return_value = _mock_macho(MH_PIE)

        findings = self.detector.analyze(sample_context)

        heap_findings = [f for f in findings if "Heap" in f.title or "heap" in f.title]
        assert len(heap_findings) == 1
        assert heap_findings[0].severity == Severity.MEDIUM

    @patch("ipa_analyzer.detectors.binary.MachO")
    def test_all_protections_enabled(self, mock_macho_cls, sample_context):
        """Binary with all protections should produce no findings."""
        mock_macho_cls.return_value = _mock_macho(MH_PIE | MH_NO_HEAP_EXECUTION)

        findings = self.detector.analyze(sample_context)
        assert len(findings) == 0

    @patch("ipa_analyzer.detectors.binary.MachO")
    def test_invalid_binary_handled_gracefully(self, mock_macho_cls, sample_context):
        """Invalid binary should produce INFO finding, not crash."""
        mock_macho_cls.side_effect = ValueError("Not a Mach-O file")

        findings = self.detector.analyze(sample_context)

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "parse" in findings[0].title.lower()
