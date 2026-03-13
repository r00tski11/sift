"""Custom exceptions for IPA Analyzer."""


class IPAAnalyzerError(Exception):
    """Base exception for IPA Analyzer."""


class InvalidIPAError(IPAAnalyzerError):
    """Raised when IPA file is invalid or corrupted."""


class ExtractionError(IPAAnalyzerError):
    """Raised when IPA extraction fails."""


class BinaryAnalysisError(IPAAnalyzerError):
    """Raised when binary analysis encounters an error."""


class DetectorError(IPAAnalyzerError):
    """Raised when a detector fails during analysis."""
