"""Base detector interface, Finding dataclass, and Severity enum."""

from __future__ import annotations

import abc
import uuid as _uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext


class Severity(Enum):
    """Finding severity levels, ordered by importance."""

    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class Finding:
    """A single security finding produced by a detector."""

    detector: str
    severity: Severity
    title: str
    description: str
    location: str
    evidence: str
    owasp: str
    remediation: str
    cwe_id: int
    uuid: str = field(default_factory=lambda: str(_uuid.uuid4()))
    scan_type: str = "static"


class BaseDetector(abc.ABC):
    """Abstract base class for all security detectors."""

    name: str
    description: str
    owasp_category: str

    @abc.abstractmethod
    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Run analysis and return findings.

        Args:
            context: The analysis context with extracted IPA data.

        Returns:
            List of security findings.
        """
