"""Base reporter interface."""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipa_analyzer.core.context import AnalysisContext
    from ipa_analyzer.detectors.base import Finding


class BaseReporter(abc.ABC):
    """Abstract base class for all report formatters."""

    @abc.abstractmethod
    def report(
        self,
        context: AnalysisContext,
        findings: list[Finding],
    ) -> str | None:
        """Generate a report from analysis findings.

        Args:
            context: The analysis context (for app metadata).
            findings: List of findings to report.

        Returns:
            Report content as a string, or None for reporters that
            write directly to stdout.
        """
