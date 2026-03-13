"""Rich console reporter for displaying analysis findings."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ipa_analyzer.core.context import AnalysisContext
from ipa_analyzer.detectors.base import Finding, Severity
from ipa_analyzer.reporters.base import BaseReporter
from ipa_analyzer.utils.scoring import calculate_risk_score

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


class ConsoleReporter(BaseReporter):
    """Renders analysis findings to the terminal using rich."""

    def __init__(self, console: Console | None = None, verbose: bool = False) -> None:
        self.console = console or Console()
        self.verbose = verbose

    def report(self, context: AnalysisContext, findings: list[Finding]) -> None:
        """Print a formatted report of all findings.

        Args:
            context: The analysis context (for app metadata).
            findings: List of findings to display.
        """
        self._print_header(context)
        self._print_risk_score(findings)
        self._print_summary(findings)

        sorted_findings = sorted(findings, key=lambda f: f.severity.value, reverse=True)
        for finding in sorted_findings:
            self._print_finding(finding)

        self._print_verdict(findings)

    def _print_header(self, context: AnalysisContext) -> None:
        header_text = Text()
        header_text.append("iOS IPA Security Analysis\n", style="bold")
        header_text.append(f"App: {context.app_name}\n")
        header_text.append(f"IPA: {context.ipa_path}")
        self.console.print(Panel(header_text, title="IPA Analyzer", border_style="blue"))

    def _print_risk_score(self, findings: list[Finding]) -> None:
        risk = calculate_risk_score(findings)
        grade_styles = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
        style = grade_styles.get(risk.grade, "bold")
        self.console.print()
        self.console.print(f"  Risk Score: [{style}]{risk.score}/100 (Grade: {risk.grade})[/]")

    def _print_summary(self, findings: list[Finding]) -> None:
        if not findings:
            self.console.print("\n[green]No security findings detected.[/]\n")
            return

        counts = Counter(f.severity for f in findings)
        table = Table(title=f"Summary: {len(findings)} finding(s)")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        for severity in Severity:
            count = counts.get(severity, 0)
            if count > 0:
                style = SEVERITY_STYLES[severity]
                table.add_row(f"[{style}]{severity.name}[/]", str(count))

        self.console.print()
        self.console.print(table)
        self.console.print()

    def _print_finding(self, finding: Finding) -> None:
        style = SEVERITY_STYLES[finding.severity]
        badge = f"[{style}]{finding.severity.name}[/]"

        content = Text()
        content.append(f"{finding.description}\n\n", style="default")
        content.append("Location: ", style="bold")
        content.append(f"{finding.location}\n")
        content.append("Evidence: ", style="bold")
        content.append(f"{finding.evidence}\n")
        content.append("OWASP: ", style="bold")
        content.append(f"{finding.owasp}\n")
        content.append("CWE: ", style="bold")
        content.append(f"CWE-{finding.cwe_id}\n")

        if self.verbose or finding.severity.value >= Severity.HIGH.value:
            content.append("Remediation: ", style="bold")
            content.append(f"{finding.remediation}")

        title = f"{badge} {finding.title}"
        self.console.print(Panel(content, title=title, border_style=style.split()[-1]))

    def _print_verdict(self, findings: list[Finding]) -> None:
        high_or_above = [f for f in findings if f.severity.value >= Severity.HIGH.value]
        self.console.print()
        if high_or_above:
            self.console.print(
                f"[bold red]FAIL[/] - {len(high_or_above)} HIGH or CRITICAL finding(s)"
            )
        else:
            self.console.print("[bold green]PASS[/] - No HIGH or CRITICAL findings")
        self.console.print()
