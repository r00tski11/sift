"""CLI entry point for iOS IPA Security Analyzer."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from ipa_analyzer import __version__
from ipa_analyzer.core.scanner import Scanner
from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.reporters.console import ConsoleReporter
from ipa_analyzer.utils.exceptions import IPAAnalyzerError

REPORTER_MAP = {
    "console": "console",
    "json": "json",
    "html": "html",
    "sarif": "sarif",
}

ALL_DETECTOR_NAMES = [
    "binary_protections",
    "ats",
    "secrets",
    "entitlements",
    "crypto",
    "privacy",
    "url_endpoints",
    "deprecated_apis",
]


def _build_reporter(fmt: str, verbose: bool) -> object:
    """Create the appropriate reporter for the given format."""
    if fmt == "console":
        return ConsoleReporter(verbose=verbose)
    if fmt == "json":
        from ipa_analyzer.reporters.json_reporter import JSONReporter

        return JSONReporter()
    if fmt == "html":
        from ipa_analyzer.reporters.html import HTMLReporter

        return HTMLReporter()
    if fmt == "sarif":
        from ipa_analyzer.reporters.sarif import SARIFReporter

        return SARIFReporter()
    if fmt == "pdf":
        # PDF reporter needs output_path, handled separately in scan command
        return None
    raise click.BadParameter(f"Unknown format: {fmt}")


def _filter_detectors(checks: str | None) -> list | None:
    """Build a filtered detector list from comma-separated names, or None for all."""
    if not checks:
        return None

    from ipa_analyzer.detectors.api_detector import DeprecatedAPIDetector
    from ipa_analyzer.detectors.ats import ATSDetector
    from ipa_analyzer.detectors.binary import BinaryProtectionsDetector
    from ipa_analyzer.detectors.crypto import CryptoDetector
    from ipa_analyzer.detectors.entitlements import EntitlementsDetector
    from ipa_analyzer.detectors.privacy import PrivacyDetector
    from ipa_analyzer.detectors.secrets import SecretsDetector
    from ipa_analyzer.detectors.url_detector import URLEndpointDetector

    name_to_detector = {
        "binary_protections": BinaryProtectionsDetector,
        "ats": ATSDetector,
        "secrets": SecretsDetector,
        "entitlements": EntitlementsDetector,
        "crypto": CryptoDetector,
        "privacy": PrivacyDetector,
        "url_endpoints": URLEndpointDetector,
        "deprecated_apis": DeprecatedAPIDetector,
    }

    requested = [c.strip() for c in checks.split(",")]
    detectors = []
    for name in requested:
        if name not in name_to_detector:
            raise click.BadParameter(
                f"Unknown detector '{name}'. Available: {', '.join(name_to_detector.keys())}"
            )
        detectors.append(name_to_detector[name]())
    return detectors


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """iOS IPA Security Analyzer - Static security analysis for iOS apps and xcarchives."""


@cli.command()
@click.argument("ipa_path", type=click.Path(exists=True, path_type=Path))
@click.option("--verbose", "-v", is_flag=True, help="Show detailed remediation for all findings")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    help="Exit with code 1 if findings at this severity or above are found",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["console", "json", "html", "sarif", "pdf"], case_sensitive=False),
    default="console",
    help="Output format (default: console)",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write report to file instead of stdout",
)
@click.option(
    "--rules",
    "-r",
    "rules_paths",
    type=click.Path(exists=True, path_type=Path),
    multiple=True,
    help="Path to YAML rule files (can be repeated to stack rules)",
)
@click.option(
    "--checks",
    "-c",
    default=None,
    help="Comma-separated list of detectors to run (e.g., binary_protections,ats)",
)
def scan(
    ipa_path: Path,
    verbose: bool,
    fail_on: str | None,
    output_format: str,
    output_path: Path | None,
    rules_paths: tuple[Path, ...],
    checks: str | None,
) -> None:
    """Scan an IPA file or .xcarchive directory for security vulnerabilities."""
    console = Console()

    try:
        # PDF format requires an output path
        if output_format == "pdf" and not output_path:
            output_path = Path(ipa_path.stem + "_report.pdf")

        reporter = _build_reporter(output_format, verbose)
        detectors = _filter_detectors(checks)

        # Append custom rules detectors for each rules file provided
        if rules_paths:
            from ipa_analyzer.detectors.custom import CustomRulesDetector
            from ipa_analyzer.utils.rules import load_rules

            all_custom_rules = []
            for rp in rules_paths:
                all_custom_rules.extend(load_rules(rp))
            custom_detector = CustomRulesDetector(rules=all_custom_rules)
            if detectors is None:
                # Get default detectors then append custom
                scanner = Scanner()
                detectors = list(scanner.detectors)
            detectors.append(custom_detector)

        # PDF reporter needs special handling (writes to file directly)
        if output_format == "pdf":
            from ipa_analyzer.reporters.pdf import PDFReporter

            pdf_reporter = PDFReporter(output_path=output_path)
            scanner = Scanner(detectors=detectors)
            findings, _ = scanner.scan(ipa_path, reporter=pdf_reporter)
            console.print(f"PDF report written to {output_path}")
        else:
            scanner = Scanner(detectors=detectors)
            findings, report_content = scanner.scan(ipa_path, reporter=reporter)

            # For non-console formats, write output
            if output_format != "console" and report_content:
                if output_path:
                    output_path.write_text(report_content)
                    console.print(f"Report written to {output_path}")
                else:
                    click.echo(report_content)

    except IPAAnalyzerError as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise SystemExit(1) from None

    if fail_on:
        threshold = Severity[fail_on.upper()]
        if any(f.severity.value >= threshold.value for f in findings):
            raise SystemExit(1)
