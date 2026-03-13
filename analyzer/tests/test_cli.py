"""Tests for the CLI interface."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from ipa_analyzer.cli import cli


@patch("ipa_analyzer.cli.Scanner")
@patch("ipa_analyzer.cli.IPAExtractor", create=True)
class TestCLIScan:
    """Test CLI scan command with mocked scanner."""

    def _setup_scanner(self, mock_scanner_cls, findings=None, report_content=None):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = (findings or [], report_content)
        mock_scanner.detectors = []
        mock_scanner_cls.return_value = mock_scanner
        return mock_scanner

    def test_scan_help(self, _mock_ext, _mock_scanner):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--output" in result.output
        assert "--rules" in result.output
        assert "--checks" in result.output

    def test_scan_default_format(self, _mock_ext, mock_scanner_cls, tmp_path):
        self._setup_scanner(mock_scanner_cls)
        ipa = tmp_path / "test.ipa"
        ipa.write_bytes(b"PK")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(ipa)])
        assert result.exit_code == 0
        mock_scanner_cls.return_value.scan.assert_called_once()

    def test_scan_json_format_stdout(self, _mock_ext, mock_scanner_cls, tmp_path):
        report = json.dumps({"findings": []})
        self._setup_scanner(mock_scanner_cls, report_content=report)
        ipa = tmp_path / "test.ipa"
        ipa.write_bytes(b"PK")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(ipa), "-f", "json"])
        assert result.exit_code == 0
        assert "findings" in result.output

    def test_scan_json_format_to_file(self, _mock_ext, mock_scanner_cls, tmp_path):
        report = json.dumps({"findings": []})
        self._setup_scanner(mock_scanner_cls, report_content=report)
        ipa = tmp_path / "test.ipa"
        ipa.write_bytes(b"PK")
        out_file = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(ipa), "-f", "json", "-o", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        assert json.loads(out_file.read_text()) == {"findings": []}

    def test_scan_checks_filter(self, _mock_ext, mock_scanner_cls, tmp_path):
        self._setup_scanner(mock_scanner_cls)
        ipa = tmp_path / "test.ipa"
        ipa.write_bytes(b"PK")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(ipa), "-c", "binary_protections,ats"])
        assert result.exit_code == 0
        # Scanner should be called with filtered detectors
        args, kwargs = mock_scanner_cls.call_args
        detectors = kwargs.get("detectors") or (args[0] if args else None)
        assert detectors is not None
        assert len(detectors) == 2

    def test_scan_invalid_check(self, _mock_ext, mock_scanner_cls, tmp_path):
        self._setup_scanner(mock_scanner_cls)
        ipa = tmp_path / "test.ipa"
        ipa.write_bytes(b"PK")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(ipa), "-c", "nonexistent"])
        assert result.exit_code != 0

    def test_scan_fail_on_high(self, _mock_ext, mock_scanner_cls, tmp_path):
        from ipa_analyzer.detectors.base import Finding, Severity

        finding = Finding("t", Severity.HIGH, "F", "d", "l", "e", "o", "r", 1)
        self._setup_scanner(mock_scanner_cls, findings=[finding])
        ipa = tmp_path / "test.ipa"
        ipa.write_bytes(b"PK")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(ipa), "--fail-on", "high"])
        assert result.exit_code == 1

    def test_scan_with_rules_file(self, _mock_ext, mock_scanner_cls, tmp_path):
        from ipa_analyzer.detectors.ats import ATSDetector
        from ipa_analyzer.detectors.binary import BinaryProtectionsDetector

        mock_scanner = self._setup_scanner(mock_scanner_cls)
        # Provide real detectors list so the CLI can extend it
        mock_scanner.detectors = [BinaryProtectionsDetector(), ATSDetector()]
        ipa = tmp_path / "test.ipa"
        ipa.write_bytes(b"PK")
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(
            """
rules:
  - id: test_001
    name: "Test Rule"
    pattern: "test"
    severity: high
    description: "A test"
    owasp: "M9"
    cwe_id: 798
    remediation: "Fix"
"""
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(ipa), "-r", str(rules_file)])
        assert result.exit_code == 0
        # Scanner should have detectors including custom rules
        # The final call creates a new Scanner with detectors list
        args, kwargs = mock_scanner_cls.call_args_list[-1]
        detectors = kwargs.get("detectors") or (args[0] if args else None)
        assert detectors is not None
        # 2 default + 1 custom = 3
        assert len(detectors) == 3


class TestCLIVersion:
    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
