"""Tests for MobSF and HAR importers."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ipa_analyzer.detectors.base import Severity
from ipa_analyzer.importers.har import HARImporter
from ipa_analyzer.importers.mobsf import MobSFImporter, _parse_cwe

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _write_json(data: dict) -> Path:
    """Write a dict to a temporary JSON file and return its path."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, tmp)
    tmp.flush()
    return Path(tmp.name)


MINIMAL_MOBSF_CODE_ANALYSIS = {
    "code_analysis": {
        "swift": {
            "rule_1": {
                "level": "high",
                "files": {"AppDelegate.swift": "line 10"},
                "metadata": {
                    "description": "Hardcoded API key found",
                    "input_case": "exact",
                    "masvs": "MSTG-STORAGE-1",
                    "cwe": "CWE-798",
                },
            },
            "rule_2": {
                "level": "warning",
                "files": {},
                "metadata": {
                    "description": "Weak hashing algorithm",
                    "input_case": "exact",
                    "masvs": "MSTG-CRYPTO-4",
                    "cwe": "cwe-327",
                },
            },
        }
    }
}

MINIMAL_MOBSF_BINARY = {
    "binary_analysis": [
        {
            "title": "PIE Enabled",
            "severity": "good",
            "description": "PIE flag is set.",
            "detailed_desc": "Binary is compiled with PIE.",
            "masvs": "MSTG-CODE-9",
            "cwe": "CWE-119",
        },
        {
            "title": "Stack Canary Missing",
            "severity": "high",
            "description": "No stack canary detected.",
            "detailed_desc": "The binary lacks stack canary protection.",
            "masvs": "MSTG-CODE-9",
            "cwe": "CWE-121",
        },
    ]
}


MINIMAL_HAR = {
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "http://api.example.com/data",
                    "headers": [],
                }
            },
            {
                "request": {
                    "method": "POST",
                    "url": "https://secure.example.com/login",
                    "headers": [
                        {"name": "Authorization", "value": "Bearer supersecrettoken123"},
                    ],
                }
            },
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/v1?api_key=ABCDEF12345678",
                    "headers": [],
                }
            },
        ]
    }
}


# ---------------------------------------------------------------------------
# TestMobSFImporter
# ---------------------------------------------------------------------------

class TestMobSFImporter:
    def test_import_code_analysis_findings(self):
        path = _write_json(MINIMAL_MOBSF_CODE_ANALYSIS)
        importer = MobSFImporter()
        findings = importer.import_report(path)

        assert len(findings) == 2
        titles = [f.title for f in findings]
        assert "Hardcoded API key found" in titles
        assert "Weak hashing algorithm" in titles

        # Check first finding details
        hardcoded = next(f for f in findings if "Hardcoded" in f.title)
        assert hardcoded.severity == Severity.HIGH
        assert hardcoded.detector == "mobsf_import"
        assert hardcoded.scan_type == "import"
        assert "AppDelegate.swift" in hardcoded.location
        assert hardcoded.cwe_id == 798

    def test_import_binary_analysis_findings(self):
        path = _write_json(MINIMAL_MOBSF_BINARY)
        importer = MobSFImporter()
        findings = importer.import_report(path)

        assert len(findings) == 2
        titles = [f.title for f in findings]
        assert "PIE Enabled" in titles
        assert "Stack Canary Missing" in titles

        canary = next(f for f in findings if "Canary" in f.title)
        assert canary.severity == Severity.HIGH
        assert canary.location == "Binary"
        assert canary.cwe_id == 121

    def test_empty_report_returns_empty(self):
        path = _write_json({})
        importer = MobSFImporter()
        findings = importer.import_report(path)
        assert findings == []

    def test_severity_mapping(self):
        """Verify all MobSF severity strings map correctly."""
        data = {
            "code_analysis": {
                "cat": {
                    "r_high": {"level": "high", "metadata": {"description": "h", "cwe": ""}},
                    "r_warn": {"level": "warning", "metadata": {"description": "w", "cwe": ""}},
                    "r_info": {"level": "info", "metadata": {"description": "i", "cwe": ""}},
                    "r_good": {"level": "good", "metadata": {"description": "g", "cwe": ""}},
                    "r_secure": {"level": "secure", "metadata": {"description": "s", "cwe": ""}},
                    "r_unknown": {"level": "banana", "metadata": {"description": "u", "cwe": ""}},
                }
            }
        }
        path = _write_json(data)
        findings = MobSFImporter().import_report(path)
        sev_map = {f.title: f.severity for f in findings}

        assert sev_map["h"] == Severity.HIGH
        assert sev_map["w"] == Severity.MEDIUM
        assert sev_map["i"] == Severity.INFO
        assert sev_map["g"] == Severity.INFO
        assert sev_map["s"] == Severity.INFO
        assert sev_map["u"] == Severity.INFO  # unknown falls back to INFO

    def test_parse_cwe(self):
        assert _parse_cwe("CWE-798") == 798
        assert _parse_cwe("cwe-327") == 327
        assert _parse_cwe("119") == 119
        assert _parse_cwe("") == 0
        assert _parse_cwe("no-number") == 0


# ---------------------------------------------------------------------------
# TestHARImporter
# ---------------------------------------------------------------------------

class TestHARImporter:
    def test_http_connection_flagged(self):
        path = _write_json(MINIMAL_HAR)
        importer = HARImporter()
        findings = importer.import_har(path)

        http_findings = [f for f in findings if "Insecure HTTP" in f.title]
        assert len(http_findings) == 1
        assert http_findings[0].severity == Severity.MEDIUM
        assert http_findings[0].cwe_id == 319
        assert "api.example.com" in http_findings[0].title

    def test_https_connection_not_flagged(self):
        data = {
            "log": {
                "entries": [
                    {"request": {"method": "GET", "url": "https://secure.example.com/ok", "headers": []}}  # noqa: E501
                ]
            }
        }
        path = _write_json(data)
        findings = HARImporter().import_har(path)
        http_findings = [f for f in findings if "Insecure HTTP" in f.title]
        assert len(http_findings) == 0

    def test_sensitive_headers_detected(self):
        path = _write_json(MINIMAL_HAR)
        findings = HARImporter().import_har(path)

        header_findings = [f for f in findings if "Sensitive header" in f.title]
        assert len(header_findings) == 1
        assert header_findings[0].severity == Severity.HIGH
        assert "authorization" in header_findings[0].title
        assert header_findings[0].cwe_id == 200

    def test_api_key_in_url_detected(self):
        path = _write_json(MINIMAL_HAR)
        findings = HARImporter().import_har(path)

        api_findings = [f for f in findings if "API key" in f.title]
        assert len(api_findings) == 1
        assert api_findings[0].severity == Severity.HIGH
        assert api_findings[0].cwe_id == 598

    def test_empty_har(self):
        path = _write_json({"log": {"entries": []}})
        findings = HARImporter().import_har(path)
        assert findings == []

    def test_dedup_hosts(self):
        """Multiple HTTP requests to the same host produce only one finding."""
        data = {
            "log": {
                "entries": [
                    {"request": {"method": "GET", "url": "http://api.example.com/a", "headers": []}},  # noqa: E501
                    {"request": {"method": "POST", "url": "http://api.example.com/b", "headers": []}},  # noqa: E501
                    {"request": {"method": "GET", "url": "http://other.example.com/c", "headers": []}},  # noqa: E501
                ]
            }
        }
        path = _write_json(data)
        findings = HARImporter().import_har(path)

        http_findings = [f for f in findings if "Insecure HTTP" in f.title]
        assert len(http_findings) == 2  # two distinct hosts
        hosts = {f.title for f in http_findings}
        assert any("api.example.com" in h for h in hosts)
        assert any("other.example.com" in h for h in hosts)
