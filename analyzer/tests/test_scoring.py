"""Tests for the risk score calculator."""

from __future__ import annotations

from ipa_analyzer.detectors.base import Finding, Severity
from ipa_analyzer.utils.scoring import calculate_risk_score


def _finding(severity: Severity) -> Finding:
    return Finding("t", severity, "T", "d", "l", "e", "o", "r", 1)


class TestCalculateRiskScore:
    def test_no_findings_score_zero(self):
        result = calculate_risk_score([])
        assert result.score == 0
        assert result.grade == "A"

    def test_single_critical(self):
        result = calculate_risk_score([_finding(Severity.CRITICAL)])
        assert result.score == 15
        assert result.grade == "A"

    def test_single_high(self):
        result = calculate_risk_score([_finding(Severity.HIGH)])
        assert result.score == 10
        assert result.grade == "A"

    def test_info_contributes_zero(self):
        result = calculate_risk_score([_finding(Severity.INFO)] * 50)
        assert result.score == 0
        assert result.grade == "A"

    def test_grade_b(self):
        # 3 HIGH = 30 -> grade B
        result = calculate_risk_score([_finding(Severity.HIGH)] * 3)
        assert result.score == 30
        assert result.grade == "B"

    def test_grade_c(self):
        # 2 CRITICAL + 3 HIGH = 30 + 30 = 60 -> grade C
        findings = [_finding(Severity.CRITICAL)] * 2 + [_finding(Severity.HIGH)] * 3
        result = calculate_risk_score(findings)
        assert result.score == 60
        assert result.grade == "C"

    def test_grade_d(self):
        # 5 HIGH + 1 CRITICAL = 50 + 15 = 65 -> grade D
        findings = [_finding(Severity.HIGH)] * 5 + [_finding(Severity.CRITICAL)]
        result = calculate_risk_score(findings)
        assert result.score == 65
        assert result.grade == "D"

    def test_score_capped_at_100(self):
        findings = [_finding(Severity.CRITICAL)] * 20
        result = calculate_risk_score(findings)
        assert result.score == 100
        assert result.grade == "F"

    def test_breakdown_structure(self):
        findings = [_finding(Severity.HIGH), _finding(Severity.MEDIUM)]
        result = calculate_risk_score(findings)
        assert result.breakdown["HIGH"]["count"] == 1
        assert result.breakdown["HIGH"]["points"] == 10
        assert result.breakdown["MEDIUM"]["count"] == 1
        assert result.breakdown["MEDIUM"]["points"] == 5
        assert result.breakdown["CRITICAL"]["count"] == 0

    def test_boundary_grade_a(self):
        # Exactly 20 -> A
        findings = [_finding(Severity.HIGH)] * 2
        result = calculate_risk_score(findings)
        assert result.score == 20
        assert result.grade == "A"

    def test_boundary_grade_b_lower(self):
        # 21 -> B (4 MEDIUM + 1 LOW = 22 -> B... let's be precise)
        # 4 HIGH = 40 -> B. Use 21: not easy to get exactly 21
        # 2 HIGH + 0.2 = can't. Use: 1 HIGH + 2 MEDIUM + 1 LOW = 10+10+2 = 22 -> B
        findings = (
            [_finding(Severity.HIGH)] + [_finding(Severity.MEDIUM)] * 2 + [_finding(Severity.LOW)]
        )
        result = calculate_risk_score(findings)
        assert result.score == 22
        assert result.grade == "B"
