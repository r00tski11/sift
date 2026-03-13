"""Risk score calculator for IPA security analysis findings."""

from __future__ import annotations

from dataclasses import dataclass

from ipa_analyzer.detectors.base import Finding, Severity

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

MAX_SCORE = 100

GRADE_THRESHOLDS = [
    (20, "A"),
    (40, "B"),
    (60, "C"),
    (80, "D"),
]


@dataclass
class RiskScore:
    """Quantified risk assessment from analysis findings."""

    score: int
    grade: str
    breakdown: dict[str, dict[str, int]]


def calculate_risk_score(findings: list[Finding]) -> RiskScore:
    """Calculate a 0-100 risk score with letter grade from findings.

    Weights: CRITICAL=15, HIGH=10, MEDIUM=5, LOW=2, INFO=0.
    Score is capped at 100.

    Returns:
        RiskScore with score (0-100), grade (A-F), and severity breakdown.
    """
    raw = 0
    breakdown: dict[str, dict[str, int]] = {}

    for severity in Severity:
        count = sum(1 for f in findings if f.severity == severity)
        points = count * SEVERITY_WEIGHTS[severity]
        breakdown[severity.name] = {"count": count, "points": points}
        raw += points

    score = min(raw, MAX_SCORE)

    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if score <= threshold:
            grade = letter
            break

    return RiskScore(score=score, grade=grade, breakdown=breakdown)
