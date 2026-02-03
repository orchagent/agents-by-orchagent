"""Security scoring logic for VPS audit results."""

from .models import CheckResult


def calculate_score(critical_issues: list[CheckResult], warnings: list[CheckResult]) -> int:
    """Calculate overall security score based on check results.

    Starts at 100 and deducts points based on severity:
    - critical: -25 points each
    - high: -15 points each
    - medium: -5 points each
    - low: -2 points each

    Minimum score is 0.
    """
    score = 100

    severity_penalties = {
        "critical": 25,
        "high": 15,
        "medium": 5,
        "low": 2,
    }

    all_issues = critical_issues + warnings
    for issue in all_issues:
        penalty = severity_penalties.get(issue.severity.lower(), 0)
        score -= penalty

    return max(0, score)


def get_grade(score: int) -> str:
    """Convert numeric score to letter grade."""
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"
