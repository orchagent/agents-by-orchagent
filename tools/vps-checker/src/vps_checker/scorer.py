"""Security scoring logic for VPS audit results."""

from .models import CheckResult, CheckStatus


def calculate_score(critical_issues: list[CheckResult], warnings: list[CheckResult]) -> int:
    """Calculate overall security score based on check results.

    Scoring is based on both status (FAIL vs WARN) and severity:

    For FAIL status (actual security failures):
    - critical: -20 points each
    - high: -12 points each
    - medium: -5 points each
    - low: -2 points each

    For WARN status (recommendations/advisories):
    - critical: -8 points each
    - high: -4 points each
    - medium: -2 points each
    - low: -1 point each

    Minimum score is 0.
    """
    score = 100

    # Different penalties for failures vs warnings
    fail_penalties = {
        "critical": 20,
        "high": 12,
        "medium": 5,
        "low": 2,
    }

    warn_penalties = {
        "critical": 8,
        "high": 4,
        "medium": 2,
        "low": 1,
    }

    all_issues = critical_issues + warnings
    for issue in all_issues:
        severity = issue.severity.lower()
        if issue.status == CheckStatus.FAIL:
            penalty = fail_penalties.get(severity, 0)
        else:
            # WARN or other status
            penalty = warn_penalties.get(severity, 0)
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
