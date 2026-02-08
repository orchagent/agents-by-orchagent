"""Generate prioritized recommendations from scan findings."""

from .models import Finding, DependencyFinding, ScanSummary, Severity, FindingCategory


# Priority scores by category and severity
_CATEGORY_PRIORITY = {
    FindingCategory.rsc_security: 1000,
    FindingCategory.server_actions: 900,
    FindingCategory.env_exposure: 850,
    FindingCategory.xss: 800,
    FindingCategory.auth: 750,
    FindingCategory.ssrf: 700,
    FindingCategory.config: 400,
    FindingCategory.cve: 600,
}

_SEVERITY_MULTIPLIER = {
    Severity.critical: 5,
    Severity.high: 3,
    Severity.medium: 2,
    Severity.low: 1,
    Severity.info: 0,
}


def _score_finding(finding: Finding) -> int:
    """Calculate priority score for a finding."""
    base = _CATEGORY_PRIORITY.get(finding.category, 500)
    mult = _SEVERITY_MULTIPLIER.get(finding.severity, 1)
    return base * mult


def _score_dep_finding(finding: DependencyFinding) -> int:
    """Calculate priority score for a dependency finding."""
    base = _CATEGORY_PRIORITY.get(FindingCategory.cve, 600)
    mult = _SEVERITY_MULTIPLIER.get(finding.severity, 1)
    return base * mult


def _recommendation_for_finding(finding: Finding) -> str:
    """Generate a recommendation string for a finding."""
    return finding.remediation.split("\n")[0]


def _recommendation_for_deps(deps: list[DependencyFinding]) -> str:
    """Generate a recommendation string for dependency findings."""
    if not deps:
        return ""

    critical_count = sum(1 for d in deps if d.severity == Severity.critical)
    high_count = sum(1 for d in deps if d.severity == Severity.high)

    parts = []
    if critical_count:
        parts.append(f"{critical_count} critical")
    if high_count:
        parts.append(f"{high_count} high")

    severity_str = " and ".join(parts) if parts else str(len(deps))
    return (
        f"Update {len(deps)} vulnerable dependencies ({severity_str} severity). "
        "Run: npm audit fix or manually update the packages listed in dependency_findings."
    )


def generate_recommendations(
    findings: list[Finding],
    summary: ScanSummary,
    dependency_findings: list[DependencyFinding] | None = None,
    max_recommendations: int = 5,
) -> list[str]:
    """Generate top prioritized recommendations from findings.

    Args:
        findings: List of pattern scan findings.
        summary: Scan summary with counts.
        dependency_findings: Optional list of CVE findings.
        max_recommendations: Maximum number of recommendations to return.

    Returns:
        List of recommendation strings, ordered by priority.
    """
    if not findings and not dependency_findings:
        return []

    # Score and deduplicate findings by category
    category_scores: dict[str, tuple[int, str]] = {}

    for finding in findings:
        score = _score_finding(finding)
        rec = _recommendation_for_finding(finding)
        key = f"{finding.category.value}:{finding.title}"

        if key not in category_scores or category_scores[key][0] < score:
            category_scores[key] = (score, rec)

    # Add dependency recommendation if there are CVE findings
    if dependency_findings:
        dep_score = max((_score_dep_finding(d) for d in dependency_findings), default=0)
        dep_rec = _recommendation_for_deps(dependency_findings)
        category_scores["cve:dependencies"] = (dep_score, dep_rec)

    # Sort by score and return top N
    sorted_recs = sorted(category_scores.values(), key=lambda x: x[0], reverse=True)

    return [rec for _, rec in sorted_recs[:max_recommendations]]
