"""Scoring logic for the 15-point security checklist."""

from .models import CategoryResult, CheckStatus, Finding, CATEGORIES


# Category weights (higher = more important for overall score)
WEIGHTS = {
    1: 8,   # Auth
    2: 7,   # Tokens
    3: 8,   # Authorization
    4: 7,   # Input validation
    5: 8,   # SQL safety
    6: 6,   # Rate limiting
    7: 8,   # Secrets
    8: 6,   # TLS
    9: 5,   # File handling
    10: 6,  # Logging
    11: 6,  # Error handling
    12: 5,  # Dependencies
    13: 6,  # Data protection
    14: 5,  # API defaults
    15: 5,  # Observability
}


def compute_category_status(findings: list[Finding]) -> CheckStatus:
    """Determine overall status for a category based on its findings."""
    if not findings:
        return CheckStatus.PASS

    severities = [f.severity for f in findings if f.status == CheckStatus.FAIL]
    if any(s in ("critical", "high") for s in severities):
        return CheckStatus.FAIL

    if any(f.status == CheckStatus.FAIL for f in findings):
        return CheckStatus.WARN

    if any(f.status == CheckStatus.WARN for f in findings):
        return CheckStatus.WARN

    return CheckStatus.PASS


def build_checklist(all_findings: list[Finding]) -> list[CategoryResult]:
    """Group findings into the 15 checklist categories."""
    by_category: dict[int, list[Finding]] = {i: [] for i in range(1, 16)}

    for finding in all_findings:
        cid = finding.category_id
        if 1 <= cid <= 15:
            by_category[cid].append(finding)

    results = []
    for cid in range(1, 16):
        findings = by_category[cid]
        status = compute_category_status(findings)
        results.append(CategoryResult(
            id=cid,
            name=CATEGORIES[cid],
            status=status,
            findings=findings,
        ))

    return results


def compute_score(checklist: list[CategoryResult]) -> tuple[int, str]:
    """Compute overall score (0-100) and letter grade from checklist results."""
    total_weight = 0
    earned = 0.0

    for cat in checklist:
        w = WEIGHTS.get(cat.id, 5)
        total_weight += w

        if cat.status == CheckStatus.PASS:
            earned += w
        elif cat.status == CheckStatus.WARN:
            earned += w * 0.5
        # FAIL = 0

    score = round((earned / total_weight) * 100) if total_weight > 0 else 0

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return score, grade


def generate_recommendations(checklist: list[CategoryResult]) -> list[str]:
    """Generate prioritized recommendations from checklist results."""
    recs = []

    # Priority: FAIL categories with critical findings first
    for cat in sorted(checklist, key=lambda c: (
        0 if c.status == CheckStatus.FAIL else 1,
        -WEIGHTS.get(c.id, 5),
    )):
        if cat.status == CheckStatus.PASS:
            continue

        critical_findings = [
            f for f in cat.findings
            if f.status == CheckStatus.FAIL and f.severity in ("critical", "high")
        ]
        warn_findings = [
            f for f in cat.findings
            if f.status == CheckStatus.WARN or f.severity in ("medium", "low")
        ]

        if critical_findings:
            f = critical_findings[0]
            prefix = "CRITICAL" if f.severity == "critical" else "HIGH"
            loc = f" ({f.file}:{f.line})" if f.file and f.line else ""
            fix = f" Fix: {f.fix}" if f.fix else ""
            recs.append(f"[{prefix}] #{cat.id} {cat.name}: {f.message}{loc}.{fix}")
        elif warn_findings:
            f = warn_findings[0]
            recs.append(f"[WARN] #{cat.id} {cat.name}: {f.message}")

    return recs[:10]  # Top 10 recommendations
