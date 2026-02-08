"""
Risk scoring engine for security assessment reports.

Translates raw security findings into business-impact metrics using
industry breach cost benchmarks (IBM Cost of a Data Breach 2024) and
the "resilience over compliance" philosophy from u/QoTSankgreall's
incident response methodology.
"""

from __future__ import annotations

from .models import RiskFinding, RemediationItem

# ---------------------------------------------------------------------------
# Industry breach-cost multipliers (relative to cross-industry average)
# Source: IBM Cost of a Data Breach Report 2024
# ---------------------------------------------------------------------------
INDUSTRY_COST_MULTIPLIER: dict[str, float] = {
    "healthcare": 1.95,   # $10.93M avg vs $4.45M cross-industry
    "finance": 1.35,      # $6.08M avg
    "technology": 1.10,   # $4.97M avg
    "government": 0.75,   # Government breaches cost less but have compliance burden
    "retail": 0.70,       # $3.28M avg
    "other": 1.00,
}

# Base financial impact per finding by severity (USD)
# Derived from: avg breach cost $4.45M, avg 277 days to contain,
# avg per-record cost $165, avg 19,500 records per breach
SEVERITY_BASE_IMPACT: dict[str, float] = {
    "critical": 450_000.0,   # Single critical finding ~10% of avg breach cost
    "high": 150_000.0,       # High findings contribute significant exposure
    "medium": 35_000.0,      # Medium findings add incremental risk
    "low": 5_000.0,          # Low findings have minimal direct financial impact
}

# Business impact score mapping (1-10) by severity and category
# Higher scores for categories that directly enable data exfiltration
# or service disruption (resilience-focused scoring)
SEVERITY_IMPACT_BASE: dict[str, int] = {
    "critical": 9,
    "high": 7,
    "medium": 4,
    "low": 2,
}

CATEGORY_IMPACT_BONUS: dict[str, int] = {
    "secrets": 1,               # Leaked secrets = immediate exploitability
    "dependencies": 0,          # Known CVEs are public but may need chaining
    "api_security": 1,          # API issues directly expose data
    "frontend_security": 0,     # Frontend issues often need user interaction
    "logging": -1,              # Logging issues reduce forensic capability, not direct exposure
}

# Effort-to-fix estimates in engineering hours by category and severity
EFFORT_HOURS: dict[str, dict[str, float]] = {
    "secrets": {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0},
    "dependencies": {"critical": 8.0, "high": 4.0, "medium": 2.0, "low": 1.0},
    "frontend_security": {"critical": 16.0, "high": 8.0, "medium": 4.0, "low": 2.0},
    "api_security": {"critical": 16.0, "high": 8.0, "medium": 4.0, "low": 2.0},
    "logging": {"critical": 8.0, "high": 4.0, "medium": 2.0, "low": 1.0},
}

# Human-readable category labels for report output
CATEGORY_LABELS: dict[str, str] = {
    "secrets": "Exposed Credentials",
    "dependencies": "Vulnerable Dependencies",
    "frontend_security": "Frontend Security Gap",
    "api_security": "API Security Gap",
    "logging": "Forensic Visibility Gap",
}


def _clamp(value: int, lo: int, hi: int) -> int:
    """Clamp an integer to [lo, hi]."""
    return max(lo, min(hi, value))


def score_finding(finding_dict: dict, category: str, industry: str) -> RiskFinding:
    """
    Transform a raw finding from security-review into a business-impact RiskFinding.

    Args:
        finding_dict: Raw finding dict from the security-review agent output.
        category: One of secrets, dependencies, frontend_security, api_security, logging.
        industry: Industry vertical for cost scaling.

    Returns:
        A RiskFinding with business-impact scoring applied.
    """
    severity = finding_dict.get("severity", "medium").lower()
    if severity not in SEVERITY_BASE_IMPACT:
        severity = "medium"

    # --- Business impact score (1-10) ---
    base_score = SEVERITY_IMPACT_BASE.get(severity, 4)
    bonus = CATEGORY_IMPACT_BONUS.get(category, 0)
    business_impact_score = _clamp(base_score + bonus, 1, 10)

    # --- Financial impact ---
    base_cost = SEVERITY_BASE_IMPACT.get(severity, 35_000.0)
    multiplier = INDUSTRY_COST_MULTIPLIER.get(industry, 1.0)
    estimated_financial_impact = base_cost * multiplier

    # --- Effort to fix ---
    category_effort = EFFORT_HOURS.get(category, EFFORT_HOURS["api_security"])
    effort_hours = category_effort.get(severity, 4.0)

    # --- Build human-readable title and description ---
    label = CATEGORY_LABELS.get(category, category.replace("_", " ").title())
    title = _build_title(finding_dict, category, label)
    description = _build_description(finding_dict, category, severity, estimated_financial_impact)
    technical_detail = _build_technical_detail(finding_dict, category)

    return RiskFinding(
        title=title,
        category=category,
        severity=severity,
        business_impact_score=business_impact_score,
        estimated_financial_impact_usd=round(estimated_financial_impact, 2),
        effort_to_fix_hours=effort_hours,
        description=description,
        technical_detail=technical_detail,
    )


def _build_title(finding: dict, category: str, label: str) -> str:
    """Build a concise finding title."""
    if category == "secrets":
        secret_type = finding.get("type", "credential")
        return f"{label}: {secret_type}"
    if category == "dependencies":
        pkg = finding.get("package", "unknown")
        cve = finding.get("cve", "")
        return f"{label}: {pkg}" + (f" ({cve})" if cve else "")
    # Try several common field names from security-review output
    detail = (
        finding.get("type")
        or finding.get("pattern")
        or finding.get("category")
        or finding.get("title")
        or finding.get("message", "")
    )
    # Humanize: replace underscores with spaces
    if detail:
        detail = detail.replace("_", " ")
    return f"{label}: {detail}" if detail else label


def _build_description(finding: dict, category: str, severity: str, financial_impact: float) -> str:
    """Build a business-language description (no technical jargon)."""
    impact_str = f"${financial_impact:,.0f}"

    if category == "secrets":
        return (
            f"A {severity}-severity credential exposure was detected that could allow "
            f"unauthorized access to protected systems. Estimated revenue exposure: {impact_str}. "
            f"If exploited, this could lead to data exfiltration, service disruption, or "
            f"regulatory penalties."
        )
    if category == "dependencies":
        pkg = finding.get("package", "a software component")
        return (
            f"A known vulnerability in {pkg} creates a potential entry point for attackers. "
            f"Estimated revenue exposure: {impact_str}. This vulnerability is publicly documented, "
            f"meaning exploit code may already be available."
        )
    if category == "api_security":
        return (
            f"An API security gap was identified that could expose sensitive data or allow "
            f"unauthorized operations. Estimated revenue exposure: {impact_str}. "
            f"API vulnerabilities are a leading cause of data breaches."
        )
    if category == "frontend_security":
        return (
            f"A frontend security gap was identified that could be exploited to target users "
            f"or steal session data. Estimated revenue exposure: {impact_str}. "
            f"This type of issue can damage customer trust and trigger notification requirements."
        )
    if category == "logging":
        return (
            f"A gap in security logging reduces the organization's ability to detect and "
            f"respond to incidents. Estimated operational exposure: {impact_str}. "
            f"Poor forensic visibility increases mean time to detect breaches (currently "
            f"industry avg 204 days)."
        )
    return f"A {severity}-severity security issue with estimated exposure of {impact_str}."


def _build_technical_detail(finding: dict, category: str) -> str:
    """Build a technical detail string for the engineering team."""
    parts: list[str] = []

    file_path = finding.get("file", "")
    if file_path:
        line = finding.get("line", 0)
        parts.append(f"{file_path}" + (f":{line}" if line else ""))

    message = finding.get("message", "")
    if message:
        parts.append(message)

    recommendation = finding.get("recommendation", "")
    if recommendation:
        parts.append(recommendation)

    if category == "dependencies":
        fixed_in = finding.get("fixed_in", "")
        if fixed_in:
            parts.append(f"Fix available in version {fixed_in}")

    snippet = finding.get("snippet", finding.get("preview", ""))
    if snippet:
        parts.append(f"Context: {snippet[:200]}")

    return " | ".join(parts) if parts else ""


def calculate_overall_risk(findings: list[RiskFinding]) -> tuple[str, int]:
    """
    Calculate aggregate risk level and numeric score from all findings.

    Uses a weighted sum approach: each finding contributes to the total score
    proportional to its business impact. The score is then normalized to 0-100.

    Returns:
        (risk_level, risk_score) where risk_level is critical/high/medium/low
        and risk_score is 0-100.
    """
    if not findings:
        return ("low", 0)

    # Weighted score: sum of (business_impact_score ^ 1.5) to penalize clusters
    # of high-impact findings more than many low-impact ones
    weighted_sum = sum(f.business_impact_score ** 1.5 for f in findings)

    # Normalize: a single critical finding (score 10) should produce ~35 risk score,
    # while 5+ critical findings should push toward 90+
    # Scale factor derived from: 10^1.5 = 31.6, so 3 criticals ≈ 95
    raw_score = min(100, int(weighted_sum * 1.05))

    if raw_score >= 75:
        level = "critical"
    elif raw_score >= 50:
        level = "high"
    elif raw_score >= 25:
        level = "medium"
    else:
        level = "low"

    return (level, raw_score)


def estimate_financial_exposure(
    findings: list[RiskFinding],
    annual_revenue: float | None,
) -> float:
    """
    Estimate total financial exposure across all findings.

    If annual_revenue is provided, the estimate is capped at a reasonable
    percentage of revenue (no organization loses more than ~30% of revenue
    from a single security incident in practice).

    Args:
        findings: Scored risk findings.
        annual_revenue: Annual revenue in USD, or None if not provided.

    Returns:
        Estimated total financial exposure in USD.
    """
    raw_total = sum(f.estimated_financial_impact_usd for f in findings)

    if annual_revenue and annual_revenue > 0:
        # Cap at 30% of annual revenue (worst-case scenario)
        cap = annual_revenue * 0.30
        return min(raw_total, cap)

    return raw_total


def estimate_time_to_low_risk(roadmap: list[RemediationItem]) -> int:
    """
    Estimate calendar days to reach 'low risk' status.

    Assumes a single engineer working full-time (8h/day) on remediation
    with some parallelization for items in different phases. Adds buffer
    for testing, review, and deployment.

    Args:
        roadmap: The prioritized remediation roadmap.

    Returns:
        Estimated calendar days.
    """
    if not roadmap:
        return 0

    # Sum effort hours per phase
    phase_hours: dict[str, float] = {
        "immediate": 0.0,
        "short-term": 0.0,
        "medium-term": 0.0,
    }
    for item in roadmap:
        phase_hours[item.timeline_phase] = (
            phase_hours.get(item.timeline_phase, 0.0) + item.effort_hours
        )

    # Convert hours to working days (8h/day) with 1.5x buffer for review/testing
    buffer_multiplier = 1.5
    hours_per_day = 8.0

    total_days = 0.0
    for phase, hours in phase_hours.items():
        if hours > 0:
            work_days = (hours * buffer_multiplier) / hours_per_day
            total_days += work_days

    # Convert working days to calendar days (~5 working days per 7 calendar days)
    calendar_days = int(total_days * (7.0 / 5.0))

    return max(1, calendar_days)
