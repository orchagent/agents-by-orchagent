"""
Report builder for security assessment reports.

Takes raw security-review output and transforms it into an executive-level
assessment report with business-impact scoring and prioritized remediation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import (
    AssessmentInput,
    AssessmentReport,
    RemediationItem,
    RiskFinding,
)
from .risk_scorer import (
    calculate_overall_risk,
    estimate_financial_exposure,
    estimate_time_to_low_risk,
    score_finding,
    CATEGORY_LABELS,
)


# Categories to extract from security-review findings, mapped to the
# sub-key within the findings collection
_FINDING_CATEGORIES: dict[str, str] = {
    "secrets": "secrets",
    "dependencies": "dependencies",
    "frontend_security": "frontend_security",
    "api_security": "api_security",
    "logging": "logging",
}


def _extract_findings(
    security_review_result: dict[str, Any],
    industry: str,
) -> list[RiskFinding]:
    """
    Extract and score all findings from the security-review result.

    Processes both the main findings and any likely_false_positives that were
    flagged. Only real issues (not false positives) are included.
    """
    findings_collection = security_review_result.get("findings", {})
    scored: list[RiskFinding] = []

    for category, key in _FINDING_CATEGORIES.items():
        raw_findings = findings_collection.get(key, [])
        for raw in raw_findings:
            scored.append(score_finding(raw, category, industry))

    # Sort by business impact score descending (most impactful first)
    scored.sort(key=lambda f: f.business_impact_score, reverse=True)

    return scored


def build_remediation_roadmap(findings: list[RiskFinding]) -> list[RemediationItem]:
    """
    Build a prioritized remediation roadmap from scored findings.

    Groups findings by category, calculates impact/effort ratio (ROI) for
    each remediation action, and assigns timeline phases:
    - immediate (0-7 days): Critical/high findings with good ROI
    - short-term (1-4 weeks): High/medium findings or complex critical fixes
    - medium-term (1-3 months): Medium/low findings and systemic improvements

    Items are ordered by ROI (impact-to-effort ratio) so teams focus on the
    highest-value remediations first.
    """
    if not findings:
        return []

    # Group findings by category to create consolidated remediation items
    category_groups: dict[str, list[RiskFinding]] = {}
    for finding in findings:
        category_groups.setdefault(finding.category, []).append(finding)

    # Collect raw item data first, then sort by ROI before constructing
    # RemediationItem objects (which validate priority >= 1 at init time).
    raw_items: list[dict] = []

    for category, group in category_groups.items():
        # Aggregate metrics for the group
        max_impact = max(f.business_impact_score for f in group)
        total_effort = sum(f.effort_to_fix_hours for f in group)
        avg_impact = sum(f.business_impact_score for f in group) / len(group)

        # ROI: impact per hour of effort (higher = better return)
        roi = avg_impact / max(total_effort, 0.1)

        # Determine timeline phase based on severity and effort
        max_severity = max(group, key=lambda f: f.business_impact_score).severity
        if max_severity == "critical" or (max_severity == "high" and total_effort <= 16):
            phase = "immediate"
        elif max_severity == "high" or (max_severity == "medium" and total_effort <= 24):
            phase = "short-term"
        else:
            phase = "medium-term"

        label = CATEGORY_LABELS.get(category, category.replace("_", " ").title())
        count = len(group)
        title = f"Remediate {count} {label} finding{'s' if count != 1 else ''}"

        description = _build_remediation_description(category, group, phase)

        raw_items.append(dict(
            title=title,
            category=category,
            effort_hours=round(total_effort, 1),
            impact_score=max_impact,
            roi_ratio=round(roi, 2),
            timeline_phase=phase,
            description=description,
        ))

    # Sort by ROI descending (best bang for the buck first)
    raw_items.sort(key=lambda x: x["roi_ratio"], reverse=True)

    # Build RemediationItem objects with correct priority ranks
    items: list[RemediationItem] = []
    for idx, raw in enumerate(raw_items, start=1):
        items.append(RemediationItem(priority=idx, **raw))

    return items


def _build_remediation_description(
    category: str,
    findings: list[RiskFinding],
    phase: str,
) -> str:
    """Build a plain-language remediation description for a category group."""
    count = len(findings)
    total_exposure = sum(f.estimated_financial_impact_usd for f in findings)
    exposure_str = f"${total_exposure:,.0f}"

    phase_labels = {
        "immediate": "within the next 7 days",
        "short-term": "within the next 4 weeks",
        "medium-term": "within the next 3 months",
    }
    timeline = phase_labels.get(phase, "as scheduled")

    if category == "secrets":
        return (
            f"Rotate or revoke {count} exposed credential{'s' if count != 1 else ''} "
            f"{timeline}. Implement automated secret scanning in CI/CD to prevent "
            f"recurrence. Combined revenue exposure: {exposure_str}."
        )
    if category == "dependencies":
        return (
            f"Upgrade {count} vulnerable dependenc{'ies' if count != 1 else 'y'} "
            f"{timeline}. Establish a dependency update policy with automated "
            f"vulnerability monitoring. Combined revenue exposure: {exposure_str}."
        )
    if category == "api_security":
        return (
            f"Address {count} API security gap{'s' if count != 1 else ''} {timeline}. "
            f"Review authentication, authorization, and input validation across all "
            f"endpoints. Combined revenue exposure: {exposure_str}."
        )
    if category == "frontend_security":
        return (
            f"Fix {count} frontend security issue{'s' if count != 1 else ''} {timeline}. "
            f"Implement Content Security Policy headers and review client-side data "
            f"handling. Combined revenue exposure: {exposure_str}."
        )
    if category == "logging":
        return (
            f"Close {count} forensic visibility gap{'s' if count != 1 else ''} {timeline}. "
            f"Ensure security-relevant events are logged with sufficient detail for "
            f"incident response. Combined operational exposure: {exposure_str}."
        )
    return (
        f"Address {count} finding{'s' if count != 1 else ''} in this category "
        f"{timeline}. Combined exposure: {exposure_str}."
    )


def generate_executive_summary(report: AssessmentReport) -> str:
    """
    Generate a 2-3 sentence executive summary using business language.

    Avoids technical jargon like "CVSS scores" or "CVE numbers" and instead
    frames everything in terms of financial risk and organizational resilience.
    """
    finding_count = len(report.findings)
    exposure_str = f"${report.estimated_financial_exposure_usd:,.0f}"

    if report.overall_risk_level == "critical":
        urgency = (
            f"{report.org_name} faces critical security exposure with an estimated "
            f"{exposure_str} in potential financial impact across {finding_count} "
            f"identified risk{'s' if finding_count != 1 else ''}. "
            f"Without immediate action, the organization is at elevated risk of "
            f"a material security incident that could disrupt operations and erode "
            f"stakeholder confidence."
        )
    elif report.overall_risk_level == "high":
        urgency = (
            f"{report.org_name} has significant security exposure totaling an estimated "
            f"{exposure_str} across {finding_count} finding{'s' if finding_count != 1 else ''}. "
            f"Several high-priority risks require prompt attention to prevent escalation "
            f"into incidents that could impact revenue and customer trust."
        )
    elif report.overall_risk_level == "medium":
        urgency = (
            f"{report.org_name} has moderate security exposure estimated at {exposure_str} "
            f"across {finding_count} finding{'s' if finding_count != 1 else ''}. "
            f"While no single issue poses an immediate existential threat, the cumulative "
            f"risk warrants a structured remediation effort to maintain organizational resilience."
        )
    else:
        if finding_count == 0:
            urgency = (
                f"{report.org_name} maintains a strong security posture with no findings "
                f"identified during this assessment. No immediate action is required."
            )
        else:
            urgency = (
                f"{report.org_name} maintains a low security risk profile with {finding_count} "
                f"minor finding{'s' if finding_count != 1 else ''} and estimated exposure of "
                f"{exposure_str}. The current security posture supports continued operational "
                f"confidence."
            )

    if report.time_to_low_risk_days > 0 and report.overall_risk_level != "low":
        urgency += (
            f" Estimated time to reach low-risk status: "
            f"{report.time_to_low_risk_days} days with dedicated remediation effort."
        )

    return urgency


def build_report(
    security_review_result: dict[str, Any],
    input_params: AssessmentInput,
) -> AssessmentReport:
    """
    Main report builder: orchestrates risk scoring, roadmap building, and
    report assembly.

    Args:
        security_review_result: Raw JSON output from orchagent/security-review.
        input_params: Parsed input parameters from the caller.

    Returns:
        A fully populated AssessmentReport ready for JSON serialization.
    """
    # Score all findings with business-impact metrics
    findings = _extract_findings(security_review_result, input_params.industry)

    # Calculate aggregate risk
    risk_level, risk_score = calculate_overall_risk(findings)

    # Build prioritized remediation roadmap (ordered by ROI)
    roadmap = build_remediation_roadmap(findings)

    # Estimate financial exposure
    financial_exposure = estimate_financial_exposure(
        findings, input_params.annual_revenue_usd
    )

    # Estimate time to reach low risk
    time_to_low_risk = estimate_time_to_low_risk(roadmap)

    # Assemble the report (executive summary is generated after assembly
    # so it can reference all computed fields)
    report = AssessmentReport(
        org_name=input_params.org_name,
        scan_date=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        executive_summary="",  # Placeholder, generated below
        overall_risk_level=risk_level,
        risk_score=risk_score,
        estimated_financial_exposure_usd=round(financial_exposure, 2),
        time_to_low_risk_days=time_to_low_risk,
        findings=findings,
        remediation_roadmap=roadmap,
    )

    # Generate executive summary referencing the completed report
    report.executive_summary = generate_executive_summary(report)

    return report
