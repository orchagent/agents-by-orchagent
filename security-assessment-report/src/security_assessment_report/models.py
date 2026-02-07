"""Pydantic models for the security assessment report agent."""

from typing import Literal, Optional
from pydantic import BaseModel, Field


class AssessmentInput(BaseModel):
    """Input parameters parsed from stdin JSON."""

    repo_url: Optional[str] = Field(
        default=None,
        description="URL of the git repository to assess",
    )
    path: Optional[str] = Field(
        default=None,
        description="Local directory path to assess",
    )
    org_name: str = Field(
        default="Organization",
        description="Organization name for the report header",
    )
    annual_revenue_usd: Optional[float] = Field(
        default=None,
        description="Annual revenue in USD for financial impact calculations",
    )
    industry: Literal[
        "technology", "finance", "healthcare", "retail", "government", "other"
    ] = Field(
        default="technology",
        description="Industry vertical for risk context",
    )


class RiskFinding(BaseModel):
    """A single finding enriched with business-impact scoring."""

    title: str = Field(description="Human-readable finding title")
    category: str = Field(
        description="Finding category: secrets, dependencies, frontend_security, api_security, logging"
    )
    severity: str = Field(description="Original severity: critical, high, medium, low")
    business_impact_score: int = Field(
        ge=1, le=10,
        description="Business impact score from 1 (minimal) to 10 (catastrophic)",
    )
    estimated_financial_impact_usd: float = Field(
        description="Estimated financial impact in USD based on industry benchmarks",
    )
    effort_to_fix_hours: float = Field(
        description="Estimated engineering hours to remediate",
    )
    description: str = Field(
        description="Business-language description of the risk (no technical jargon)",
    )
    technical_detail: str = Field(
        default="",
        description="Technical detail for the engineering team",
    )


class RemediationItem(BaseModel):
    """A prioritized remediation step in the roadmap."""

    priority: int = Field(
        ge=1,
        description="Priority rank (1 = highest)",
    )
    title: str = Field(description="Remediation action title")
    category: str = Field(description="Finding category this addresses")
    effort_hours: float = Field(description="Estimated engineering hours")
    impact_score: int = Field(
        ge=1, le=10,
        description="Risk reduction impact (1-10)",
    )
    roi_ratio: float = Field(
        description="Impact-to-effort ratio (higher = better ROI)",
    )
    timeline_phase: Literal["immediate", "short-term", "medium-term"] = Field(
        description="When to execute: immediate (0-7 days), short-term (1-4 weeks), medium-term (1-3 months)",
    )
    description: str = Field(
        description="What to do, in plain business language",
    )


class AssessmentReport(BaseModel):
    """The full executive-level security assessment report."""

    org_name: str = Field(description="Organization name")
    scan_date: str = Field(description="ISO 8601 date of the assessment")
    executive_summary: str = Field(
        description="2-3 sentence executive summary using business-impact language",
    )
    overall_risk_level: Literal["critical", "high", "medium", "low"] = Field(
        description="Aggregate risk level for the organization",
    )
    risk_score: int = Field(
        ge=0, le=100,
        description="Numeric risk score from 0 (secure) to 100 (critical exposure)",
    )
    estimated_financial_exposure_usd: float = Field(
        description="Total estimated financial exposure across all findings",
    )
    time_to_low_risk_days: int = Field(
        description="Estimated calendar days to reach 'low risk' status",
    )
    findings: list[RiskFinding] = Field(
        default_factory=list,
        description="All findings with business-impact scoring",
    )
    remediation_roadmap: list[RemediationItem] = Field(
        default_factory=list,
        description="Prioritized remediation steps ordered by ROI",
    )
    methodology_note: str = Field(
        default=(
            "This assessment evaluates organizational resilience over compliance. "
            "Risk scores reflect real-world exploitability and business impact, not "
            "theoretical severity. Financial estimates use IBM Cost of a Data Breach "
            "2024 benchmarks and are scaled to the organization's industry and revenue. "
            "Methodology inspired by u/QoTSankgreall's incident response framework."
        ),
        description="Note explaining the assessment methodology",
    )
