"""Pydantic models for AI data leak scanner."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk severity level for findings."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingCategory(str, Enum):
    """Category of a finding."""

    pii_exposure = "pii_exposure"
    ai_api_data_flow = "ai_api_data_flow"
    secret_in_ai_context = "secret_in_ai_context"
    schema_exposure = "schema_exposure"
    logging_leak = "logging_leak"
    unprotected_endpoint = "unprotected_endpoint"


class Finding(BaseModel):
    """A data exposure finding from the scanner."""

    category: FindingCategory = Field(description="Category of the finding")
    risk_level: RiskLevel = Field(description="Risk severity level")
    title: str = Field(description="Short title describing the finding")
    file: str = Field(description="File path where the finding was detected")
    line: Optional[int] = Field(default=None, description="Line number in the file")
    description: str = Field(description="Detailed description of the issue")
    data_types_at_risk: list[str] = Field(
        default_factory=list,
        description="Data types that may be exposed (e.g., email, ssn, phone)",
    )
    remediation: str = Field(description="Recommended remediation steps")


class SecretFinding(BaseModel):
    """A secret finding from leak-finder sub-agent results."""

    type: str = Field(description="Type of secret (e.g., aws_access_key, openai_api_key)")
    severity: str = Field(description="Severity level: critical, high, medium, low")
    file: str = Field(description="File path where the secret was found")
    line: int = Field(default=0, description="Line number")
    preview: str = Field(default="", description="Redacted preview of the secret")
    recommendation: str = Field(default="", description="Recommended action")


class AIIntegration(BaseModel):
    """A detected AI API integration point."""

    file: str = Field(description="File path containing the AI integration")
    line: int = Field(description="Line number of the integration call")
    provider: str = Field(description="AI provider name (e.g., openai, anthropic, google)")
    api_call_type: str = Field(description="Type of API call (e.g., chat.completions.create)")
    data_flows_in: list[str] = Field(
        default_factory=list,
        description="Data that flows into the API call (e.g., user_input, db_records)",
    )
    is_protected: bool = Field(
        default=False,
        description="Whether the integration has data protection (sanitization, filtering)",
    )
    issues: list[str] = Field(
        default_factory=list,
        description="List of specific issues found with this integration",
    )


class PolicyRecommendation(BaseModel):
    """A DLP policy recommendation."""

    category: str = Field(description="Policy category (e.g., ai_tool_usage, data_classification)")
    priority: str = Field(description="Priority level: critical, high, medium, low")
    recommendation: str = Field(description="The policy recommendation")
    implementation_steps: list[str] = Field(
        default_factory=list,
        description="Steps to implement this recommendation",
    )


class ScanSummary(BaseModel):
    """Summary statistics for a scan."""

    total_findings: int = Field(default=0, description="Total number of findings")
    critical: int = Field(default=0, description="Number of critical findings")
    high: int = Field(default=0, description="Number of high findings")
    pii_types_found: list[str] = Field(
        default_factory=list,
        description="Types of PII detected (e.g., email, ssn, phone)",
    )
    ai_providers_found: list[str] = Field(
        default_factory=list,
        description="AI providers detected in the codebase",
    )
    unprotected_ai_calls: int = Field(
        default=0,
        description="Number of AI API calls without data protection",
    )


class ScanReport(BaseModel):
    """Complete scan report output."""

    scan_id: str = Field(description="Unique identifier for this scan")
    findings: list[Finding] = Field(
        default_factory=list, description="Data exposure findings"
    )
    secret_findings: list[SecretFinding] = Field(
        default_factory=list, description="Secret findings from leak-finder"
    )
    ai_integrations: list[AIIntegration] = Field(
        default_factory=list, description="Detected AI API integrations"
    )
    summary: ScanSummary = Field(
        default_factory=ScanSummary, description="Summary statistics"
    )
    policy_recommendations: list[PolicyRecommendation] = Field(
        default_factory=list, description="DLP policy recommendations"
    )
