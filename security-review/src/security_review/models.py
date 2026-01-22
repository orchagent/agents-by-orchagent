"""Pydantic models for security review orchestrator."""

from typing import Literal, Optional
from pydantic import BaseModel, Field


class ReviewRequest(BaseModel):
    """Request body for reviewing a repository's security."""

    repo_url: str = Field(description="URL of the git repository to review")
    scan_mode: Literal["full", "secrets-only", "deps-only", "patterns-only"] = Field(
        default="full",
        description="What to scan: full, secrets-only, deps-only, or patterns-only",
    )


class SecretFinding(BaseModel):
    """A detected secret from leak-finder."""

    type: str = Field(description="Type of secret (e.g., 'aws_access_key')")
    severity: str = Field(description="Severity level: critical, high, medium, low")
    file: str = Field(description="File path where the secret was found")
    line: int = Field(description="Line number")
    preview: str = Field(description="Redacted preview of the secret")
    recommendation: str = Field(default="", description="Recommended action")
    likely_false_positive: bool = Field(default=False, description="Whether this is likely a false positive")
    fp_reason: Optional[str] = Field(default=None, description="Explanation of why this might be a false positive")


class DependencyFinding(BaseModel):
    """A detected vulnerability from dep-scanner."""

    package: str = Field(description="Name of the vulnerable package")
    version: str = Field(description="Installed version")
    severity: str = Field(description="Severity level: critical, high, medium, low")
    cve: str = Field(description="CVE identifier")
    title: str = Field(description="Brief description")
    fixed_in: str = Field(description="Version that fixes the vulnerability")
    recommendation: str = Field(description="Recommended action")


class PatternFinding(BaseModel):
    """A security pattern finding from internal scanners."""

    category: str = Field(description="Category: frontend_security, api_security, logging")
    pattern: str = Field(description="The pattern that was matched")
    severity: str = Field(description="Severity level: critical, high, medium, low")
    file: str = Field(description="File path where the pattern was found")
    line: int = Field(description="Line number")
    snippet: str = Field(description="Code snippet showing the issue")
    recommendation: str = Field(description="Recommended action")
    likely_false_positive: bool = Field(default=False, description="Whether this is likely a false positive")
    fp_reason: Optional[str] = Field(default=None, description="Explanation of why this might be a false positive")


class FindingsCollection(BaseModel):
    """Collection of all findings by category."""

    secrets: list[SecretFinding] = Field(
        default_factory=list, description="Secrets from leak-finder"
    )
    dependencies: list[DependencyFinding] = Field(
        default_factory=list, description="Dependencies from dep-scanner"
    )
    frontend_security: list[PatternFinding] = Field(
        default_factory=list, description="Frontend security patterns"
    )
    api_security: list[PatternFinding] = Field(
        default_factory=list, description="API security patterns"
    )
    logging: list[PatternFinding] = Field(
        default_factory=list, description="Logging issues"
    )


class ReviewSummary(BaseModel):
    """Summary counts by severity."""

    critical: int = Field(default=0, description="Number of critical issues")
    high: int = Field(default=0, description="Number of high issues")
    medium: int = Field(default=0, description="Number of medium issues")
    low: int = Field(default=0, description="Number of low issues")


class ReviewResponse(BaseModel):
    """Response from a security review."""

    scan_id: str = Field(description="Unique identifier for this review")
    findings: FindingsCollection = Field(
        default_factory=FindingsCollection, description="Real issues by category"
    )
    likely_false_positives: FindingsCollection = Field(
        default_factory=FindingsCollection,
        description="Findings that are likely false positives, with explanations"
    )
    summary: ReviewSummary = Field(
        default_factory=ReviewSummary, description="Summary counts by severity (real issues only)"
    )
    recommendations: list[str] = Field(
        default_factory=list, description="Top actionable recommendations"
    )
