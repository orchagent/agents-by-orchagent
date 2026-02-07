"""Pydantic models for react-security-scanner."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingCategory(str, Enum):
    """Categories of security findings."""

    cve = "cve"
    rsc_security = "rsc_security"
    server_actions = "server_actions"
    env_exposure = "env_exposure"
    xss = "xss"
    ssrf = "ssrf"
    auth = "auth"
    config = "config"


class Finding(BaseModel):
    """A security finding from pattern scanning."""

    category: FindingCategory = Field(description="Category of the finding")
    severity: Severity = Field(description="Severity level")
    title: str = Field(description="Short title describing the issue")
    file: Optional[str] = Field(default=None, description="File path where the issue was found")
    line: Optional[int] = Field(default=None, description="Line number")
    description: str = Field(description="Detailed description of the vulnerability")
    remediation: str = Field(description="Fix command or code to remediate the issue")
    cwe: Optional[str] = Field(default=None, description="CWE identifier, e.g. CWE-79")


class DependencyFinding(BaseModel):
    """A CVE finding from dep-scanner."""

    package: str = Field(description="Name of the vulnerable package")
    version: str = Field(description="Installed version")
    severity: Severity = Field(description="Severity level")
    cve: str = Field(description="CVE identifier")
    title: str = Field(description="Brief description of the vulnerability")
    fixed_in: str = Field(description="Version that fixes the vulnerability")
    recommendation: str = Field(description="Recommended action")


class ScanSummary(BaseModel):
    """Summary counts for a scan report."""

    critical: int = Field(default=0, description="Number of critical findings")
    high: int = Field(default=0, description="Number of high findings")
    medium: int = Field(default=0, description="Number of medium findings")
    low: int = Field(default=0, description="Number of low findings")
    total: int = Field(default=0, description="Total number of findings")
    framework_detected: str = Field(default="unknown", description="Detected framework")
    has_app_router: bool = Field(default=False, description="Whether the project uses App Router")
    has_server_components: bool = Field(default=False, description="Whether the project uses Server Components")


class ScanReport(BaseModel):
    """Full scan report output."""

    scan_id: str = Field(description="Unique identifier for this scan")
    repo_url: Optional[str] = Field(default=None, description="URL of the scanned repository")
    findings: list[Finding] = Field(default_factory=list, description="Pattern scan findings")
    dependency_findings: list[DependencyFinding] = Field(
        default_factory=list, description="CVE findings from dep-scanner"
    )
    summary: ScanSummary = Field(default_factory=ScanSummary, description="Summary counts")
    recommendations: list[str] = Field(
        default_factory=list, description="Top prioritized recommendations"
    )
