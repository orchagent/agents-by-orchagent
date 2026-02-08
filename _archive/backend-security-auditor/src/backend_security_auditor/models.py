"""Pydantic models for the backend security auditor."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CheckStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class Finding(BaseModel):
    """A single security finding from a check."""

    category: str = Field(description="Checklist category (e.g., 'authentication')")
    category_id: int = Field(description="Checklist item number (1-15)")
    check: str = Field(description="Specific check identifier")
    status: CheckStatus
    severity: str = Field(description="critical, high, medium, low")
    message: str = Field(description="Human-readable description")
    file: Optional[str] = Field(default=None)
    line: Optional[int] = Field(default=None)
    snippet: Optional[str] = Field(default=None, description="Relevant code snippet (truncated)")
    fix: Optional[str] = Field(default=None, description="Suggested remediation")


class CategoryResult(BaseModel):
    """Result for one of the 15 checklist categories."""

    id: int
    name: str
    status: CheckStatus
    findings: list[Finding] = Field(default_factory=list)


# The 15 categories from @0xlelouch_'s checklist
CATEGORIES = {
    1: "Authentication & Password Policy",
    2: "Access Tokens & Refresh Tokens",
    3: "Authorization Checks",
    4: "Input Validation & Output Encoding",
    5: "SQL Safety",
    6: "Rate Limiting & Abuse Protection",
    7: "Secrets Management",
    8: "TLS Everywhere",
    9: "Safe File Handling",
    10: "Logging & Audit Trails",
    11: "Error Handling",
    12: "Dependency Hygiene",
    13: "Data Protection",
    14: "Secure API Defaults",
    15: "Security Observability",
}


class ScanResult(BaseModel):
    """Complete audit result."""

    score: int = Field(description="Overall security score 0-100")
    grade: str = Field(description="Letter grade A-F")
    checklist: list[CategoryResult]
    critical_issues: list[Finding]
    warnings: list[Finding]
    passed_categories: list[str]
    recommendations: list[str]
    files_scanned: int
    summary: str
