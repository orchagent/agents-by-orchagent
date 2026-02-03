"""Pydantic models for VPS security checker."""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class CheckStatus(str, Enum):
    """Status of a security check."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class CheckResult(BaseModel):
    """Individual security check result."""

    check: str = Field(description="Name of the check (e.g., 'fail2ban', 'ufw')")
    status: CheckStatus = Field(description="Result status: PASS, WARN, or FAIL")
    severity: str = Field(description="Severity level: critical, high, medium, low")
    message: str = Field(description="Human-readable description of the finding")
    fix_available: bool = Field(default=False, description="Whether an automated fix exists")
    fix_agent: Optional[str] = Field(default=None, description="Agent that can fix this (e.g., 'joe/vps-fixer')")


class AttackSummary(BaseModel):
    """Summary of detected attack activity on the server."""

    failed_logins_total: int = Field(default=0, description="Total failed login attempts")
    failed_logins_24h: int = Field(default=0, description="Failed login attempts in last 24 hours")
    unique_attacker_ips: int = Field(default=0, description="Number of unique attacker IP addresses")
    top_usernames: list[str] = Field(default_factory=list, description="Most commonly targeted usernames")
    currently_banned: int = Field(default=0, description="Number of currently banned IPs (fail2ban)")


class BreachIndicators(BaseModel):
    """Indicators of potential system compromise."""

    found: bool = Field(default=False, description="Whether any breach indicators were found")
    suspicious_files: list[str] = Field(default_factory=list, description="Suspicious files found in /tmp, /var/tmp, etc.")
    unknown_processes: list[str] = Field(default_factory=list, description="Unknown or suspicious running processes")
    unknown_ssh_keys: list[str] = Field(default_factory=list, description="SSH keys not recognized by the user")


class ScanInput(BaseModel):
    """Input parameters for VPS security scan."""

    dry_run: bool = Field(default=True, description="Run in dry-run mode (read-only)")
    skip_attack_metrics: bool = Field(default=False, description="Skip attack metrics collection")


class ScanResult(BaseModel):
    """Result of a VPS security scan."""

    host: str = Field(description="Hostname of the scanned server")
    os: str = Field(description="Operating system information (e.g., 'Ubuntu 24.04 LTS')")
    scan_time: datetime = Field(description="Timestamp of the scan in ISO 8601 format")
    security_score: int = Field(description="Security score (0-100)")
    max_score: int = Field(default=100, description="Maximum possible score")
    critical_issues: list[CheckResult] = Field(default_factory=list, description="Critical security issues found")
    warnings: list[CheckResult] = Field(default_factory=list, description="Warning-level issues found")
    passed: list[CheckResult] = Field(default_factory=list, description="Checks that passed")
    attack_summary: AttackSummary = Field(default_factory=AttackSummary, description="Summary of attack activity")
    breach_indicators: BreachIndicators = Field(default_factory=BreachIndicators, description="Potential breach indicators")
    recommendations: list[str] = Field(default_factory=list, description="Recommended actions to improve security")


# Keep legacy models for backward compatibility if needed
class Finding(BaseModel):
    """A security finding from the VPS audit (legacy model)."""

    category: str = Field(description="Category of the finding (e.g., 'ssh', 'firewall', 'kernel')")
    check: str = Field(description="Specific check that identified the issue")
    severity: str = Field(description="Severity level: critical, high, medium, low")
    title: str = Field(description="Short title describing the finding")
    description: str = Field(description="Detailed description of the security issue")
    current_value: Optional[str] = Field(default=None, description="Current configuration value")
    recommended_value: Optional[str] = Field(default=None, description="Recommended configuration value")
    remediation: str = Field(default="", description="Steps to fix the issue")
    fixable: bool = Field(default=False, description="Whether this can be auto-fixed by vps-fixer")


class AttackMetrics(BaseModel):
    """Metrics about detected attacks on the server (legacy model)."""

    failed_ssh_attempts_24h: int = Field(default=0, description="Failed SSH login attempts in last 24 hours")
    unique_attacker_ips: int = Field(default=0, description="Number of unique IPs attempting attacks")
    banned_ips_count: int = Field(default=0, description="Number of currently banned IPs")
    top_attacked_services: list[str] = Field(default_factory=list, description="Most targeted services")
