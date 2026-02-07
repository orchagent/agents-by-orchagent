"""Logging leak scanner.

Detects logging statements that may output PII or sensitive data:
- Logging statements that might output PII
- Request/response logging that includes full bodies
- AI API call logging that might log prompts containing sensitive data
- Error logging that dumps full stack traces with sensitive context
"""

import re
from pathlib import Path
from typing import NamedTuple

from ..models import Finding, FindingCategory, RiskLevel
from .common import walk_source_files, read_file_lines, get_display_path, SOURCE_EXTENSIONS


class LogPattern(NamedTuple):
    """A logging leak detection pattern."""

    name: str
    risk_level: RiskLevel
    description: str
    remediation: str
    regex: re.Pattern


# Logging patterns that may leak sensitive data
LOG_PATTERNS: list[LogPattern] = [
    # Python logging with PII variables
    LogPattern(
        name="python_log_pii",
        risk_level=RiskLevel.high,
        description="Python logging statement may output PII data",
        remediation="Add PII redaction before logging; never log raw user data",
        regex=re.compile(
            r'(?:logger|logging)\.(?:info|debug|warning|error|critical)\s*\('
            r'[^)]*(?:email|phone|ssn|address|first_name|last_name|password|credit_card)',
            re.IGNORECASE,
        ),
    ),
    # Console.log with PII
    LogPattern(
        name="console_log_pii",
        risk_level=RiskLevel.high,
        description="Console.log statement may output PII data",
        remediation="Remove PII from console.log statements; use redaction",
        regex=re.compile(
            r'console\.(?:log|info|warn|debug|error)\s*\('
            r'[^)]*(?:email|phone|ssn|address|firstName|lastName|password|creditCard)',
            re.IGNORECASE,
        ),
    ),
    # Print statements with PII
    LogPattern(
        name="print_pii",
        risk_level=RiskLevel.high,
        description="Print statement may output PII data",
        remediation="Remove PII from print statements; use proper logging with redaction",
        regex=re.compile(
            r'print\s*\(\s*(?:'
            r'(?:email|phone|ssn|address|password|user_data|customer|patient)\b'
            r'|f["\x27][^"\x27]*\{(?:email|phone|ssn|address|password|user_data|customer|patient)\}'
            r')',
            re.IGNORECASE,
        ),
    ),
    # Request/response body logging
    LogPattern(
        name="request_body_logging",
        risk_level=RiskLevel.high,
        description="Full request/response body being logged - may contain PII",
        remediation="Log only non-sensitive request metadata; redact body contents",
        regex=re.compile(
            r'(?:logger|logging|console)\.(?:log|info|debug|warning|error)\s*\('
            r'[^)]*(?:request\.body|req\.body|response\.body|res\.body|request\.json|request\.data)',
            re.IGNORECASE,
        ),
    ),
    # AI prompt logging
    LogPattern(
        name="ai_prompt_logging",
        risk_level=RiskLevel.critical,
        description="AI API prompt or response being logged - may contain sensitive data passed to AI",
        remediation="Never log full AI prompts or responses; they may contain user PII. Log only metadata.",
        regex=re.compile(
            r'(?:logger|logging|console|print)\s*[\.(]\s*'
            r'[^)]*(?:prompt|completion|ai_response|llm_response|chat_message|messages\[)',
            re.IGNORECASE,
        ),
    ),
    # Full object/record logging
    LogPattern(
        name="full_record_logging",
        risk_level=RiskLevel.medium,
        description="Full data record being logged - may contain PII fields",
        remediation="Log only non-sensitive fields; implement a logging serializer that strips PII",
        regex=re.compile(
            r'(?:logger|logging|console|print)\s*[\.(]\s*'
            r'[^)]*(?:user_record|customer_record|patient_record|employee_record|record\b|\.to_dict|\.dict\(\)|__dict__|json\.dumps|JSON\.stringify)',
            re.IGNORECASE,
        ),
    ),
    # Stack trace with sensitive context in error handlers
    LogPattern(
        name="error_context_leak",
        risk_level=RiskLevel.medium,
        description="Error handler may expose sensitive data in stack traces",
        remediation="Sanitize error context before logging; strip sensitive variables from stack traces",
        regex=re.compile(
            r'(?:except|catch)\s*.*\n.*(?:traceback|stack_trace|format_exc|err\.stack)',
            re.IGNORECASE,
        ),
    ),
]


def _scan_file_for_logging(
    file_path: Path,
    base_path: Path,
) -> list[Finding]:
    """Scan a single file for logging leak patterns."""
    findings: list[Finding] = []
    display_path = get_display_path(file_path, base_path)
    lines = read_file_lines(file_path)

    for line_num, line_content in lines:
        # Skip comment-only lines
        stripped = line_content.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue

        for pattern in LOG_PATTERNS:
            if pattern.regex.search(line_content):
                data_types = []
                lower = line_content.lower()
                if "email" in lower:
                    data_types.append("email")
                if "phone" in lower:
                    data_types.append("phone")
                if "ssn" in lower:
                    data_types.append("ssn")
                if "password" in lower:
                    data_types.append("password")
                if "address" in lower:
                    data_types.append("address")
                if "credit_card" in lower or "creditcard" in lower:
                    data_types.append("credit_card")
                if "prompt" in lower or "completion" in lower or "ai_response" in lower:
                    data_types.append("ai_prompt_data")

                if not data_types:
                    data_types = ["unclassified_sensitive_data"]

                findings.append(
                    Finding(
                        category=FindingCategory.logging_leak,
                        risk_level=pattern.risk_level,
                        title=pattern.description,
                        file=display_path,
                        line=line_num,
                        description=(
                            f"{pattern.description} at line {line_num}. "
                            f"Data types at risk: {', '.join(data_types)}."
                        ),
                        data_types_at_risk=data_types,
                        remediation=pattern.remediation,
                    )
                )

    return findings


def scan_logging_leaks(
    repo_path: str | Path,
    exclude_dirs: set[str] | None = None,
) -> list[Finding]:
    """Scan a repository for logging statements that may leak sensitive data.

    Args:
        repo_path: Path to the repository root.
        exclude_dirs: Additional directory names to skip.

    Returns:
        List of Finding objects for detected logging leaks.
    """
    base = Path(repo_path)
    findings: list[Finding] = []

    for file_path in walk_source_files(base, extensions=SOURCE_EXTENSIONS, exclude_dirs=exclude_dirs):
        file_findings = _scan_file_for_logging(file_path, base)
        findings.extend(file_findings)

    return findings
