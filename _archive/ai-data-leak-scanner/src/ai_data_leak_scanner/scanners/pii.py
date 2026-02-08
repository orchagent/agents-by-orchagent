"""PII pattern scanner.

Detects personally identifiable information patterns in source code:
- Email addresses (hardcoded, not just configs)
- Phone numbers (various formats)
- SSN patterns (XXX-XX-XXXX)
- Credit card numbers (Luhn-validatable patterns)
- IP addresses (in non-config contexts)
- Name fields populated with real data
- Physical addresses
- Date of birth patterns
- Medical record numbers
"""

import re
from pathlib import Path
from typing import NamedTuple

from ..models import Finding, FindingCategory, RiskLevel
from .common import walk_source_files, read_file_lines, get_display_path, SOURCE_EXTENSIONS


class PIIPattern(NamedTuple):
    """A PII detection pattern."""

    name: str
    risk_level: RiskLevel
    data_type: str
    description: str
    remediation: str
    regex: re.Pattern


# Test file indicators (lower severity for test files)
TEST_INDICATORS = [
    "/tests/", "/test/", "/__tests__/", "/spec/",
    "test_", "_test.", ".test.", ".spec.",
    "/fixtures/", "/testdata/", "/mock/", "/mocks/",
]


def _is_test_file(file_path: Path) -> bool:
    """Check if a file is a test file."""
    path_str = str(file_path).lower()
    return any(indicator in path_str for indicator in TEST_INDICATORS)


# PII patterns to detect
PII_PATTERNS: list[PIIPattern] = [
    # Email addresses hardcoded in source (not config keys, but actual email values)
    PIIPattern(
        name="hardcoded_email",
        risk_level=RiskLevel.medium,
        data_type="email",
        description="Hardcoded email address found in source code",
        remediation="Remove hardcoded email addresses; use environment variables or configuration files",
        regex=re.compile(
            r'(?:=\s*|:\s*|["\x27])[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:["\x27]|\s|$)',
        ),
    ),
    # Phone numbers - various formats
    PIIPattern(
        name="phone_number",
        risk_level=RiskLevel.medium,
        data_type="phone",
        description="Phone number pattern detected in source code",
        remediation="Remove hardcoded phone numbers; use redacted test data or environment configuration",
        regex=re.compile(
            r'(?:["\x27]\s*|=\s*["\x27])'
            r'(?:'
            r'\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
            r'|\+\d{1,3}[-.\s]?\d{4,14}'
            r')'
            r'(?:["\x27])',
        ),
    ),
    # SSN patterns
    PIIPattern(
        name="ssn_pattern",
        risk_level=RiskLevel.critical,
        data_type="ssn",
        description="Social Security Number pattern detected",
        remediation="Remove SSN data immediately; never store SSNs in source code",
        regex=re.compile(
            r'(?:["\x27]\s*|=\s*["\x27])\d{3}-\d{2}-\d{4}(?:["\x27])',
        ),
    ),
    # Credit card number patterns (13-19 digits, possibly with separators)
    PIIPattern(
        name="credit_card_number",
        risk_level=RiskLevel.critical,
        data_type="credit_card",
        description="Credit card number pattern detected",
        remediation="Remove credit card numbers immediately; use tokenized test data",
        regex=re.compile(
            r'(?:["\x27]\s*|=\s*["\x27])'
            r'(?:'
            r'4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}'
            r'|5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}'
            r'|3[47]\d{1}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3}'
            r'|6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}'
            r')'
            r'(?:["\x27])',
        ),
    ),
    # IP addresses in non-config contexts (not 127.0.0.1 or 0.0.0.0)
    PIIPattern(
        name="ip_address",
        risk_level=RiskLevel.low,
        data_type="ip_address",
        description="IP address found in source code (non-localhost)",
        remediation="Remove hardcoded IP addresses; use configuration or environment variables",
        regex=re.compile(
            r'(?:["\x27]\s*|=\s*["\x27])'
            r'(?!127\.0\.0\.1|0\.0\.0\.0|localhost|255\.255\.255\.\d)'
            r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
            r'(?:["\x27])',
        ),
    ),
    # Name fields populated with real-looking data
    PIIPattern(
        name="name_field_data",
        risk_level=RiskLevel.medium,
        data_type="person_name",
        description="Name field populated with what appears to be real personal data",
        remediation="Use clearly fake test data (e.g., 'Jane Doe') instead of real-looking names",
        regex=re.compile(
            r'(?:first_name|last_name|full_name|customer_name|user_name|patient_name)'
            r'\s*[:=]\s*["\x27][A-Z][a-z]+(?:\s[A-Z][a-z]+)?["\x27]',
        ),
    ),
    # Physical address patterns
    PIIPattern(
        name="physical_address",
        risk_level=RiskLevel.medium,
        data_type="address",
        description="Physical address pattern detected in source code",
        remediation="Remove hardcoded addresses; use clearly fake test addresses",
        regex=re.compile(
            r'["\x27]\d{1,5}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+'
            r'(?:St|Ave|Blvd|Dr|Ln|Rd|Way|Ct|Pl|Cir|Ter|Loop)'
            r'(?:\.?\s*,?\s*[A-Z][a-zA-Z]+)?["\x27]',
        ),
    ),
    # Date of birth patterns
    PIIPattern(
        name="date_of_birth",
        risk_level=RiskLevel.medium,
        data_type="date_of_birth",
        description="Date of birth field with data detected",
        remediation="Remove real dates of birth; use clearly fake test dates",
        regex=re.compile(
            r'(?:date_of_birth|dob|birth_date|birthdate|birthday)'
            r'\s*[:=]\s*["\x27]\d{4}[-/]\d{2}[-/]\d{2}["\x27]',
            re.IGNORECASE,
        ),
    ),
    # Medical record number patterns
    PIIPattern(
        name="medical_record_number",
        risk_level=RiskLevel.critical,
        data_type="medical_record",
        description="Medical record number pattern detected",
        remediation="Remove medical record numbers immediately; use tokenized test data",
        regex=re.compile(
            r'(?:medical_record|mrn|patient_id|health_id)'
            r'\s*[:=]\s*["\x27]\w{2,4}-?\d{4,10}["\x27]',
            re.IGNORECASE,
        ),
    ),
]


def _scan_file_for_pii(
    file_path: Path,
    base_path: Path,
) -> list[Finding]:
    """Scan a single file for PII patterns."""
    findings: list[Finding] = []
    is_test = _is_test_file(file_path)
    display_path = get_display_path(file_path, base_path)
    lines = read_file_lines(file_path)

    for line_num, line_content in lines:
        # Skip comment-only lines
        stripped = line_content.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue

        for pattern in PII_PATTERNS:
            if pattern.regex.search(line_content):
                # Skip common false positives
                lower_line = line_content.lower()

                # Skip import/require lines
                if lower_line.strip().startswith(("import ", "from ", "require(")):
                    continue

                # Skip example/placeholder patterns
                if any(fp in lower_line for fp in [
                    "example.com", "example.org", "test@", "user@",
                    "placeholder", "xxx-xx-xxxx", "000-00-0000",
                    "jane doe", "john doe", "foo@bar",
                    "noreply@", "no-reply@", "schema", "migration",
                ]):
                    continue

                risk = pattern.risk_level
                if is_test and risk in (RiskLevel.critical, RiskLevel.high):
                    risk = RiskLevel.low

                findings.append(
                    Finding(
                        category=FindingCategory.pii_exposure,
                        risk_level=risk,
                        title=pattern.description,
                        file=display_path,
                        line=line_num,
                        description=(
                            f"{pattern.description} at line {line_num}. "
                            f"Data type at risk: {pattern.data_type}."
                        ),
                        data_types_at_risk=[pattern.data_type],
                        remediation=pattern.remediation,
                    )
                )

    return findings


def scan_pii_patterns(
    repo_path: str | Path,
    exclude_dirs: set[str] | None = None,
) -> list[Finding]:
    """Scan a repository for PII patterns in source code.

    Args:
        repo_path: Path to the repository root.
        exclude_dirs: Additional directory names to skip.

    Returns:
        List of Finding objects for detected PII patterns.
    """
    base = Path(repo_path)
    findings: list[Finding] = []

    for file_path in walk_source_files(base, extensions=SOURCE_EXTENSIONS, exclude_dirs=exclude_dirs):
        file_findings = _scan_file_for_pii(file_path, base)
        findings.extend(file_findings)

    return findings
