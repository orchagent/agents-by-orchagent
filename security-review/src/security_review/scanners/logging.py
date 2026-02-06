"""Logging security pattern scanner.

Detects security anti-patterns in logging code:
- console.log with password/secret/key variables
- err.stack exposed in API responses
- Raw error objects sent to clients
"""

import re
from pathlib import Path
from typing import NamedTuple

from ..models import PatternFinding
from .common import walk_repo


class PatternMatch(NamedTuple):
    """A matched pattern with its metadata."""

    name: str
    severity: str
    description: str
    recommendation: str
    regex: re.Pattern


# Logging security patterns to detect
LOGGING_PATTERNS: list[PatternMatch] = [
    # console.log with sensitive data
    PatternMatch(
        name="console_log_password",
        severity="high",
        description="Logging password or credential data",
        recommendation="Remove logging of sensitive data; use redaction or remove entirely",
        regex=re.compile(
            r'console\.(?:log|info|warn|debug|error)\s*\([^)]*(?:password|passwd|pwd|credential)',
            re.IGNORECASE,
        ),
    ),
    PatternMatch(
        name="console_log_secret",
        severity="high",
        description="Logging secret or API key data",
        recommendation="Remove logging of secrets; never log API keys or tokens",
        regex=re.compile(
            r'console\.(?:log|info|warn|debug|error)\s*\(\s*(?:'
            r'(?:secret|apiKey|api_key|token|bearer|auth)\b'  # Direct variable
            r'|`[^`]*\$\{(?:secret|apiKey|api_key|token|bearer|auth)\}'  # Template literal
            r')',
            re.IGNORECASE,
        ),
    ),
    PatternMatch(
        name="console_log_private_key",
        severity="critical",
        description="Logging private key data",
        recommendation="Remove immediately; private keys must never be logged",
        regex=re.compile(
            r'console\.(?:log|info|warn|debug|error)\s*\([^)]*(?:privateKey|private_key|privkey)',
            re.IGNORECASE,
        ),
    ),
    # Python logging with sensitive data
    PatternMatch(
        name="python_log_password",
        severity="high",
        description="Python logging password or credential data",
        recommendation="Remove logging of sensitive data; use redaction or remove entirely",
        regex=re.compile(
            r'(?:logger|logging)\.(?:info|debug|warning|error|critical)\s*\([^)]*(?:password|passwd|pwd|credential)',
            re.IGNORECASE,
        ),
    ),
    PatternMatch(
        name="python_log_secret",
        severity="high",
        description="Python logging secret or API key data",
        recommendation="Remove logging of secrets; never log API keys or tokens",
        regex=re.compile(
            r'(?:logger|logging)\.(?:info|debug|warning|error|critical)\s*\([^)]*(?:secret|api_key|apikey|token|bearer)',
            re.IGNORECASE,
        ),
    ),
    # err.stack exposed in responses
    PatternMatch(
        name="stack_trace_in_response",
        severity="high",
        description="Stack trace exposed in API response",
        recommendation="Return generic error messages; log stack traces server-side only",
        regex=re.compile(
            r'(?:res\.(?:json|send|status)\s*\([^)]*|return\s+\{[^}]*|(?:body|response|data)\s*[=:]\s*\{[^}]*)(?:err|error|e)\.stack',
            re.IGNORECASE,
        ),
    ),
    PatternMatch(
        name="stack_trace_property_access",
        severity="high",
        description="Error stack trace accessed in response context",
        recommendation="Log stack traces server-side; send only user-friendly messages to clients",
        regex=re.compile(
            r'(?:message|error|detail)\s*:\s*(?:err|error|e)\.stack',
            re.IGNORECASE,
        ),
    ),
    # Raw error object sent to client
    PatternMatch(
        name="raw_error_in_response",
        severity="medium",
        description="Raw error object sent in API response",
        recommendation="Sanitize errors before sending; expose only safe fields",
        regex=re.compile(
            r'res\.(?:json|send)\s*\(\s*(?:err|error|e)\s*\)',
            re.IGNORECASE,
        ),
    ),
    PatternMatch(
        name="error_spread_in_response",
        severity="medium",
        description="Error object spread into response - may leak internal details",
        recommendation="Explicitly select safe error fields instead of spreading",
        regex=re.compile(
            r'(?:res\.(?:json|send)|return)\s*\(\s*\{\s*\.\.\.(?:err|error|e)',
            re.IGNORECASE,
        ),
    ),
    # FastAPI/Python verbose error responses
    PatternMatch(
        name="fastapi_exception_detail",
        severity="medium",
        description="Exception details exposed in FastAPI HTTPException",
        recommendation="Use generic error messages; log details server-side",
        regex=re.compile(
            r'HTTPException\s*\([^)]*detail\s*=\s*(?:str\s*\(\s*)?(?:e|err|error|exc)',
            re.IGNORECASE,
        ),
    ),
    PatternMatch(
        name="traceback_in_response",
        severity="high",
        description="Python traceback exposed in response",
        recommendation="Never send tracebacks to clients; log them server-side only",
        regex=re.compile(
            r'(?:return|response|JSONResponse|HTTPException).*(?:traceback\.format_exc|format_exception)',
            re.IGNORECASE,
        ),
    ),
    # Print statements with sensitive data (often left from debugging)
    PatternMatch(
        name="print_sensitive_data",
        severity="high",
        description="Print statement with potentially sensitive data",
        recommendation="Remove debug print statements; use proper logging with redaction",
        regex=re.compile(
            r'print\s*\(\s*(?:'
            r'(?:password|secret|token|api_key|credential)\b'  # Direct variable
            r'|f["\'][^"\']*\{(?:password|secret|token|api_key|credential)\}'  # f-string interpolation
            r')',
            re.IGNORECASE,
        ),
    ),
]

# File extensions to scan for logging patterns
LOGGING_EXTENSIONS = {".py", ".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs"}

# Test file indicators (to lower severity for test files)
TEST_INDICATORS = [
    "/tests/",
    "/test/",
    "/__tests__/",
    "/spec/",
    "test_",
    "_test.",
    ".test.",
    ".spec.",
]


def _is_test_file(file_path: Path) -> bool:
    """Check if a file is a test file."""
    path_str = str(file_path).lower()
    return any(indicator in path_str for indicator in TEST_INDICATORS)


def _is_scannable_file(file_path: Path) -> bool:
    """Check if a file should be scanned for logging patterns."""
    return file_path.suffix.lower() in LOGGING_EXTENSIONS


def scan_file(file_path: Path, base_path: Path) -> list[PatternFinding]:
    """Scan a single file for logging security patterns."""
    if not _is_scannable_file(file_path):
        return []

    findings = []
    is_test = _is_test_file(file_path)

    # Get display path
    try:
        display_path = str(file_path.relative_to(base_path))
    except ValueError:
        display_path = str(file_path)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for pattern in LOGGING_PATTERNS:
                    if pattern.regex.search(line):
                        # Get a snippet (trim whitespace, limit length)
                        snippet = line.strip()[:100]
                        if len(line.strip()) > 100:
                            snippet += "..."

                        # Lower severity for test files (still report but less critical)
                        severity = pattern.severity
                        fp_reason = None
                        if is_test:
                            if severity in ("critical", "high"):
                                severity = "low"
                            fp_reason = "Finding is in a test file - may be intentional for testing"

                        findings.append(
                            PatternFinding(
                                category="logging",
                                pattern=pattern.name,
                                severity=severity,
                                file=display_path,
                                line=line_num,
                                snippet=snippet,
                                recommendation=pattern.recommendation,
                                likely_false_positive=fp_reason is not None,
                                fp_reason=fp_reason,
                            )
                        )
    except (IOError, OSError):
        pass

    return findings


def scan_logging_patterns(
    repo_path: str | Path,
    exclude: list[str] | None = None,
) -> list[PatternFinding]:
    """
    Scan a repository for logging security patterns.

    Args:
        repo_path: Path to the repository root
        exclude: Additional directory names to skip

    Returns:
        List of PatternFinding objects for detected issues
    """
    repo_path = Path(repo_path)
    extra_skip = set(exclude) if exclude else None

    findings = []

    for root_path, file_names in walk_repo(repo_path, extra_skip_dirs=extra_skip):
        for file_name in file_names:
            file_path = root_path / file_name
            file_findings = scan_file(file_path, repo_path)
            findings.extend(file_findings)

    return findings
