"""File and directory scanning for secrets."""

import os
import re
from pathlib import Path

from .models import Finding
from .patterns import SECRET_PATTERNS

# Directories to skip during scanning
SKIP_DIRS = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    ".coverage",
    "vendor",
    "target",
}

# Binary file extensions to skip
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".pyc", ".pyo", ".class", ".o",
    ".lock", ".min.js", ".min.css",
}


def redact_secret(value: str) -> str:
    """Redact a secret value, showing only first 4 and last 4 chars."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


# Patterns that indicate fake/test data
FAKE_VALUE_INDICATORS = [
    "fake", "test", "example", "placeholder", "xxx", "dummy", "sample",
    "changeme", "your_", "my_", "todo", "fixme", "replace",
]

FAKE_CREDENTIAL_PATTERNS = [
    r"user:pass@localhost",
    r"admin:password@",
    r"password123",
    r"secret12345",
    r"secret_12345",
    r"sk_test_secret",
    r"api_key_here",
]

def is_fake_value(value: str) -> tuple[bool, str | None]:
    """Check if a value looks like fake test data. Returns (is_fake, indicator_found)."""
    value_lower = value.lower()
    for indicator in FAKE_VALUE_INDICATORS:
        if indicator in value_lower:
            return True, indicator
    for pattern in FAKE_CREDENTIAL_PATTERNS:
        if re.search(pattern, value_lower):
            return True, pattern
    return False, None


# File context indicators
DOC_INDICATORS = ["/docs/", ".md", "readme", "changelog", "example"]
TEST_INDICATORS = ["/tests/", "/test/", "test_", "_test.", ".test.", ".spec."]

def get_file_context_reason(file_path: str) -> str | None:
    """Return reasoning if file is likely docs/test, else None."""
    path_lower = file_path.lower()
    for ind in DOC_INDICATORS:
        if ind in path_lower:
            return f"File appears to be documentation ({ind} in path)"
    for ind in TEST_INDICATORS:
        if ind in path_lower:
            return f"File appears to be a test ({ind} in path)"
    return None


def is_binary_file(file_path: Path) -> bool:
    """Check if a file is binary based on extension or content."""
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except (IOError, OSError):
        return True
    return False


def get_recommendation(pattern_name: str, severity: str) -> str:
    """Generate a recommendation based on the finding type."""
    recommendations = {
        "critical": "Rotate this credential immediately and remove from codebase.",
        "high": "Rotate this credential and use environment variables instead.",
        "medium": "Consider using environment variables for this value.",
        "low": "Review if this should be in the codebase.",
        "info": "Informational finding - review as needed.",
    }
    return recommendations.get(severity, "Review this finding.")


def scan_file(file_path: str | Path, base_path: str | Path | None = None) -> list[Finding]:
    """
    Scan a single file for secrets.

    Args:
        file_path: Path to the file to scan
        base_path: Base path for relative file paths in findings

    Returns:
        List of Finding objects
    """
    file_path = Path(file_path)

    if not file_path.exists() or not file_path.is_file():
        return []

    if is_binary_file(file_path):
        return []

    findings = []

    # Determine relative path for display
    if base_path:
        try:
            display_path = str(file_path.relative_to(base_path))
        except ValueError:
            display_path = str(file_path)
    else:
        display_path = str(file_path)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for pattern_name, pattern_info in SECRET_PATTERNS.items():
                    matches = pattern_info["regex"].finditer(line)
                    for match in matches:
                        # Get the matched value (use group 1 if it exists, else group 0)
                        try:
                            secret_value = match.group(1) if match.lastindex else match.group(0)
                        except IndexError:
                            secret_value = match.group(0)

                        # Build reasoning from multiple signals
                        reasons = []
                        if file_context_reason := get_file_context_reason(display_path):
                            reasons.append(file_context_reason)
                        is_fake, fake_indicator = is_fake_value(secret_value)
                        if is_fake:
                            reasons.append(f"Value looks like test data (contains '{fake_indicator}')")

                        fp_reason = "; ".join(reasons) if reasons else None

                        finding = Finding(
                            type=pattern_name,
                            severity=pattern_info["severity"],
                            file=display_path,
                            line=line_num,
                            preview=redact_secret(secret_value),
                            in_history=False,
                            rotated=False,
                            recommendation=get_recommendation(pattern_name, pattern_info["severity"]),
                            likely_false_positive=fp_reason is not None,
                            fp_reason=fp_reason,
                        )
                        findings.append(finding)
    except (IOError, OSError):
        pass

    return findings


def scan_directory(dir_path: str | Path, base_path: str | Path | None = None) -> list[Finding]:
    """
    Recursively scan a directory for secrets.

    Args:
        dir_path: Path to the directory to scan
        base_path: Base path for relative file paths in findings

    Returns:
        List of Finding objects
    """
    dir_path = Path(dir_path)

    if not dir_path.exists() or not dir_path.is_dir():
        return []

    if base_path is None:
        base_path = dir_path

    findings = []

    for root, dirs, files in os.walk(dir_path):
        # Filter out directories to skip
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for file_name in files:
            file_path = Path(root) / file_name
            file_findings = scan_file(file_path, base_path)
            findings.extend(file_findings)

    return findings
