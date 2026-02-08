"""XSS pattern scanner for React/Next.js projects.

Detects:
- dangerouslySetInnerHTML with user/external data
- innerHTML assignments in useEffect/useRef
- Unsanitized URL parameters in href attributes (javascript: protocol)
- document.write usage
- Template literals in JSX with unsanitized input
"""

import re
from pathlib import Path

from ..models import Finding, FindingCategory, Severity
from .common import walk_source_files, read_file_lines


# dangerouslySetInnerHTML patterns
DANGEROUS_INNER_HTML = re.compile(
    r'dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:',
)

# dangerouslySetInnerHTML with dynamic/user data (not a static string)
DANGEROUS_INNER_HTML_DYNAMIC = re.compile(
    r"""dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(?!"""
    r"""['"`][^'"`]*['"`]\s*\})"""
    r"""[^}]+\}\}""",
)

# innerHTML assignment
INNER_HTML_ASSIGNMENT = re.compile(
    r'\.innerHTML\s*=',
)

# javascript: protocol
JAVASCRIPT_PROTOCOL = re.compile(
    r'javascript\s*:',
    re.IGNORECASE,
)

# document.write usage
DOCUMENT_WRITE = re.compile(
    r'document\.write(?:ln)?\s*\(',
)

# Template literal with potentially unsanitized content in HTML context
UNSAFE_TEMPLATE_HTML = re.compile(
    r'(?:__html|innerHTML)\s*(?:=|:)\s*`[^`]*\$\{',
)


def scan_xss_patterns(
    project_path: str | Path,
    base_path: str | Path | None = None,
) -> list[Finding]:
    """Scan for XSS vulnerability patterns."""
    project_path = Path(project_path)
    base_path = Path(base_path) if base_path else project_path
    findings: list[Finding] = []

    for file_path in walk_source_files(project_path):
        lines = read_file_lines(file_path)
        if not lines:
            continue

        try:
            display_path = str(file_path.relative_to(base_path))
        except ValueError:
            display_path = str(file_path)

        for line_num, line in lines:
            if DANGEROUS_INNER_HTML_DYNAMIC.search(line):
                findings.append(Finding(
                    category=FindingCategory.xss,
                    severity=Severity.high,
                    title="dangerouslySetInnerHTML with dynamic content",
                    file=display_path,
                    line=line_num,
                    description=(
                        "dangerouslySetInnerHTML is used with dynamic content. "
                        "If this content comes from user input, API responses, or a database, "
                        "it can lead to XSS attacks."
                    ),
                    remediation=(
                        "Sanitize HTML before rendering:\n"
                        "  import DOMPurify from 'dompurify';\n"
                        "  <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />"
                    ),
                    cwe="CWE-79",
                ))
            elif DANGEROUS_INNER_HTML.search(line):
                findings.append(Finding(
                    category=FindingCategory.xss,
                    severity=Severity.medium,
                    title="dangerouslySetInnerHTML usage",
                    file=display_path,
                    line=line_num,
                    description=(
                        "dangerouslySetInnerHTML bypasses React XSS protections. "
                        "Verify the HTML content is from a trusted source and sanitized."
                    ),
                    remediation=(
                        "Sanitize with DOMPurify:\n"
                        "  import DOMPurify from 'dompurify';\n"
                        "  dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}"
                    ),
                    cwe="CWE-79",
                ))

            if INNER_HTML_ASSIGNMENT.search(line):
                findings.append(Finding(
                    category=FindingCategory.xss,
                    severity=Severity.high,
                    title="Direct innerHTML assignment",
                    file=display_path,
                    line=line_num,
                    description=(
                        "Direct innerHTML assignment bypasses React XSS protections. "
                        "Dangerous in useEffect or useRef callbacks."
                    ),
                    remediation=(
                        "Use React built-in rendering instead of innerHTML. "
                        "If raw HTML is needed, sanitize with DOMPurify first."
                    ),
                    cwe="CWE-79",
                ))

            if JAVASCRIPT_PROTOCOL.search(line):
                findings.append(Finding(
                    category=FindingCategory.xss,
                    severity=Severity.high,
                    title="javascript: protocol in URL",
                    file=display_path,
                    line=line_num,
                    description=(
                        "javascript: protocol URLs execute JavaScript when clicked. "
                        "If the URL is from user input, this is an XSS vector."
                    ),
                    remediation=(
                        "Validate URLs start with https:// or /:\n"
                        "  const safeUrl = url.startsWith('https://') || url.startsWith('/') ? url : '#';"
                    ),
                    cwe="CWE-79",
                ))

            if DOCUMENT_WRITE.search(line):
                findings.append(Finding(
                    category=FindingCategory.xss,
                    severity=Severity.high,
                    title="document.write() usage",
                    file=display_path,
                    line=line_num,
                    description=(
                        "document.write() injects raw HTML into the page. "
                        "This is a legacy API that bypasses all XSS protections."
                    ),
                    remediation="Remove document.write(). Use React components or textContent.",
                    cwe="CWE-79",
                ))

            if UNSAFE_TEMPLATE_HTML.search(line):
                findings.append(Finding(
                    category=FindingCategory.xss,
                    severity=Severity.high,
                    title="Template literal with interpolation in HTML context",
                    file=display_path,
                    line=line_num,
                    description=(
                        "Template literal with variable interpolation in innerHTML "
                        "or __html context bypasses React XSS protections."
                    ),
                    remediation=(
                        "Sanitize interpolated values:\n"
                        "  import DOMPurify from 'dompurify';\n"
                        "  const safe = DOMPurify.sanitize(userInput);"
                    ),
                    cwe="CWE-79",
                ))

    return findings
