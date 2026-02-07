"""Configuration security scanner for Next.js projects.

Detects:
- next.config.js with dangerous settings
- Missing security headers (CSP, X-Frame-Options, etc.)
- poweredByHeader not disabled
- Misconfigured images.domains (too permissive)
- Missing reactStrictMode
"""

import re
from pathlib import Path

from ..models import Finding, FindingCategory, Severity
from .common import read_file_lines


# Security headers that should be set
REQUIRED_SECURITY_HEADERS = [
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "X-Frame-Options"),
    ("X-Content-Type-Options", "X-Content-Type-Options"),
    ("Referrer-Policy", "Referrer-Policy"),
    ("Permissions-Policy", "Permissions-Policy"),
]

# Dangerous rewrite/redirect patterns
INTERNAL_PROXY_PATTERN = re.compile(
    r"""(?:destination|url)\s*:\s*['"`](?:http://localhost|http://127\.0\.0\.1|http://internal)""",
    re.IGNORECASE,
)

# Wildcard image domain
WILDCARD_IMAGE_DOMAIN = re.compile(
    r"""(?:domains|remotePatterns)\s*:\s*\[\s*['"`]\*""",
    re.IGNORECASE,
)

# Overly permissive remote pattern
PERMISSIVE_REMOTE_PATTERN = re.compile(
    r"""hostname\s*:\s*['"`]\*\*?['"`]""",
)


def scan_config_patterns(
    project_path: str | Path,
    base_path: str | Path | None = None,
) -> list[Finding]:
    """Scan Next.js configuration for security issues."""
    project_path = Path(project_path)
    base_path = Path(base_path) if base_path else project_path
    findings: list[Finding] = []

    # Find next.config file
    config_path = None
    for config_name in ("next.config.js", "next.config.ts", "next.config.mjs"):
        candidate = project_path / config_name
        if candidate.exists():
            config_path = candidate
            break

    if config_path is None:
        return findings

    lines = read_file_lines(config_path)
    if not lines:
        return findings

    content = "\n".join(line for _, line in lines)

    try:
        display_path = str(config_path.relative_to(base_path))
    except ValueError:
        display_path = str(config_path)

    # 1. reactStrictMode
    if "reactStrictMode" not in content:
        findings.append(Finding(
            category=FindingCategory.config,
            severity=Severity.low,
            title="reactStrictMode not enabled",
            file=display_path,
            description=(
                "reactStrictMode is not enabled in next.config. "
                "Strict mode helps identify unsafe lifecycles and potential issues."
            ),
            remediation="Add reactStrictMode: true to next.config.js.",
        ))
    elif re.search(r'reactStrictMode\s*:\s*false', content):
        findings.append(Finding(
            category=FindingCategory.config,
            severity=Severity.low,
            title="reactStrictMode explicitly disabled",
            file=display_path,
            description="reactStrictMode is explicitly set to false.",
            remediation="Set reactStrictMode: true in next.config.js.",
        ))

    # 2. poweredByHeader
    if "poweredByHeader" not in content:
        findings.append(Finding(
            category=FindingCategory.config,
            severity=Severity.low,
            title="X-Powered-By header not disabled",
            file=display_path,
            description=(
                "Next.js sends X-Powered-By by default, revealing the tech stack. "
                "This helps attackers target framework-specific vulnerabilities."
            ),
            remediation="Add poweredByHeader: false to next.config.js.",
        ))
    elif re.search(r'poweredByHeader\s*:\s*true', content):
        findings.append(Finding(
            category=FindingCategory.config,
            severity=Severity.low,
            title="X-Powered-By header explicitly enabled",
            file=display_path,
            description="poweredByHeader is set to true, exposing the tech stack.",
            remediation="Set poweredByHeader: false in next.config.js.",
        ))

    # 3. Security headers
    has_headers_config = bool(re.search(r'async\s+headers\s*\(\s*\)', content))
    if not has_headers_config:
        findings.append(Finding(
            category=FindingCategory.config,
            severity=Severity.medium,
            title="No security headers configured",
            file=display_path,
            description=(
                "No custom headers in next.config.js. Security headers like CSP, "
                "X-Frame-Options, X-Content-Type-Options should be set."
            ),
            remediation=(
                "Add headers() to next.config.js:\n"
                "  async headers() {\n"
                "    return [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }];\n"
                "  }"
            ),
            cwe="CWE-693",
        ))
    else:
        for header_name, display_name in REQUIRED_SECURITY_HEADERS:
            if header_name not in content:
                sev = Severity.medium if header_name == "Content-Security-Policy" else Severity.low
                findings.append(Finding(
                    category=FindingCategory.config,
                    severity=sev,
                    title=f"Missing {display_name} header",
                    file=display_path,
                    description=f"{display_name} header is not configured in next.config.js headers().",
                    remediation=f"Add {header_name} to your headers() configuration.",
                    cwe="CWE-693",
                ))

    # 4. Internal proxy rewrites
    for line_num, line in lines:
        if INTERNAL_PROXY_PATTERN.search(line):
            findings.append(Finding(
                category=FindingCategory.config,
                severity=Severity.high,
                title="Rewrite/redirect exposing internal service",
                file=display_path,
                line=line_num,
                description=(
                    "A rewrite/redirect proxies to an internal service (localhost/internal). "
                    "This can expose internal APIs to the public internet."
                ),
                remediation=(
                    "Remove or restrict the rewrite. If needed, add authentication "
                    "and use a dedicated API route."
                ),
                cwe="CWE-441",
            ))

    # 5. Overly permissive image domains
    for line_num, line in lines:
        if WILDCARD_IMAGE_DOMAIN.search(line) or PERMISSIVE_REMOTE_PATTERN.search(line):
            findings.append(Finding(
                category=FindingCategory.config,
                severity=Severity.medium,
                title="Overly permissive image domains",
                file=display_path,
                line=line_num,
                description=(
                    "Image domains uses wildcards, allowing images from any domain. "
                    "This can be exploited for SSRF via Next.js image optimization."
                ),
                remediation=(
                    "Restrict to specific trusted domains:\n"
                    "  images: { domains: ['cdn.yourdomain.com', 'images.unsplash.com'] }"
                ),
                cwe="CWE-918",
            ))

    return findings
