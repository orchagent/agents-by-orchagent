"""
Checks #14-15: Secure API Defaults, Security Observability.

#14 Secure defaults in APIs (idempotency keys, pagination limits, strict CORS)
#15 Observability for security (alerts on auth failures, spikes, weird access paths)
"""

import re

from ..models import Finding, CheckStatus


# --- Category 14: Secure API Defaults ---

# CORS wildcard
_CORS_WILDCARD_PATTERNS = [
    (re.compile(r"""allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]"""),
     "CORS allows all origins (wildcard *)", "high"),
    (re.compile(r"""Access-Control-Allow-Origin['":\s]+\*"""),
     "CORS header set to wildcard *", "high"),
    (re.compile(r"""cors\s*\(\s*\{?\s*origin\s*:\s*(?:true|['"]\*['"])""", re.IGNORECASE),
     "CORS middleware allows all origins", "high"),
]

# Pagination patterns (positive signal)
_PAGINATION_RE = re.compile(
    r"\b(?:paginate|pagination|limit|offset|cursor|page_size|per_page|"
    r"skip|take|pageSize|perPage)\b",
    re.IGNORECASE,
)

# Security headers middleware (positive signal)
_SECURITY_HEADERS_RE = re.compile(
    r"\b(?:helmet|secure-headers|SecureHeaders|SecurityMiddleware|"
    r"X-Content-Type-Options|X-Frame-Options|X-XSS-Protection|"
    r"Content-Security-Policy)\b",
    re.IGNORECASE,
)

# Idempotency patterns (positive signal)
_IDEMPOTENCY_RE = re.compile(
    r"\b(?:idempotency[_\-]?key|Idempotency-Key|idempotent)\b",
    re.IGNORECASE,
)


# --- Category 15: Security Observability ---

# Auth failure monitoring (positive signal)
_AUTH_MONITORING_RE = re.compile(
    r"\b(?:failed[_\s]?login|auth[_\s]?fail|login[_\s]?attempt|"
    r"unauthorized[_\s]?access|brute[_\s]?force|account[_\s]?lockout|"
    r"suspicious[_\s]?activity)\b",
    re.IGNORECASE,
)

# Monitoring/alerting tools (positive signal)
_MONITORING_RE = re.compile(
    r"\b(?:sentry|datadog|newrelic|prometheus|grafana|"
    r"cloudwatch|stackdriver|honeycomb|"
    r"pagerduty|opsgenie|alertmanager)\b",
    re.IGNORECASE,
)

# Health check endpoint (positive signal)
_HEALTH_CHECK_RE = re.compile(
    r"""['"]/health['"]\s*[,)]|['"]/healthz['"]\s*[,)]|['"]/readyz['"]\s*[,)]""",
)


def run_checks(files: list[dict], project_type: str = "unknown") -> list[Finding]:
    """Run API defaults and security observability checks."""
    findings = []
    source_files = [f for f in files if f["extension"] in (".py", ".js", ".ts") and not f["is_test"]]
    config_files = [f for f in files if f["extension"] in (".json", ".yaml", ".yml", ".toml")]

    has_pagination = False
    has_security_headers = False
    has_idempotency = False
    has_auth_monitoring = False
    has_monitoring_tool = False
    has_health_check = False
    has_api_routes = False

    for f in source_files + config_files:
        content = f["content"]

        if _PAGINATION_RE.search(content):
            has_pagination = True
        if _SECURITY_HEADERS_RE.search(content):
            has_security_headers = True
        if _IDEMPOTENCY_RE.search(content):
            has_idempotency = True
        if _AUTH_MONITORING_RE.search(content):
            has_auth_monitoring = True
        if _MONITORING_RE.search(content):
            has_monitoring_tool = True
        if _HEALTH_CHECK_RE.search(content):
            has_health_check = True

    for f in source_files:
        content = f["content"]
        lines = content.split("\n")

        if re.search(r"@(?:app|router)\.|\.listen\(|createServer", content):
            has_api_routes = True

        for i, line in enumerate(lines, 1):
            # CORS wildcard
            for pattern, desc, severity in _CORS_WILDCARD_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        category="api_defaults",
                        category_id=14,
                        check="cors_wildcard",
                        status=CheckStatus.FAIL,
                        severity=severity,
                        message=desc,
                        file=f["relative_path"],
                        line=i,
                        snippet=line.strip()[:120],
                        fix="Restrict CORS to specific trusted origins instead of '*'",
                    ))

    if not has_api_routes:
        return findings

    # Summary findings for missing API defaults

    if not has_pagination:
        findings.append(Finding(
            category="api_defaults",
            category_id=14,
            check="no_pagination",
            status=CheckStatus.WARN,
            severity="medium",
            message="No pagination pattern detected — list endpoints may return unbounded results",
            fix="Add pagination (limit/offset or cursor-based) to all list endpoints",
        ))

    if not has_security_headers:
        findings.append(Finding(
            category="api_defaults",
            category_id=14,
            check="no_security_headers",
            status=CheckStatus.WARN,
            severity="medium",
            message="No security headers middleware detected (helmet, SecureHeaders, etc.)",
            fix="Add security headers: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy",
        ))

    # Observability findings

    if not has_monitoring_tool:
        findings.append(Finding(
            category="observability",
            category_id=15,
            check="no_monitoring",
            status=CheckStatus.WARN,
            severity="medium",
            message="No monitoring/alerting tool detected (Sentry, Datadog, Prometheus, etc.)",
            fix="Add error tracking (Sentry) and metrics (Prometheus/Datadog) for production visibility",
        ))

    if not has_auth_monitoring:
        findings.append(Finding(
            category="observability",
            category_id=15,
            check="no_auth_monitoring",
            status=CheckStatus.WARN,
            severity="medium",
            message="No auth failure monitoring detected — brute-force attacks may go unnoticed",
            fix="Log and alert on repeated auth failures, account lockouts, and suspicious access patterns",
        ))

    if not has_health_check:
        findings.append(Finding(
            category="observability",
            category_id=15,
            check="no_health_check",
            status=CheckStatus.WARN,
            severity="low",
            message="No health check endpoint detected (/health, /healthz)",
            fix="Add a /health endpoint for load balancer and monitoring integration",
        ))

    return findings
