"""Generate actionable recommendations from security findings."""

from .models import FindingsCollection


def _count_by_type(findings: FindingsCollection) -> dict[str, int]:
    """Count findings by type for recommendation generation."""
    counts: dict[str, int] = {}

    # Count secret types
    for secret in findings.secrets:
        key = f"secret:{secret.type}"
        counts[key] = counts.get(key, 0) + 1

    # Count dependency vulnerabilities
    for dep in findings.dependencies:
        key = f"dependency:{dep.severity}"
        counts[key] = counts.get(key, 0) + 1

    # Count pattern categories
    for pattern in findings.frontend_security:
        key = f"frontend:{pattern.pattern}"
        counts[key] = counts.get(key, 0) + 1

    for pattern in findings.api_security:
        key = f"api:{pattern.pattern}"
        counts[key] = counts.get(key, 0) + 1

    for pattern in findings.logging:
        key = f"logging:{pattern.pattern}"
        counts[key] = counts.get(key, 0) + 1

    return counts


def _get_priority_score(finding_type: str, count: int) -> int:
    """Calculate priority score for a finding type.

    Higher scores = higher priority for recommendations.
    """
    # Base priority by category and severity — uses pattern machine names
    priority_map = {
        # Secrets are always highest priority - no count multiplier
        "secret:": 10000,
        # Critical/high dependencies
        "dependency:critical": 900,
        "dependency:high": 800,
        "dependency:medium": 400,
        "dependency:low": 100,
        # Frontend security (auth/payment bypasses are critical)
        "frontend:localstorage_auth_token": 850,
        "frontend:localstorage_premium_flag": 850,
        "frontend:client_side_premium_check": 850,
        "frontend:client_side_admin_check": 850,
        "frontend:supabase_client_in_component": 700,
        "frontend:firebase_admin_in_frontend": 900,
        "frontend:client_side_price_calculation": 500,
        "frontend:stripe_amount_in_frontend": 700,
        # API security
        "api:fastapi_missing_auth": 750,
        "api:express_missing_auth": 750,
        "api:missing_rate_limiter": 600,
        # Logging issues
        "logging:console_log_password": 650,
        "logging:console_log_secret": 650,
        "logging:console_log_private_key": 700,
        "logging:python_log_password": 650,
        "logging:python_log_secret": 650,
        "logging:stack_trace_in_response": 650,
        "logging:stack_trace_property_access": 650,
        "logging:raw_error_in_response": 550,
        "logging:error_spread_in_response": 550,
        "logging:fastapi_exception_detail": 550,
        "logging:traceback_in_response": 650,
        "logging:print_sensitive_data": 600,
    }

    base_score = 0
    for key, score in priority_map.items():
        if finding_type.startswith(key):
            base_score = score
            break

    # Secrets don't multiply by count - each exposed secret is equally critical
    if finding_type.startswith("secret:"):
        return base_score

    # Multiply by count for other findings (more occurrences = higher priority)
    return base_score * min(count, 5)  # Cap at 5x to prevent one category dominating


def _generate_secret_recommendation(secret_type: str, count: int) -> str:
    """Generate recommendation for exposed secrets."""
    type_names = {
        "aws_access_key": "AWS access key",
        "aws_secret_key": "AWS secret key",
        "stripe_key": "Stripe API key",
        "github_token": "GitHub token",
        "openai_api_key": "OpenAI API key",
        "anthropic_api_key": "Anthropic API key",
        "slack_token": "Slack token",
        "database_url": "database connection string",
        "jwt_secret": "JWT secret",
        "private_key": "private key",
        "generic_api_key": "API key",
        "generic_secret": "secret",
    }

    name = type_names.get(secret_type, secret_type.replace("_", " "))

    if count == 1:
        return f"Rotate the exposed {name} immediately and move it to environment variables"
    return f"Rotate {count} exposed {name}s immediately and move them to environment variables"


def _generate_dependency_recommendation(severity: str, count: int) -> str:
    """Generate recommendation for vulnerable dependencies."""
    if count == 1:
        return f"Update 1 package with {severity}-severity vulnerability to a patched version"
    return f"Update {count} packages with {severity}-severity vulnerabilities to patched versions"


def _generate_pattern_recommendation(pattern: str, count: int) -> str:
    """Generate recommendation for pattern findings."""
    recommendations = {
        # Frontend patterns
        "localstorage_auth_token": "Move auth tokens from localStorage to httpOnly cookies",
        "localstorage_premium_flag": "Move premium flags from localStorage to server-side validation",
        "client_side_premium_check": "Move premium/subscription checks to server-side middleware",
        "client_side_admin_check": "Move admin/role checks to server-side middleware",
        "supabase_client_in_component": "Move Supabase queries to server-side API routes",
        "firebase_admin_in_frontend": "Move Firebase Admin SDK to server-side; use Client SDK in frontend",
        "client_side_price_calculation": "Move price calculations to server-side to prevent tampering",
        "stripe_amount_in_frontend": "Set Stripe payment amounts server-side only",
        # API patterns
        "fastapi_missing_auth": f"Add authentication middleware to {count} unprotected FastAPI route(s)",
        "express_missing_auth": f"Add authentication middleware to {count} unprotected Express route(s)",
        "missing_rate_limiter": "Add rate limiting to your API endpoints (e.g., slowapi for FastAPI)",
        # Logging patterns
        "console_log_password": f"Remove sensitive data from {count} console.log statement(s)",
        "console_log_secret": f"Remove sensitive data from {count} console.log statement(s)",
        "console_log_private_key": f"Remove private key logging from {count} statement(s)",
        "python_log_password": f"Remove sensitive data from {count} Python logging statement(s)",
        "python_log_secret": f"Remove sensitive data from {count} Python logging statement(s)",
        "stack_trace_in_response": "Remove stack traces from API responses in production",
        "stack_trace_property_access": "Remove stack traces from API responses in production",
        "raw_error_in_response": "Sanitize error messages before sending to clients",
        "error_spread_in_response": "Explicitly select safe error fields instead of spreading",
        "fastapi_exception_detail": "Use generic error messages in HTTPException; log details server-side",
        "traceback_in_response": "Never send Python tracebacks to clients",
        "print_sensitive_data": f"Remove sensitive data from {count} print statement(s)",
    }

    return recommendations.get(pattern, f"Address {count} {pattern} issue(s)")


def generate_recommendations(findings: FindingsCollection, max_recommendations: int = 3) -> list[str]:
    """Generate top actionable recommendations from findings.

    Prioritizes recommendations by severity and count, returns the most important ones.
    """
    if not any([
        findings.secrets,
        findings.dependencies,
        findings.frontend_security,
        findings.api_security,
        findings.logging,
    ]):
        return []

    # Build list of (priority_score, recommendation)
    scored_recommendations: list[tuple[int, str]] = []

    # Process secrets
    secret_counts: dict[str, int] = {}
    for secret in findings.secrets:
        secret_counts[secret.type] = secret_counts.get(secret.type, 0) + 1

    for secret_type, count in secret_counts.items():
        score = _get_priority_score(f"secret:{secret_type}", count)
        rec = _generate_secret_recommendation(secret_type, count)
        scored_recommendations.append((score, rec))

    # Process dependencies by severity
    dep_severity_counts: dict[str, int] = {}
    for dep in findings.dependencies:
        severity = dep.severity.lower()
        dep_severity_counts[severity] = dep_severity_counts.get(severity, 0) + 1

    for severity, count in dep_severity_counts.items():
        score = _get_priority_score(f"dependency:{severity}", count)
        rec = _generate_dependency_recommendation(severity, count)
        scored_recommendations.append((score, rec))

    # Process patterns — determine category from the finding list they came from
    pattern_counts: dict[str, tuple[str, int]] = {}  # pattern -> (category, count)
    for category, pattern_list in [
        ("frontend", findings.frontend_security),
        ("api", findings.api_security),
        ("logging", findings.logging),
    ]:
        for p in pattern_list:
            if p.pattern in pattern_counts:
                cat, cnt = pattern_counts[p.pattern]
                pattern_counts[p.pattern] = (cat, cnt + 1)
            else:
                pattern_counts[p.pattern] = (category, 1)

    for pattern, (category, count) in pattern_counts.items():
        score = _get_priority_score(f"{category}:{pattern}", count)
        rec = _generate_pattern_recommendation(pattern, count)
        scored_recommendations.append((score, rec))

    # Sort by score descending and return top N
    scored_recommendations.sort(key=lambda x: x[0], reverse=True)

    return [rec for _, rec in scored_recommendations[:max_recommendations]]
