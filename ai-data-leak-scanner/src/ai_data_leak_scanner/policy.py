"""DLP policy generator.

Generates AI-specific data loss prevention policy recommendations based on scan findings.
Categories:
1. AI Tool Usage Policy
2. Data Classification
3. Technical Controls
4. Monitoring
5. Training
"""

from .models import Finding, FindingCategory, RiskLevel, AIIntegration, PolicyRecommendation


def _generate_ai_usage_policy(
    findings: list[Finding],
    ai_integrations: list[AIIntegration],
) -> list[PolicyRecommendation]:
    """Generate AI tool usage policy recommendations."""
    recommendations: list[PolicyRecommendation] = []

    unprotected = [i for i in ai_integrations if not i.is_protected]
    providers = list(set(i.provider for i in ai_integrations))

    if unprotected:
        recommendations.append(
            PolicyRecommendation(
                category="ai_tool_usage",
                priority="critical",
                recommendation=(
                    f"Establish an AI tool usage policy covering {len(providers)} detected "
                    f"AI provider(s): {', '.join(providers)}. "
                    f"{len(unprotected)} of {len(ai_integrations)} integrations lack data protection."
                ),
                implementation_steps=[
                    "Define which AI tools are approved for organizational use",
                    "Establish data classification levels for AI tool input (public, internal, confidential, restricted)",
                    "Require approval for any new AI API integration",
                    "Create a pre-submission checklist for data going to AI APIs",
                    "Implement automated scanning of AI API calls for PII before submission",
                ],
            )
        )

    if ai_integrations:
        recommendations.append(
            PolicyRecommendation(
                category="ai_tool_usage",
                priority="high",
                recommendation=(
                    "Implement an AI API gateway or proxy to centralize AI tool access and enforce policies."
                ),
                implementation_steps=[
                    "Deploy an AI API proxy that intercepts all outbound AI API calls",
                    "Configure the proxy to scan request payloads for PII patterns",
                    "Block or redact requests containing sensitive data categories",
                    "Log all AI API usage for audit purposes",
                    "Set up alerts for policy violations",
                ],
            )
        )

    return recommendations


def _generate_data_classification(
    findings: list[Finding],
) -> list[PolicyRecommendation]:
    """Generate data classification policy recommendations."""
    recommendations: list[PolicyRecommendation] = []

    pii_types = set()
    for f in findings:
        pii_types.update(f.data_types_at_risk)

    if pii_types:
        recommendations.append(
            PolicyRecommendation(
                category="data_classification",
                priority="high",
                recommendation=(
                    f"Classify the following detected data types and restrict their use with AI tools: "
                    f"{', '.join(sorted(pii_types))}."
                ),
                implementation_steps=[
                    "Create a data classification schema (public, internal, confidential, restricted)",
                    f"Classify detected PII types: {', '.join(sorted(pii_types))}",
                    "Label data stores and API endpoints with classification levels",
                    "Define which classification levels are prohibited from AI tool usage",
                    "Document exceptions and approval workflows for restricted data",
                ],
            )
        )

    critical_findings = [f for f in findings if f.risk_level == RiskLevel.critical]
    if critical_findings:
        recommendations.append(
            PolicyRecommendation(
                category="data_classification",
                priority="critical",
                recommendation=(
                    f"Address {len(critical_findings)} critical data exposure findings immediately. "
                    "These represent the highest risk of data leakage through AI tools."
                ),
                implementation_steps=[
                    "Triage all critical findings within 24 hours",
                    "Remove or redact hardcoded sensitive data from source code",
                    "Rotate any exposed credentials or API keys",
                    "Implement code review gates that block commits with PII patterns",
                ],
            )
        )

    return recommendations


def _generate_technical_controls(
    findings: list[Finding],
    ai_integrations: list[AIIntegration],
) -> list[PolicyRecommendation]:
    """Generate technical control recommendations."""
    recommendations: list[PolicyRecommendation] = []

    # Input sanitization
    pii_findings = [f for f in findings if f.category == FindingCategory.pii_exposure]
    ai_flow_findings = [f for f in findings if f.category == FindingCategory.ai_api_data_flow]

    if ai_flow_findings:
        recommendations.append(
            PolicyRecommendation(
                category="technical_controls",
                priority="critical",
                recommendation=(
                    "Implement input sanitization for all AI API calls. "
                    f"{len(ai_flow_findings)} unprotected data flows detected."
                ),
                implementation_steps=[
                    "Create a PII detection and redaction library for AI API inputs",
                    "Add pre-processing middleware that sanitizes data before AI API calls",
                    "Implement allow-lists for fields that can be sent to AI APIs",
                    "Add output filtering on AI API responses to catch reflected PII",
                    "Create unit tests for PII redaction covering all detected PII types",
                ],
            )
        )

    # API key management
    secret_findings = [f for f in findings if f.category == FindingCategory.secret_in_ai_context]
    if secret_findings:
        recommendations.append(
            PolicyRecommendation(
                category="technical_controls",
                priority="critical",
                recommendation=(
                    f"Fix {len(secret_findings)} hardcoded AI API keys. "
                    "Move all API keys to a secrets manager."
                ),
                implementation_steps=[
                    "Rotate all detected hardcoded API keys immediately",
                    "Move API keys to environment variables or a secrets manager (e.g., AWS Secrets Manager, Vault)",
                    "Add pre-commit hooks to prevent API key commits",
                    "Configure AI SDK clients to read keys from environment only",
                ],
            )
        )

    # Schema exposure
    schema_findings = [f for f in findings if f.category == FindingCategory.schema_exposure]
    if schema_findings:
        recommendations.append(
            PolicyRecommendation(
                category="technical_controls",
                priority="high",
                recommendation=(
                    "Protect database schema definitions from AI tool exposure. "
                    f"{len(schema_findings)} schemas with PII columns detected."
                ),
                implementation_steps=[
                    "Add schema files to AI tool exclusion lists (e.g., .aiignore, .cursorignore)",
                    "Implement column-level encryption for PII fields in the database",
                    "Use database views that exclude PII columns for non-privileged access",
                    "Add data masking for development and staging environments",
                ],
            )
        )

    return recommendations


def _generate_monitoring(
    findings: list[Finding],
    ai_integrations: list[AIIntegration],
) -> list[PolicyRecommendation]:
    """Generate monitoring policy recommendations."""
    recommendations: list[PolicyRecommendation] = []

    if ai_integrations:
        recommendations.append(
            PolicyRecommendation(
                category="monitoring",
                priority="high",
                recommendation=(
                    "Implement comprehensive monitoring for AI API usage and data flows."
                ),
                implementation_steps=[
                    "Log all AI API requests with metadata (user, timestamp, data types, but NOT full prompts)",
                    "Set up DLP alerts for AI API calls containing PII patterns",
                    "Create dashboards showing AI API usage volume and data categories",
                    "Implement anomaly detection for unusual AI API usage patterns",
                    "Set up weekly reports on AI data flow compliance",
                ],
            )
        )

    logging_findings = [f for f in findings if f.category == FindingCategory.logging_leak]
    if logging_findings:
        recommendations.append(
            PolicyRecommendation(
                category="monitoring",
                priority="high",
                recommendation=(
                    f"Fix {len(logging_findings)} logging statements that may leak sensitive data. "
                    "Implement structured logging with PII redaction."
                ),
                implementation_steps=[
                    "Audit all logging statements for PII exposure",
                    "Implement a structured logging framework with automatic PII redaction",
                    "Add log scrubbing for any PII patterns that reach log storage",
                    "Ensure AI API prompt/response logging redacts all PII",
                    "Set up alerts for PII patterns detected in log streams",
                ],
            )
        )

    return recommendations


def _generate_training(
    findings: list[Finding],
    ai_integrations: list[AIIntegration],
) -> list[PolicyRecommendation]:
    """Generate training policy recommendations."""
    recommendations: list[PolicyRecommendation] = []

    if findings or ai_integrations:
        recommendations.append(
            PolicyRecommendation(
                category="training",
                priority="high",
                recommendation=(
                    "Implement mandatory AI data safety training for all employees who interact with AI tools."
                ),
                implementation_steps=[
                    "Create training module: 'What NOT to paste into AI tools' (real incident examples)",
                    "Create training module: 'Identifying PII and sensitive data'",
                    "Create training module: 'Safe AI tool usage for developers'",
                    "Require training completion before granting AI tool access",
                    "Conduct quarterly refresher training with updated examples",
                    "Run simulated AI data leak exercises to test awareness",
                ],
            )
        )

    return recommendations


def generate_policy(
    findings: list[Finding],
    ai_integrations: list[AIIntegration],
) -> list[PolicyRecommendation]:
    """Generate AI-specific DLP policy recommendations based on scan findings.

    Args:
        findings: List of all findings from scanners.
        ai_integrations: List of detected AI integrations.

    Returns:
        List of PolicyRecommendation objects.
    """
    recommendations: list[PolicyRecommendation] = []

    recommendations.extend(_generate_ai_usage_policy(findings, ai_integrations))
    recommendations.extend(_generate_data_classification(findings))
    recommendations.extend(_generate_technical_controls(findings, ai_integrations))
    recommendations.extend(_generate_monitoring(findings, ai_integrations))
    recommendations.extend(_generate_training(findings, ai_integrations))

    return recommendations
