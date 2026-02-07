"""AI API integration scanner.

Detects AI API usage and analyzes data flow into AI calls:
- OpenAI API calls (chat.completions.create, etc.)
- Anthropic API calls (messages.create, etc.)
- Google AI calls (genai, palm, vertex)
- LangChain/LlamaIndex usage
- Checks for data protection (sanitization, filtering, redaction)
"""

import re
from pathlib import Path
from typing import NamedTuple

from ..models import Finding, FindingCategory, RiskLevel, AIIntegration
from .common import walk_source_files, read_file_lines, get_display_path, SOURCE_EXTENSIONS


class AIProviderPattern(NamedTuple):
    """Pattern for detecting an AI provider API call."""

    provider: str
    api_call_type: str
    regex: re.Pattern


# AI API call patterns
AI_CALL_PATTERNS: list[AIProviderPattern] = [
    # OpenAI
    AIProviderPattern(
        provider="openai",
        api_call_type="chat.completions.create",
        regex=re.compile(
            r'(?:openai|client)\.chat\.completions\.create\s*\(',
            re.IGNORECASE,
        ),
    ),
    AIProviderPattern(
        provider="openai",
        api_call_type="completions.create",
        regex=re.compile(
            r'(?:openai|client)\.completions\.create\s*\(',
            re.IGNORECASE,
        ),
    ),
    AIProviderPattern(
        provider="openai",
        api_call_type="embeddings.create",
        regex=re.compile(
            r'(?:openai|client)\.embeddings\.create\s*\(',
            re.IGNORECASE,
        ),
    ),
    AIProviderPattern(
        provider="openai",
        api_call_type="ChatCompletion",
        regex=re.compile(
            r'openai\.ChatCompletion\.create\s*\(',
        ),
    ),
    # Anthropic
    AIProviderPattern(
        provider="anthropic",
        api_call_type="messages.create",
        regex=re.compile(
            r'(?:anthropic|client)\.messages\.create\s*\(',
            re.IGNORECASE,
        ),
    ),
    AIProviderPattern(
        provider="anthropic",
        api_call_type="completions.create",
        regex=re.compile(
            r'(?:anthropic|client)\.completions\.create\s*\(',
            re.IGNORECASE,
        ),
    ),
    # Google AI
    AIProviderPattern(
        provider="google",
        api_call_type="generate_content",
        regex=re.compile(
            r'(?:model|genai|generative_model)\.generate_content\s*\(',
            re.IGNORECASE,
        ),
    ),
    AIProviderPattern(
        provider="google",
        api_call_type="palm.generate_text",
        regex=re.compile(
            r'palm\.generate_text\s*\(',
            re.IGNORECASE,
        ),
    ),
    AIProviderPattern(
        provider="google",
        api_call_type="vertex_ai.predict",
        regex=re.compile(
            r'(?:endpoint|model)\.predict\s*\(',
            re.IGNORECASE,
        ),
    ),
    # LangChain
    AIProviderPattern(
        provider="langchain",
        api_call_type="llm.invoke",
        regex=re.compile(
            r'(?:llm|chain|model)\.(?:invoke|run|predict|call)\s*\(',
            re.IGNORECASE,
        ),
    ),
    AIProviderPattern(
        provider="langchain",
        api_call_type="ChatOpenAI",
        regex=re.compile(
            r'ChatOpenAI\s*\(',
        ),
    ),
    AIProviderPattern(
        provider="langchain",
        api_call_type="ChatAnthropic",
        regex=re.compile(
            r'ChatAnthropic\s*\(',
        ),
    ),
    # LlamaIndex
    AIProviderPattern(
        provider="llamaindex",
        api_call_type="query_engine.query",
        regex=re.compile(
            r'query_engine\.query\s*\(',
            re.IGNORECASE,
        ),
    ),
    AIProviderPattern(
        provider="llamaindex",
        api_call_type="index.as_query_engine",
        regex=re.compile(
            r'\.as_query_engine\s*\(',
            re.IGNORECASE,
        ),
    ),
]

# Patterns that indicate data flowing into AI calls
DATA_FLOW_PATTERNS = [
    (re.compile(r'(?:user_input|user_message|user_query|user_prompt|user_text)', re.IGNORECASE), "user_input"),
    (re.compile(r'(?:request\.body|request\.json|req\.body|request\.data)', re.IGNORECASE), "request_body"),
    (re.compile(r'(?:db_result|query_result|rows|records|cursor|fetchall|fetchone)', re.IGNORECASE), "db_records"),
    (re.compile(r'(?:\.query\(|\.execute\(|\.find\(|\.select\(|\.fetchall)', re.IGNORECASE), "db_query"),
    (re.compile(r'(?:email|phone|ssn|address|first_name|last_name|patient)', re.IGNORECASE), "pii_fields"),
    (re.compile(r'(?:document|file_content|file_data|read\(\)|readlines)', re.IGNORECASE), "file_contents"),
    (re.compile(r'f["\x27].*\{.*\}', re.IGNORECASE), "interpolated_data"),
    (re.compile(r'\.format\(', re.IGNORECASE), "formatted_string"),
]

# Patterns indicating data protection
PROTECTION_PATTERNS = [
    re.compile(r'(?:sanitize|redact|mask|filter|scrub|clean|anonymize|pseudonymize)', re.IGNORECASE),
    re.compile(r'(?:strip_pii|remove_pii|hide_pii|pii_filter)', re.IGNORECASE),
    re.compile(r'(?:DLP|data_loss_prevention|content_filter)', re.IGNORECASE),
    re.compile(r'(?:validate_input|input_validation|check_input)', re.IGNORECASE),
]

# Import patterns that confirm AI SDK usage
AI_IMPORT_PATTERNS = [
    re.compile(r'(?:import|from)\s+openai', re.IGNORECASE),
    re.compile(r'(?:import|from)\s+anthropic', re.IGNORECASE),
    re.compile(r'(?:import|from)\s+google\.generativeai', re.IGNORECASE),
    re.compile(r'(?:import|from)\s+langchain', re.IGNORECASE),
    re.compile(r'(?:import|from)\s+llama_index', re.IGNORECASE),
    re.compile(r'require\s*\(\s*["\x27]openai["\x27]\s*\)', re.IGNORECASE),
    re.compile(r'require\s*\(\s*["\x27]@anthropic', re.IGNORECASE),
    re.compile(r'from\s+["\x27]openai["\x27]', re.IGNORECASE),
    re.compile(r'from\s+["\x27]@anthropic', re.IGNORECASE),
]


def _has_ai_imports(content: str) -> bool:
    """Check if file content contains AI SDK imports."""
    return any(p.search(content) for p in AI_IMPORT_PATTERNS)


def _detect_data_flows(context_lines: list[str]) -> list[str]:
    """Detect what data flows into the AI API call from surrounding context."""
    flows: list[str] = []
    context = "\n".join(context_lines)
    for pattern, flow_name in DATA_FLOW_PATTERNS:
        if pattern.search(context):
            flows.append(flow_name)
    return list(set(flows))


def _has_protection(context_lines: list[str]) -> bool:
    """Check if any data protection patterns are present near the AI call."""
    context = "\n".join(context_lines)
    return any(p.search(context) for p in PROTECTION_PATTERNS)


def _get_issues(
    data_flows: list[str],
    is_protected: bool,
    has_hardcoded_key: bool,
) -> list[str]:
    """Generate list of issues for an AI integration."""
    issues: list[str] = []

    if "user_input" in data_flows and not is_protected:
        issues.append("User input passed directly to AI API without sanitization")
    if "db_records" in data_flows or "db_query" in data_flows:
        issues.append("Database query results passed into AI prompt - may contain PII")
    if "pii_fields" in data_flows:
        issues.append("PII fields (email, phone, SSN, etc.) included in AI context")
    if "request_body" in data_flows and not is_protected:
        issues.append("Raw request body passed to AI API without filtering")
    if "file_contents" in data_flows and not is_protected:
        issues.append("File contents passed to AI API without content scanning")
    if not is_protected and data_flows:
        issues.append("No output filtering or redaction detected on AI responses")
    if has_hardcoded_key:
        issues.append("AI API key appears to be hardcoded (not using environment variable)")

    return issues


def _check_hardcoded_key(context_lines: list[str]) -> bool:
    """Check if API key appears hardcoded in context."""
    hardcoded_key_pattern = re.compile(
        r'(?:api_key|apikey|api_secret)\s*[:=]\s*["\x27](?:sk-|key-|pk-)[\w-]+["\x27]',
        re.IGNORECASE,
    )
    context = "\n".join(context_lines)
    return bool(hardcoded_key_pattern.search(context))


def _scan_file_for_ai(
    file_path: Path,
    base_path: Path,
) -> tuple[list[Finding], list[AIIntegration]]:
    """Scan a single file for AI API integrations."""
    findings: list[Finding] = []
    integrations: list[AIIntegration] = []

    display_path = get_display_path(file_path, base_path)
    lines = read_file_lines(file_path)

    if not lines:
        return findings, integrations

    # Read full content to check for AI imports
    full_content = "\n".join(line for _, line in lines)
    if not _has_ai_imports(full_content):
        return findings, integrations

    all_lines = [line for _, line in lines]

    for line_num, line_content in lines:
        for ai_pattern in AI_CALL_PATTERNS:
            if ai_pattern.regex.search(line_content):
                # Get surrounding context (20 lines before and after)
                start_idx = max(0, line_num - 21)
                end_idx = min(len(all_lines), line_num + 20)
                context = all_lines[start_idx:end_idx]

                data_flows = _detect_data_flows(context)
                is_protected = _has_protection(context)
                has_hardcoded_key = _check_hardcoded_key(context)
                issues = _get_issues(data_flows, is_protected, has_hardcoded_key)

                integration = AIIntegration(
                    file=display_path,
                    line=line_num,
                    provider=ai_pattern.provider,
                    api_call_type=ai_pattern.api_call_type,
                    data_flows_in=data_flows,
                    is_protected=is_protected,
                    issues=issues,
                )
                integrations.append(integration)

                # Create findings for unprotected integrations with issues
                if issues:
                    risk = RiskLevel.high
                    if "PII fields" in " ".join(issues) or "Database query" in " ".join(issues):
                        risk = RiskLevel.critical

                    data_types = []
                    if "pii_fields" in data_flows:
                        data_types.extend(["email", "phone", "ssn", "person_name"])
                    if "db_records" in data_flows or "db_query" in data_flows:
                        data_types.append("database_records")
                    if "user_input" in data_flows:
                        data_types.append("user_input")

                    findings.append(
                        Finding(
                            category=FindingCategory.ai_api_data_flow,
                            risk_level=risk,
                            title=f"Unprotected {ai_pattern.provider} API call ({ai_pattern.api_call_type})",
                            file=display_path,
                            line=line_num,
                            description=(
                                f"{ai_pattern.provider.title()} API call at line {line_num} "
                                f"with data flowing in: {', '.join(data_flows)}. "
                                f"Issues: {'; '.join(issues)}"
                            ),
                            data_types_at_risk=data_types,
                            remediation=(
                                "Add input sanitization before sending data to AI APIs. "
                                "Implement PII redaction, use allow-lists for data fields, "
                                "and add output filtering on AI responses."
                            ),
                        )
                    )

                    if has_hardcoded_key:
                        findings.append(
                            Finding(
                                category=FindingCategory.secret_in_ai_context,
                                risk_level=RiskLevel.critical,
                                title=f"Hardcoded {ai_pattern.provider} API key",
                                file=display_path,
                                line=line_num,
                                description=(
                                    f"AI API key for {ai_pattern.provider} appears to be "
                                    f"hardcoded near line {line_num}."
                                ),
                                data_types_at_risk=["api_key"],
                                remediation=(
                                    "Move API keys to environment variables. "
                                    "Never commit API keys to source code."
                                ),
                            )
                        )

    return findings, integrations


def scan_ai_integrations(
    repo_path: str | Path,
    exclude_dirs: set[str] | None = None,
) -> tuple[list[Finding], list[AIIntegration]]:
    """Scan a repository for AI API integrations and data flow issues.

    Args:
        repo_path: Path to the repository root.
        exclude_dirs: Additional directory names to skip.

    Returns:
        Tuple of (findings, ai_integrations).
    """
    base = Path(repo_path)
    all_findings: list[Finding] = []
    all_integrations: list[AIIntegration] = []

    for file_path in walk_source_files(base, extensions=SOURCE_EXTENSIONS, exclude_dirs=exclude_dirs):
        findings, integrations = _scan_file_for_ai(file_path, base)
        all_findings.extend(findings)
        all_integrations.extend(integrations)

    return all_findings, all_integrations
