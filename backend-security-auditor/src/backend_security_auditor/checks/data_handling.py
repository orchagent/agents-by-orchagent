"""
SECURITY DETECTION MODULE — This file contains regex patterns used to DETECT
data handling issues in user codebases (sensitive data logging, error exposure, PII).
These patterns are used for READ-ONLY static analysis. This code does NOT
log sensitive data or expose errors itself.

Checks #9, #10, #11, #13: File Handling, Logging, Error Handling, Data Protection.
#9  Safe file handling (size limits, type allowlist, malware scan, signed URLs)
#10 Logging & audit trails (who did what/when + tamper-resistant storage)
#11 Error handling (no stack traces to clients, consistent error contracts)
#13 Data protection (encryption at rest, field-level for PII, retention policies)
"""

import re

from ..models import Finding, CheckStatus


# --- Category 9: Safe File Handling ---

# File upload detection
_FILE_UPLOAD_RE = re.compile(
    r"\b(?:multer|upload|UploadFile|FileUpload|multipart|formidable|busboy|"
    r"request\.files|req\.file|req\.files)\b",
    re.IGNORECASE,
)

# File size limits (positive signal)
_FILE_SIZE_LIMIT_RE = re.compile(
    r"\b(?:maxFileSize|max_size|fileSize|MAX_SIZE|size_limit|limit|maxSize|"
    r"content_length|MAX_CONTENT_LENGTH)\b",
    re.IGNORECASE,
)

# File type validation (positive signal)
_FILE_TYPE_CHECK_RE = re.compile(
    r"\b(?:mimetype|content_type|content-type|file_extension|allowed_extensions|"
    r"accept|allowedTypes|fileFilter|ALLOWED_TYPES)\b",
    re.IGNORECASE,
)


# --- Category 10: Logging & Audit ---

# Sensitive data in logs — match interpolated variables, not static config-warning strings
_SENSITIVE_LOG_PATTERNS = [
    # f-string interpolation of sensitive variables: logger.info(f"...{password}...")
    (re.compile(r"""(?:console\.log|logger?\.\w+|logging\.\w+|print)\s*\(\s*f['"].*\{[^}]*(?:password|passwd|pwd|secret_key|api_key|token|credential|private_key)[^}]*\}""", re.IGNORECASE),
     "Sensitive variable interpolated in log message", "high"),
    # Direct variable logging: logger.info(password) or logger.info(secret)
    (re.compile(r"""(?:console\.log|logger?\.\w+|logging\.\w+|print)\s*\(\s*(?:password|passwd|pwd|secret_key|api_key|auth_token|private_key)\s*[,)]""", re.IGNORECASE),
     "Sensitive variable passed directly to log function", "high"),
    # Key=value logging: logger.info(f"key={api_key}")
    (re.compile(r"""(?:console\.log|logger?\.\w+|logging\.\w+|print)\s*\(.*(?:password|secret|token|api_key|credential)\s*[:=]\s*['"]?\s*\{""", re.IGNORECASE),
     "Sensitive key=value pair logged", "high"),
]

# Structured logging (positive signal)
_STRUCTURED_LOGGING_RE = re.compile(
    r"\b(?:structlog|winston|pino|bunyan|loguru|"
    r"logging\.config|logging\.handlers|"
    r"morgan|log4j|NLog|serilog)\b",
    re.IGNORECASE,
)

# Audit trail patterns (positive signal)
_AUDIT_RE = re.compile(
    r"\b(?:audit[_\-\s]?log|audit[_\-\s]?trail|AuditLog|activity[_\-\s]?log)\b",
    re.IGNORECASE,
)


# --- Category 11: Error Handling ---

# Stack traces exposed to clients
_STACK_TRACE_EXPOSURE = [
    (re.compile(r"traceback\.format_exc\s*\(\s*\).*(?:return|response|json|detail)"),
     "Python traceback exposed in response", "high"),
    (re.compile(r"(?:res\.(?:json|send)|return\s+\{)[^}]*err\.stack"),
     "Error stack trace sent to client", "high"),
    (re.compile(r"""HTTPException\s*\([^)]*detail\s*=\s*(?:str\s*\(\s*e\s*\)|traceback|f['"])"""),
     "FastAPI HTTPException with raw error details", "high"),
    (re.compile(r"""detail\s*=\s*traceback"""),
     "Traceback in HTTP error detail", "high"),
]

# Consistent error handling (positive signal)
_ERROR_HANDLER_RE = re.compile(
    r"\b(?:exception_handler|errorHandler|@app\.exception|"
    r"app\.use\(\s*(?:function)?\s*\(\s*err|"
    r"error_middleware|ErrorBoundary)\b",
    re.IGNORECASE,
)

# Debug mode in production
_DEBUG_MODE_RE = re.compile(
    r"(?:DEBUG\s*=\s*True|debug\s*:\s*true|NODE_ENV\s*[!=]=\s*['\"]development['\"])",
)


# --- Category 13: Data Protection ---

# Encryption at rest (positive signal)
_ENCRYPTION_RE = re.compile(
    r"\b(?:encrypt|decrypt|AES|Fernet|cipher|cryptography|"
    r"bcrypt|hashlib\.pbkdf2|crypto\.createCipheriv|"
    r"pgcrypto|field_encrypt|EncryptedField)\b",
    re.IGNORECASE,
)

# PII field patterns
_PII_FIELDS_RE = re.compile(
    r"\b(?:ssn|social_security|credit_card|card_number|"
    r"date_of_birth|national_id|passport|driver_license)\b",
    re.IGNORECASE,
)


def run_checks(files: list[dict], project_type: str = "unknown") -> list[Finding]:
    """Run file handling, logging, error handling, and data protection checks."""
    findings = []
    source_files = [f for f in files if f["extension"] in (".py", ".js", ".ts") and not f["is_test"]]

    has_file_uploads = False
    has_file_size_limit = False
    has_file_type_check = False
    has_structured_logging = False
    has_audit_trail = False
    has_error_handler = False
    has_encryption = False

    for f in source_files:
        content = f["content"]
        lines = content.split("\n")

        if _FILE_UPLOAD_RE.search(content):
            has_file_uploads = True
        if _FILE_SIZE_LIMIT_RE.search(content):
            has_file_size_limit = True
        if _FILE_TYPE_CHECK_RE.search(content):
            has_file_type_check = True
        if _STRUCTURED_LOGGING_RE.search(content):
            has_structured_logging = True
        if _AUDIT_RE.search(content):
            has_audit_trail = True
        if _ERROR_HANDLER_RE.search(content):
            has_error_handler = True
        if _ENCRYPTION_RE.search(content):
            has_encryption = True

        for i, line in enumerate(lines, 1):
            # Sensitive data in logs
            for pattern, desc, severity in _SENSITIVE_LOG_PATTERNS:
                if pattern.search(line):
                    # Skip comments
                    stripped = line.strip()
                    if stripped.startswith(("#", "//", "*")):
                        continue
                    findings.append(Finding(
                        category="logging",
                        category_id=10,
                        check="sensitive_data_logged",
                        status=CheckStatus.FAIL,
                        severity=severity,
                        message=desc,
                        file=f["relative_path"],
                        line=i,
                        snippet=stripped[:120],
                        fix="Never log passwords, tokens, or API keys. Redact sensitive fields before logging",
                    ))

            # Stack traces / error exposure
            for pattern, desc, severity in _STACK_TRACE_EXPOSURE:
                if pattern.search(line):
                    findings.append(Finding(
                        category="error_handling",
                        category_id=11,
                        check="error_exposure",
                        status=CheckStatus.FAIL,
                        severity=severity,
                        message=desc,
                        file=f["relative_path"],
                        line=i,
                        snippet=line.strip()[:120],
                        fix="Return generic error messages to clients. Log detailed errors server-side only",
                    ))

            # Debug mode
            if _DEBUG_MODE_RE.search(line):
                if f["extension"] in (".py", ".js", ".ts"):
                    stripped = line.strip()
                    if not stripped.startswith(("#", "//", "*", "if")):
                        findings.append(Finding(
                            category="error_handling",
                            category_id=11,
                            check="debug_mode",
                            status=CheckStatus.WARN,
                            severity="medium",
                            message="Debug mode may be enabled — exposes detailed errors in production",
                            file=f["relative_path"],
                            line=i,
                            snippet=stripped[:120],
                            fix="Ensure DEBUG is False / NODE_ENV is 'production' in production",
                        ))

            # PII without encryption
            if _PII_FIELDS_RE.search(line):
                context = "\n".join(lines[max(0, i - 5):min(len(lines), i + 5)])
                if not _ENCRYPTION_RE.search(context):
                    findings.append(Finding(
                        category="data_protection",
                        category_id=13,
                        check="pii_unencrypted",
                        status=CheckStatus.WARN,
                        severity="high",
                        message="PII field found without nearby encryption — may be stored in plaintext",
                        file=f["relative_path"],
                        line=i,
                        snippet=line.strip()[:120],
                        fix="Use field-level encryption for PII (SSN, credit cards, etc.)",
                    ))

    # Summary findings for missing infrastructure

    if has_file_uploads and not has_file_size_limit:
        findings.append(Finding(
            category="file_handling",
            category_id=9,
            check="no_file_size_limit",
            status=CheckStatus.FAIL,
            severity="high",
            message="File uploads detected without size limits — vulnerable to DoS via large uploads",
            fix="Set maximum file size (e.g., 10MB). Use multer limits or MAX_CONTENT_LENGTH",
        ))

    if has_file_uploads and not has_file_type_check:
        findings.append(Finding(
            category="file_handling",
            category_id=9,
            check="no_file_type_validation",
            status=CheckStatus.FAIL,
            severity="high",
            message="File uploads detected without type validation — users could upload malicious files",
            fix="Validate file MIME type and extension against an allowlist",
        ))

    if source_files and not has_structured_logging:
        findings.append(Finding(
            category="logging",
            category_id=10,
            check="no_structured_logging",
            status=CheckStatus.WARN,
            severity="low",
            message="No structured logging library detected — consider structured logs for better auditing",
            fix="Use structlog/loguru (Python) or winston/pino (Node.js) for structured logging",
        ))

    if source_files and not has_audit_trail:
        has_data_mutations = any(
            re.search(r"\b(?:create|update|delete|insert|remove|destroy)\b", f["content"], re.IGNORECASE)
            for f in source_files
        )
        if has_data_mutations:
            findings.append(Finding(
                category="logging",
                category_id=10,
                check="no_audit_trail",
                status=CheckStatus.WARN,
                severity="medium",
                message="No audit trail pattern detected — data mutations may not be tracked",
                fix="Implement audit logging: record who did what, when, on which resource",
            ))

    if source_files and not has_error_handler:
        findings.append(Finding(
            category="error_handling",
            category_id=11,
            check="no_global_error_handler",
            status=CheckStatus.WARN,
            severity="medium",
            message="No global error handler detected — unhandled errors may expose stack traces",
            fix="Add a global exception handler that returns consistent, safe error responses",
        ))

    if source_files and not has_encryption:
        has_database = any(
            re.search(r"\b(?:database|db|sql|mongo|postgres|mysql|supabase)\b", f["content"], re.IGNORECASE)
            for f in source_files
        )
        if has_database:
            findings.append(Finding(
                category="data_protection",
                category_id=13,
                check="no_encryption",
                status=CheckStatus.WARN,
                severity="medium",
                message="No application-level encryption detected — data may not be encrypted at rest",
                fix="Enable encryption at rest (database-level) and field-level encryption for sensitive data",
            ))

    return findings
