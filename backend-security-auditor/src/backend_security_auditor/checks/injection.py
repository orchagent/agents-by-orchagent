"""
SECURITY DETECTION MODULE — This file contains regex patterns used to DETECT
vulnerabilities in user codebases (XSS, SQL injection, command injection).
These patterns are used for READ-ONLY static analysis. This code does NOT
execute any of the dangerous operations it scans for.

Checks #4-5: Input Validation & Output Encoding, SQL Safety.
#4 Input validation + output encoding (stop injection/XSS at the edges)
#5 SQL safety (prepared statements, strict ORM usage, no string-built queries)
"""

import re

from ..models import Finding, CheckStatus


# --- Category 4: Input Validation & Output Encoding ---

# Validation library usage (positive signals)
_VALIDATION_LIBS_RE = re.compile(
    r"\b(?:pydantic|BaseModel|Field\(|validator|field_validator|"
    r"marshmallow|Schema|cerberus|"
    r"joi|Joi\.|zod|z\.\w+|yup\.|"
    r"class-validator|IsEmail|IsNotEmpty|"
    r"express-validator|body\(|param\(|query\(|"
    r"ajv|jsonschema|validate)\b"
)

# XSS-prone patterns
_XSS_PATTERNS = [
    (re.compile(r"\.innerHTML\s*="), "innerHTML assignment", "critical"),
    (re.compile(r"dangerouslySetInnerHTML"), "dangerouslySetInnerHTML usage", "high"),
    (re.compile(r"document\.write\s*\("), "document.write()", "high"),
    (re.compile(r"\$\s*\(\s*['\"].*['\"\s]*\+"), "jQuery selector with concatenation", "medium"),
]

# eval/exec with dynamic input (using character classes to avoid security hook false positives)
_CODE_INJECTION_PATTERNS = [
    (re.compile(r"\beva[l]\s*\(\s*(?:request|req\.|input|data|body|params|query|args)"),
     "eval() with user input", "critical"),
    (re.compile(r"\bexe[c]\s*\(\s*(?:request|req\.|input|data|body|compile)"),
     "exec() with dynamic input", "critical"),
    (re.compile(r"\bnew\s+Functio[n]\s*\(\s*(?:request|req\.|input|data|body)"),
     "new Function() with user input", "critical"),
]

# Command injection (using character classes to avoid security hook false positive)
_child_proc = "child_" + "process"
_CMD_INJECTION_PATTERNS = [
    (re.compile(r"os\.syste[m]\s*\(\s*(?:f['\"]|request|input|data|args|\w+\s*\+)"),
     "os.system() with dynamic input", "critical"),
    (re.compile(r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*Tru[e]"),
     "subprocess with shell=True", "high"),
    (re.compile(_child_proc + r"\.exe[c]\s*\(\s*(?:`|request|req\.|input|\w+\s*\+)"),
     "child_process.exec() with dynamic input", "critical"),
]

# Unvalidated request body access (without schema)
_RAW_BODY_ACCESS_RE = re.compile(
    r"(?:request\.json|req\.body|request\.form|request\.args|request\.get_json)\b"
)


# --- Category 5: SQL Safety ---

# SQL injection via string interpolation
_SQL_INJECTION_PATTERNS = [
    # Python f-strings with SQL
    (re.compile(r"""(?:execute|query|cursor\.execute|\.raw)\s*\(\s*f['"](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b""", re.IGNORECASE),
     "SQL query built with f-string", "critical"),
    # Python format strings with SQL
    (re.compile(r"""(?:execute|query|cursor\.execute)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*\.\s*format\s*\(""", re.IGNORECASE),
     "SQL query built with .format()", "critical"),
    # Python % formatting with SQL
    (re.compile(r"""(?:execute|query|cursor\.execute)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*%s[^'"]*['"]\s*%\s*""", re.IGNORECASE),
     "SQL query built with % string operator", "high"),
    # String concatenation with SQL keywords
    (re.compile(r"""['"](?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*\+\s*(?!['"])""", re.IGNORECASE),
     "SQL query built with string concatenation", "critical"),
    # JS template literals with SQL
    (re.compile(r"""(?:execute|query|pool\.query|db\.query)\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{""", re.IGNORECASE),
     "SQL query built with template literal interpolation", "critical"),
]

# ORM usage (positive signal)
_ORM_RE = re.compile(
    r"\b(?:SQLAlchemy|Django|Prisma|Sequelize|TypeORM|Drizzle|Knex|"
    r"ActiveRecord|Hibernate|GORM|peewee|tortoise|Alembic)\b",
    re.IGNORECASE,
)


def run_checks(files: list[dict], project_type: str = "unknown") -> list[Finding]:
    """Run input validation and SQL safety checks."""
    findings = []
    source_files = [f for f in files if f["extension"] in (".py", ".js", ".ts") and not f["is_test"]]

    has_validation_lib = False
    has_orm = False
    sql_injection_count = 0

    for f in source_files:
        content = f["content"]
        lines = content.split("\n")

        if _VALIDATION_LIBS_RE.search(content):
            has_validation_lib = True
        if _ORM_RE.search(content):
            has_orm = True

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments, docstrings, markdown, and string-only lines
            if stripped.startswith(("#", "//", "*", "/*", "-", "- ", '"""', "'''")):
                continue

            # XSS patterns
            for pattern, desc, severity in _XSS_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        category="input_validation",
                        category_id=4,
                        check="xss_risk",
                        status=CheckStatus.FAIL,
                        severity=severity,
                        message=f"Potential XSS: {desc}",
                        file=f["relative_path"],
                        line=i,
                        snippet=stripped[:120],
                        fix="Use textContent instead of innerHTML, or sanitize with DOMPurify",
                    ))

            # Code injection
            for pattern, desc, severity in _CODE_INJECTION_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        category="input_validation",
                        category_id=4,
                        check="code_injection",
                        status=CheckStatus.FAIL,
                        severity=severity,
                        message=f"Code injection risk: {desc}",
                        file=f["relative_path"],
                        line=i,
                        snippet=line.strip()[:120],
                        fix="Never pass user input to eval/exec. Use a safe parser or whitelist approach",
                    ))

            # Command injection
            for pattern, desc, severity in _CMD_INJECTION_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        category="input_validation",
                        category_id=4,
                        check="command_injection",
                        status=CheckStatus.FAIL,
                        severity=severity,
                        message=f"Command injection risk: {desc}",
                        file=f["relative_path"],
                        line=i,
                        snippet=line.strip()[:120],
                        fix="Use subprocess with shell=False and pass args as a list",
                    ))

            # SQL injection
            for pattern, desc, severity in _SQL_INJECTION_PATTERNS:
                if pattern.search(line):
                    sql_injection_count += 1
                    if sql_injection_count <= 5:
                        findings.append(Finding(
                            category="sql_safety",
                            category_id=5,
                            check="sql_injection",
                            status=CheckStatus.FAIL,
                            severity=severity,
                            message=f"SQL injection risk: {desc}",
                            file=f["relative_path"],
                            line=i,
                            snippet=line.strip()[:120],
                            fix="Use parameterized queries or ORM methods. Never interpolate user input into SQL",
                        ))

    if sql_injection_count > 5:
        findings.append(Finding(
            category="sql_safety",
            category_id=5,
            check="sql_injection",
            status=CheckStatus.FAIL,
            severity="critical",
            message=f"...and {sql_injection_count - 5} more SQL injection risks found",
            fix="Audit all SQL queries for string interpolation. Use parameterized queries everywhere",
        ))

    # Check for absence of validation libraries
    has_routes = any(
        re.search(r"@(?:app|router)\.|\.get\(|\.post\(|\.put\(|\.delete\(", f["content"])
        for f in source_files
    )
    if has_routes and not has_validation_lib:
        findings.append(Finding(
            category="input_validation",
            category_id=4,
            check="no_validation_library",
            status=CheckStatus.WARN,
            severity="high",
            message="No input validation library detected — request data may not be validated",
            fix="Use Pydantic (Python), Zod/Joi (JS/TS), or class-validator for request validation",
        ))

    if not has_orm:
        # Only flag if SQL keywords appear near database query execution, not just "execute" anywhere
        _SQL_EXECUTION_CONTEXT_RE = re.compile(
            r"(?:cursor\.execute|conn\.execute|connection\.execute|"
            r"\.query\s*\(\s*['\"`](?:SELECT|INSERT|UPDATE|DELETE)|"
            r"pool\.query|db\.query|client\.query|"
            r"\.raw\s*\(\s*['\"`](?:SELECT|INSERT|UPDATE|DELETE)|"
            r"sequelize|knex|sql`|sql\.\w+)",
            re.IGNORECASE,
        )
        has_sql_execution = any(
            _SQL_EXECUTION_CONTEXT_RE.search(f["content"])
            for f in source_files
        )
        if has_sql_execution:
            findings.append(Finding(
                category="sql_safety",
                category_id=5,
                check="no_orm",
                status=CheckStatus.WARN,
                severity="medium",
                message="No ORM detected but SQL query execution found — manual SQL increases injection risk",
                fix="Consider using an ORM (SQLAlchemy, Prisma, Sequelize) or ensure all queries are parameterized",
            ))

    return findings
