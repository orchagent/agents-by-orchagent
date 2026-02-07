"""Database schema exposure scanner.

Detects database schema definitions that may expose sensitive data structures:
- SQL schema definitions (CREATE TABLE, etc.)
- ORM model definitions (SQLAlchemy, Prisma, Django, TypeORM) with PII columns
- Database migration files with schema details
- Connection strings with embedded credentials
"""

import re
from pathlib import Path

from ..models import Finding, FindingCategory, RiskLevel
from .common import (
    walk_source_files,
    read_file_lines,
    get_display_path,
    SOURCE_EXTENSIONS,
    SCHEMA_EXTENSIONS,
    ALL_EXTENSIONS,
)


# PII column names to flag in schemas
PII_COLUMN_NAMES = {
    "email", "phone", "phone_number", "mobile", "ssn", "social_security",
    "credit_card", "card_number", "cvv", "address", "street_address",
    "date_of_birth", "dob", "birthday", "first_name", "last_name",
    "full_name", "password", "password_hash", "salary", "income",
    "bank_account", "routing_number", "tax_id", "driver_license",
    "passport", "medical_record", "diagnosis", "insurance_id",
    "patient_id", "health_id", "ip_address",
}

# SQL CREATE TABLE pattern
SQL_CREATE_TABLE = re.compile(
    r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"\x27]?(\w+)[`"\x27]?',
    re.IGNORECASE,
)

# ORM model patterns
SQLALCHEMY_MODEL = re.compile(
    r'class\s+(\w+)\s*\(.*(?:Base|Model|DeclarativeBase)\s*\)',
)

DJANGO_MODEL = re.compile(
    r'class\s+(\w+)\s*\(.*models\.Model\s*\)',
)

PRISMA_MODEL = re.compile(
    r'model\s+(\w+)\s*\{',
)

TYPEORM_ENTITY = re.compile(
    r'@Entity\s*\(',
)

# Connection string patterns
CONNECTION_STRING_PATTERNS = [
    re.compile(
        r'(?:postgres|postgresql|mysql|mongodb|redis|mssql)://\S+:\S+@\S+',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?:DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL)\s*[:=]\s*["\x27](?:postgres|mysql|mongodb)\S+["\x27]',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?:connection_string|conn_str|dsn)\s*[:=]\s*["\x27]\S+://\S+["\x27]',
        re.IGNORECASE,
    ),
]

# Migration file indicators
MIGRATION_INDICATORS = [
    "/migrations/", "/migrate/", "/alembic/", "/db/migrate/",
    "migration", "_migration.", ".migration.",
]


def _is_migration_file(file_path: Path) -> bool:
    """Check if a file is a database migration file."""
    path_str = str(file_path).lower()
    return any(indicator in path_str for indicator in MIGRATION_INDICATORS)


def _find_pii_columns(lines: list[tuple[int, str]]) -> list[tuple[int, str, str]]:
    """Find PII column names in a list of lines.

    Returns:
        List of (line_number, column_name, line_content) tuples.
    """
    results: list[tuple[int, str, str]] = []
    for line_num, line_content in lines:
        lower = line_content.lower()
        for col_name in PII_COLUMN_NAMES:
            if col_name in lower:
                # Verify it looks like a column/field definition, not just a comment
                stripped = line_content.strip()
                if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("--"):
                    continue
                results.append((line_num, col_name, line_content.strip()))
    return results


def _scan_file_for_schema(
    file_path: Path,
    base_path: Path,
) -> list[Finding]:
    """Scan a single file for schema exposure issues."""
    findings: list[Finding] = []
    display_path = get_display_path(file_path, base_path)
    lines = read_file_lines(file_path)

    if not lines:
        return findings

    full_content = "\n".join(line for _, line in lines)
    is_migration = _is_migration_file(file_path)

    # Check for SQL CREATE TABLE with PII columns
    if SQL_CREATE_TABLE.search(full_content):
        pii_cols = _find_pii_columns(lines)
        if pii_cols:
            col_names = list(set(col for _, col, _ in pii_cols))
            first_line = pii_cols[0][0]
            findings.append(
                Finding(
                    category=FindingCategory.schema_exposure,
                    risk_level=RiskLevel.high if not is_migration else RiskLevel.medium,
                    title="SQL schema with PII columns",
                    file=display_path,
                    line=first_line,
                    description=(
                        f"SQL schema definition contains PII columns: {', '.join(col_names)}. "
                        f"{'This is a migration file that may be committed to version control.' if is_migration else ''}"
                    ),
                    data_types_at_risk=col_names,
                    remediation=(
                        "Ensure database schemas with PII columns are not exposed to AI tools. "
                        "Add these tables to DLP policies and ensure schema files are excluded "
                        "from AI tool context."
                    ),
                )
            )

    # Check for ORM models with PII columns
    for orm_pattern in [SQLALCHEMY_MODEL, DJANGO_MODEL, PRISMA_MODEL]:
        if orm_pattern.search(full_content):
            pii_cols = _find_pii_columns(lines)
            if pii_cols:
                col_names = list(set(col for _, col, _ in pii_cols))
                first_line = pii_cols[0][0]
                findings.append(
                    Finding(
                        category=FindingCategory.schema_exposure,
                        risk_level=RiskLevel.medium,
                        title="ORM model with PII fields",
                        file=display_path,
                        line=first_line,
                        description=(
                            f"ORM model definition contains PII fields: {', '.join(col_names)}. "
                            "These schemas could be inadvertently shared with AI tools."
                        ),
                        data_types_at_risk=col_names,
                        remediation=(
                            "Add data classification annotations to ORM models with PII. "
                            "Implement field-level access controls and ensure these models "
                            "are excluded from AI tool context."
                        ),
                    )
                )

    # Check for TypeORM entities
    if TYPEORM_ENTITY.search(full_content):
        pii_cols = _find_pii_columns(lines)
        if pii_cols:
            col_names = list(set(col for _, col, _ in pii_cols))
            first_line = pii_cols[0][0]
            findings.append(
                Finding(
                    category=FindingCategory.schema_exposure,
                    risk_level=RiskLevel.medium,
                    title="TypeORM entity with PII columns",
                    file=display_path,
                    line=first_line,
                    description=(
                        f"TypeORM entity contains PII columns: {', '.join(col_names)}."
                    ),
                    data_types_at_risk=col_names,
                    remediation=(
                        "Add data classification to TypeORM entities with PII. "
                        "Use column-level encryption for sensitive fields."
                    ),
                )
            )

    # Check for connection strings with embedded credentials
    for conn_pattern in CONNECTION_STRING_PATTERNS:
        for line_num, line_content in lines:
            if conn_pattern.search(line_content):
                findings.append(
                    Finding(
                        category=FindingCategory.schema_exposure,
                        risk_level=RiskLevel.critical,
                        title="Database connection string with embedded credentials",
                        file=display_path,
                        line=line_num,
                        description=(
                            "Database connection string contains embedded credentials. "
                            "If this code is shared with AI tools, the credentials could be exposed."
                        ),
                        data_types_at_risk=["database_credentials"],
                        remediation=(
                            "Move database credentials to environment variables. "
                            "Never hardcode connection strings with passwords in source code."
                        ),
                    )
                )
                break  # One finding per file for connection strings

    return findings


def scan_schema_exposure(
    repo_path: str | Path,
    exclude_dirs: set[str] | None = None,
) -> list[Finding]:
    """Scan a repository for database schema exposure issues.

    Args:
        repo_path: Path to the repository root.
        exclude_dirs: Additional directory names to skip.

    Returns:
        List of Finding objects for detected schema exposure issues.
    """
    base = Path(repo_path)
    findings: list[Finding] = []

    for file_path in walk_source_files(base, extensions=ALL_EXTENSIONS, exclude_dirs=exclude_dirs):
        file_findings = _scan_file_for_schema(file_path, base)
        findings.extend(file_findings)

    return findings
