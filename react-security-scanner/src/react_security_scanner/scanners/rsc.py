"""React Server Components security scanner.

Detects security issues in React Server Components and Server Actions:
- Server actions without input validation
- eval/new Function/child_process in server components
- Dynamic imports with user-controlled paths
- Server actions without authentication checks
"""

import re
from pathlib import Path

from ..models import Finding, FindingCategory, Severity
from .common import walk_source_files, read_file_lines, is_server_component


EVAL_PATTERN = re.compile(r'\beval\s*\(')
NEW_FUNCTION_PATTERN = re.compile(r'\bnew\s+Function\s*\(')
CHILD_PROCESS_PATTERN = re.compile(
    r"""(?:require\s*\(\s*['"]child_process['"]\s*\)|"""
    r"""from\s+['"]child_process['"]|"""
    r"""\bexec\s*\(|\bexecSync\s*\(|\bspawn\s*\(|\bspawnSync\s*\()""",
)

USE_SERVER_DIRECTIVE = re.compile(r"""^\s*(?:"|')use server(?:"|')\s*;?\s*$""")

SERVER_ACTION_FUNCTION = re.compile(r'(?:export\s+)?(?:async\s+)?function\s+(\w+)')

AUTH_PATTERNS = [
    re.compile(r'getServerSession\s*\(', re.IGNORECASE),
    re.compile(r'\bauth\s*\(\s*\)', re.IGNORECASE),
    re.compile(r'getSession\s*\(', re.IGNORECASE),
    re.compile(r'currentUser\s*\(', re.IGNORECASE),
    re.compile(r'getUser\s*\(', re.IGNORECASE),
    re.compile(r'verifyToken\s*\(', re.IGNORECASE),
    re.compile(r'requireAuth\s*\(', re.IGNORECASE),
    re.compile(r'cookies\s*\(\s*\)', re.IGNORECASE),
    re.compile(r'headers\s*\(\s*\)', re.IGNORECASE),
    re.compile(r'clerk', re.IGNORECASE),
    re.compile(r'supabase\.auth', re.IGNORECASE),
]

VALIDATION_PATTERNS = [
    re.compile(r'\.parse\s*\('),
    re.compile(r'\.safeParse\s*\('),
    re.compile(r'\bvalidate\s*\(', re.IGNORECASE),
    re.compile(r'\bsanitize\s*\(', re.IGNORECASE),
    re.compile(r'\bjoi\.', re.IGNORECASE),
    re.compile(r'\byup\.', re.IGNORECASE),
    re.compile(r'\bz\.'),
]

DYNAMIC_IMPORT_PATTERN = re.compile(
    r'import\s*\(\s*(?:`[^`]*\$\{|[a-zA-Z_]\w*(?:\[|\.))',
)


def _has_auth_check(content: str) -> bool:
    """Check if content contains any authentication pattern."""
    for pattern in AUTH_PATTERNS:
        if pattern.search(content):
            return True
    return False


def _has_input_validation(content: str) -> bool:
    """Check if content contains input validation patterns."""
    for pattern in VALIDATION_PATTERNS:
        if pattern.search(content):
            return True
    return False


def _find_server_action_blocks(
    content: str, lines: list[tuple[int, str]],
) -> list[tuple[str, int, int, str]]:
    """Find server action function blocks in a file.

    Returns list of (function_name, start_line, end_line, block_content).
    """
    blocks: list[tuple[str, int, int, str]] = []
    is_use_server_file = False

    for line_num, line in lines[:5]:
        if USE_SERVER_DIRECTIVE.match(line):
            is_use_server_file = True
            break

    if not is_use_server_file:
        return blocks

    for line_num, line in lines:
        match = SERVER_ACTION_FUNCTION.search(line)
        if match:
            func_name = match.group(1)
            start = line_num
            block_lines: list[str] = []
            brace_depth = 0
            started = False
            for ln, l in lines[line_num - 1:]:
                block_lines.append(l)
                brace_depth += l.count("{") - l.count("}")
                if "{" in l:
                    started = True
                if started and brace_depth <= 0:
                    blocks.append((func_name, start, ln, "\n".join(block_lines)))
                    break
            else:
                if block_lines:
                    end = lines[-1][0] if lines else start
                    blocks.append((func_name, start, end, "\n".join(block_lines)))

    return blocks


def scan_rsc_patterns(
    project_path: str | Path,
    base_path: str | Path | None = None,
) -> list[Finding]:
    """Scan for React Server Components security issues.

    Args:
        project_path: Path to scan.
        base_path: Base path for relative file display.

    Returns:
        List of Finding objects.
    """
    project_path = Path(project_path)
    base_path = Path(base_path) if base_path else project_path
    findings: list[Finding] = []

    for file_path in walk_source_files(project_path):
        lines = read_file_lines(file_path)
        if not lines:
            continue

        content = "\n".join(line for _, line in lines)

        try:
            display_path = str(file_path.relative_to(base_path))
        except ValueError:
            display_path = str(file_path)

        if not is_server_component(file_path, content):
            continue

        # Check for eval() in server components
        for line_num, line in lines:
            if EVAL_PATTERN.search(line):
                findings.append(Finding(
                    category=FindingCategory.rsc_security,
                    severity=Severity.critical,
                    title="eval() in server component",
                    file=display_path,
                    line=line_num,
                    description=(
                        "eval() in a server component can execute arbitrary code on the server. "
                        "If any part of the input is user-controlled, this is a Remote Code Execution vulnerability."
                    ),
                    remediation="Remove eval(). Use a safe parser or a whitelist-based approach instead.",
                    cwe="CWE-95",
                ))

        # Check for new Function()
        for line_num, line in lines:
            if NEW_FUNCTION_PATTERN.search(line):
                findings.append(Finding(
                    category=FindingCategory.rsc_security,
                    severity=Severity.critical,
                    title="new Function() in server component",
                    file=display_path,
                    line=line_num,
                    description=(
                        "new Function() dynamically compiles and executes code on the server. "
                        "This is equivalent to eval() and can lead to RCE."
                    ),
                    remediation="Remove new Function(). Use static function references or a safe evaluation strategy.",
                    cwe="CWE-95",
                ))

        # Check for child_process usage
        for line_num, line in lines:
            if CHILD_PROCESS_PATTERN.search(line):
                findings.append(Finding(
                    category=FindingCategory.rsc_security,
                    severity=Severity.critical,
                    title="child_process usage in server component",
                    file=display_path,
                    line=line_num,
                    description=(
                        "child_process exec/spawn in a server component can execute system commands. "
                        "If user input reaches the command string, this is OS command injection."
                    ),
                    remediation=(
                        "Remove child_process usage from server components. "
                        "If shell commands are necessary, use a strict allowlist and never interpolate user input."
                    ),
                    cwe="CWE-78",
                ))

        # Check for dynamic imports with user-controlled paths
        for line_num, line in lines:
            if DYNAMIC_IMPORT_PATTERN.search(line):
                findings.append(Finding(
                    category=FindingCategory.rsc_security,
                    severity=Severity.high,
                    title="Dynamic import with variable path in server component",
                    file=display_path,
                    line=line_num,
                    description=(
                        "Dynamic import() with a variable path can load arbitrary modules. "
                        "If the path is user-controlled, an attacker could import sensitive files."
                    ),
                    remediation=(
                        "Use a static import map or allowlist of importable modules. "
                        "Example: const modules = { a: () => import('./a'), b: () => import('./b') };"
                    ),
                    cwe="CWE-98",
                ))

        # Check server actions for missing auth and validation
        action_blocks = _find_server_action_blocks(content, lines)
        for func_name, start_line, _end_line, block_content in action_blocks:
            if not _has_auth_check(block_content):
                findings.append(Finding(
                    category=FindingCategory.server_actions,
                    severity=Severity.high,
                    title=f"Server action '{func_name}' without authentication",
                    file=display_path,
                    line=start_line,
                    description=(
                        f"Server action '{func_name}' has no authentication check. "
                        "Anyone can call this action directly via POST request."
                    ),
                    remediation=(
                        f"Add auth check at the top of '{func_name}':\n"
                        "  const session = await getServerSession(authOptions);\n"
                        "  if (!session) throw new Error('Unauthorized');"
                    ),
                    cwe="CWE-306",
                ))

            if not _has_input_validation(block_content):
                findings.append(Finding(
                    category=FindingCategory.server_actions,
                    severity=Severity.medium,
                    title=f"Server action '{func_name}' without input validation",
                    file=display_path,
                    line=start_line,
                    description=(
                        f"Server action '{func_name}' does not validate its input. "
                        "Server actions receive FormData or arbitrary JSON from the client."
                    ),
                    remediation=(
                        f"Add zod validation at the top of '{func_name}':\n"
                        "  const schema = z.object({ ... });\n"
                        "  const data = schema.parse(input);"
                    ),
                    cwe="CWE-20",
                ))

    return findings
