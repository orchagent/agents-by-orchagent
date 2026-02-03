"""User security checks for VPS auditing."""

import subprocess
from typing import Optional

from ..models import CheckResult, CheckStatus


def _read_file(path: str) -> tuple[Optional[str], Optional[str]]:
    """Read a file and return its contents.

    Returns:
        Tuple of (contents, error). If successful, error is None.
        If failed, contents is None and error contains the error message.
    """
    try:
        with open(path, "r") as f:
            return f.read(), None
    except PermissionError:
        return None, f"Permission denied reading {path}"
    except FileNotFoundError:
        return None, f"File not found: {path}"
    except Exception as e:
        return None, f"Error reading {path}: {str(e)}"


def _run_command(cmd: list[str]) -> tuple[Optional[str], Optional[str]]:
    """Run a command and return its output.

    Returns:
        Tuple of (output, error). If successful, error is None.
        If failed, output is None and error contains the error message.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None, f"Command failed: {result.stderr.strip()}"
        return result.stdout, None
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, "Command timed out"
    except Exception as e:
        return None, f"Error running command: {str(e)}"


def _check_empty_passwords() -> CheckResult:
    """Check /etc/shadow for users with empty password field.

    Users with empty password fields can log in without a password,
    which is a critical security vulnerability.
    """
    # Try to read /etc/shadow directly first
    content, error = _read_file("/etc/shadow")

    if error:
        # Try using awk command with sudo as fallback
        output, cmd_error = _run_command(
            ["awk", "-F:", '($2 == "") {print $1}', "/etc/shadow"]
        )

        if cmd_error:
            return CheckResult(
                check="users_empty_passwords",
                status=CheckStatus.WARN,
                severity="critical",
                message=f"Could not check for empty passwords: {error}. Run as root for full audit.",
                fix_available=False,
                fix_agent=None,
            )

        users_with_empty = [u.strip() for u in output.strip().split("\n") if u.strip()]
    else:
        # Parse /etc/shadow content
        users_with_empty = []
        for line in content.strip().split("\n"):
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                users_with_empty.append(parts[0])

    if not users_with_empty:
        return CheckResult(
            check="users_empty_passwords",
            status=CheckStatus.PASS,
            severity="critical",
            message="No users with empty passwords found",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="users_empty_passwords",
            status=CheckStatus.FAIL,
            severity="critical",
            message=f"Users with empty passwords: {', '.join(users_with_empty)}. Set passwords immediately!",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )


def _check_multiple_uid_zero() -> CheckResult:
    """Check for multiple accounts with UID 0.

    Only the root account should have UID 0. Multiple accounts with
    UID 0 could indicate a compromised system or backdoor account.
    """
    content, error = _read_file("/etc/passwd")

    if error:
        return CheckResult(
            check="users_multiple_uid_zero",
            status=CheckStatus.WARN,
            severity="critical",
            message=f"Could not check for multiple UID 0 accounts: {error}",
            fix_available=False,
            fix_agent=None,
        )

    uid_zero_users = []
    for line in content.strip().split("\n"):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0":
            uid_zero_users.append(parts[0])

    if len(uid_zero_users) == 1 and uid_zero_users[0] == "root":
        return CheckResult(
            check="users_multiple_uid_zero",
            status=CheckStatus.PASS,
            severity="critical",
            message="Only root has UID 0",
            fix_available=False,
            fix_agent=None,
        )
    elif len(uid_zero_users) == 0:
        return CheckResult(
            check="users_multiple_uid_zero",
            status=CheckStatus.WARN,
            severity="critical",
            message="No UID 0 account found (unusual configuration)",
            fix_available=False,
            fix_agent=None,
        )
    else:
        non_root_uid_zero = [u for u in uid_zero_users if u != "root"]
        if non_root_uid_zero:
            return CheckResult(
                check="users_multiple_uid_zero",
                status=CheckStatus.FAIL,
                severity="critical",
                message=f"Multiple accounts with UID 0: {', '.join(uid_zero_users)}. Non-root UID 0 accounts may indicate compromise!",
                fix_available=True,
                fix_agent="orchagent/vps-fixer",
            )
        else:
            return CheckResult(
                check="users_multiple_uid_zero",
                status=CheckStatus.PASS,
                severity="critical",
                message="Only root has UID 0",
                fix_available=False,
                fix_agent=None,
            )


def _check_sudo_users() -> CheckResult:
    """Audit users in sudo/wheel group.

    Lists users with sudo/administrative privileges for manual review.
    """
    # Try to read /etc/group to find sudo/wheel group members
    content, error = _read_file("/etc/group")

    if error:
        return CheckResult(
            check="users_sudo_audit",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Could not audit sudo users: {error}",
            fix_available=False,
            fix_agent=None,
        )

    sudo_users = []
    wheel_users = []

    for line in content.strip().split("\n"):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 4:
            group_name = parts[0]
            members = parts[3].split(",") if parts[3] else []
            members = [m.strip() for m in members if m.strip()]

            if group_name == "sudo":
                sudo_users.extend(members)
            elif group_name == "wheel":
                wheel_users.extend(members)

    all_privileged = list(set(sudo_users + wheel_users))

    if not all_privileged:
        return CheckResult(
            check="users_sudo_audit",
            status=CheckStatus.PASS,
            severity="medium",
            message="No users in sudo/wheel groups (root-only access)",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="users_sudo_audit",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Users with sudo privileges: {', '.join(sorted(all_privileged))}. Review for necessity.",
            fix_available=False,
            fix_agent=None,
        )


def _check_password_aging() -> CheckResult:
    """Check if password aging is configured.

    Verifies that PASS_MAX_DAYS is set in /etc/login.defs to enforce
    regular password changes.
    """
    content, error = _read_file("/etc/login.defs")

    if error:
        return CheckResult(
            check="users_password_aging",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Could not check password aging: {error}",
            fix_available=False,
            fix_agent=None,
        )

    pass_max_days = None
    pass_min_days = None
    pass_warn_age = None

    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) >= 2:
            if parts[0] == "PASS_MAX_DAYS":
                try:
                    pass_max_days = int(parts[1])
                except ValueError:
                    pass
            elif parts[0] == "PASS_MIN_DAYS":
                try:
                    pass_min_days = int(parts[1])
                except ValueError:
                    pass
            elif parts[0] == "PASS_WARN_AGE":
                try:
                    pass_warn_age = int(parts[1])
                except ValueError:
                    pass

    if pass_max_days is None:
        return CheckResult(
            check="users_password_aging",
            status=CheckStatus.FAIL,
            severity="medium",
            message="PASS_MAX_DAYS not configured in /etc/login.defs. Password aging not enforced.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )
    elif pass_max_days == 99999 or pass_max_days > 365:
        return CheckResult(
            check="users_password_aging",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"PASS_MAX_DAYS={pass_max_days} (effectively no expiration). Consider setting to 90 days or less.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )
    elif pass_max_days <= 90:
        details = [f"PASS_MAX_DAYS={pass_max_days}"]
        if pass_min_days is not None:
            details.append(f"PASS_MIN_DAYS={pass_min_days}")
        if pass_warn_age is not None:
            details.append(f"PASS_WARN_AGE={pass_warn_age}")

        return CheckResult(
            check="users_password_aging",
            status=CheckStatus.PASS,
            severity="medium",
            message=f"Password aging is configured ({', '.join(details)})",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="users_password_aging",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"PASS_MAX_DAYS={pass_max_days}. Consider reducing to 90 days for better security.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )


def run_user_checks() -> list[CheckResult]:
    """Run all user security checks.

    Returns:
        List of CheckResult objects for each user security check.
    """
    results: list[CheckResult] = []

    results.append(_check_empty_passwords())
    results.append(_check_multiple_uid_zero())
    results.append(_check_sudo_users())
    results.append(_check_password_aging())

    return results
