"""Fail2ban security checks for VPS auditing."""

import subprocess
from typing import Optional

from ..models import CheckResult, CheckStatus


def _run_command(cmd: list[str], timeout: int = 10) -> tuple[Optional[str], Optional[str]]:
    """Run a shell command and return output.

    Returns:
        Tuple of (output, error). If successful, error is None.
        If failed, output is None and error contains the error message.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return None, result.stderr.strip() if result.stderr.strip() else f"Command failed with code {result.returncode}"
        return result.stdout.strip(), None
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, f"Command timed out: {' '.join(cmd)}"
    except Exception as e:
        return None, f"Error running command: {str(e)}"


def _check_fail2ban_installed() -> tuple[bool, CheckResult]:
    """Check if fail2ban is installed.

    Returns:
        Tuple of (is_installed, CheckResult).
    """
    # Try which fail2ban-client first
    output, error = _run_command(["which", "fail2ban-client"])
    if output:
        return True, CheckResult(
            check="fail2ban_installed",
            status=CheckStatus.PASS,
            severity="critical",
            message="fail2ban is installed",
            fix_available=False,
            fix_agent=None,
        )

    # Fallback: check systemctl list-unit-files
    output, error = _run_command(["systemctl", "list-unit-files"])
    if output and "fail2ban" in output:
        return True, CheckResult(
            check="fail2ban_installed",
            status=CheckStatus.PASS,
            severity="critical",
            message="fail2ban is installed",
            fix_available=False,
            fix_agent=None,
        )

    return False, CheckResult(
        check="fail2ban_installed",
        status=CheckStatus.FAIL,
        severity="critical",
        message="fail2ban is not installed. Install it to protect against brute-force attacks.",
        fix_available=True,
        fix_agent="joe/vps-fixer",
    )


def _check_fail2ban_service_status() -> CheckResult:
    """Check if fail2ban service is active."""
    output, error = _run_command(["systemctl", "is-active", "fail2ban"])

    if output == "active":
        return CheckResult(
            check="fail2ban_service",
            status=CheckStatus.PASS,
            severity="critical",
            message="fail2ban service is active",
            fix_available=False,
            fix_agent=None,
        )
    elif output == "inactive":
        return CheckResult(
            check="fail2ban_service",
            status=CheckStatus.FAIL,
            severity="critical",
            message="fail2ban service is inactive. Start and enable it for protection.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )
    else:
        return CheckResult(
            check="fail2ban_service",
            status=CheckStatus.FAIL,
            severity="critical",
            message=f"fail2ban service status: {output or error}. Service should be active.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )


def _check_ssh_jail_enabled() -> CheckResult:
    """Check if the SSH jail is enabled in fail2ban."""
    output, error = _run_command(["fail2ban-client", "status", "sshd"])

    if error:
        # Check if it's because the jail doesn't exist vs other errors
        if "does not exist" in (error or "").lower() or "no such" in (error or "").lower():
            return CheckResult(
                check="fail2ban_ssh_jail",
                status=CheckStatus.FAIL,
                severity="critical",
                message="fail2ban SSH jail (sshd) is not enabled. Enable it to protect SSH from brute-force attacks.",
                fix_available=True,
                fix_agent="joe/vps-fixer",
            )
        else:
            return CheckResult(
                check="fail2ban_ssh_jail",
                status=CheckStatus.WARN,
                severity="critical",
                message=f"Could not check fail2ban SSH jail status: {error}",
                fix_available=True,
                fix_agent="joe/vps-fixer",
            )

    # If we got output, the jail exists and is enabled
    if output and "sshd" in output.lower():
        return CheckResult(
            check="fail2ban_ssh_jail",
            status=CheckStatus.PASS,
            severity="critical",
            message="fail2ban SSH jail (sshd) is enabled",
            fix_available=False,
            fix_agent=None,
        )

    return CheckResult(
        check="fail2ban_ssh_jail",
        status=CheckStatus.WARN,
        severity="critical",
        message="Could not verify fail2ban SSH jail status",
        fix_available=True,
        fix_agent="joe/vps-fixer",
    )


def _get_banned_count() -> CheckResult:
    """Get the count of currently banned IPs from fail2ban."""
    output, error = _run_command(["fail2ban-client", "status", "sshd"])

    if error:
        return CheckResult(
            check="fail2ban_banned_count",
            status=CheckStatus.WARN,
            severity="low",
            message=f"Could not retrieve banned IP count: {error}",
            fix_available=False,
            fix_agent=None,
        )

    # Parse output to find banned count
    # Output format includes: "Currently banned: X"
    banned_count = 0
    if output:
        for line in output.splitlines():
            line = line.strip()
            if "currently banned" in line.lower():
                try:
                    # Extract number from "Currently banned:   X"
                    parts = line.split(":")
                    if len(parts) >= 2:
                        banned_count = int(parts[1].strip())
                except (ValueError, IndexError):
                    pass

    if banned_count > 0:
        return CheckResult(
            check="fail2ban_banned_count",
            status=CheckStatus.PASS,
            severity="low",
            message=f"fail2ban has {banned_count} currently banned IP(s) - actively protecting the server",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="fail2ban_banned_count",
            status=CheckStatus.PASS,
            severity="low",
            message="fail2ban has 0 currently banned IPs",
            fix_available=False,
            fix_agent=None,
        )


def run_fail2ban_checks() -> list[CheckResult]:
    """Run all fail2ban security checks.

    Returns:
        List of CheckResult objects for each fail2ban security check.
    """
    results: list[CheckResult] = []

    # Check if fail2ban is installed
    is_installed, install_result = _check_fail2ban_installed()
    results.append(install_result)

    # If not installed, no point in checking further
    if not is_installed:
        return results

    # Check service status
    results.append(_check_fail2ban_service_status())

    # Check SSH jail
    results.append(_check_ssh_jail_enabled())

    # Get banned count
    results.append(_get_banned_count())

    return results
