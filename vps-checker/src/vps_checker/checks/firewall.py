"""Firewall security checks for VPS auditing."""

import subprocess
from typing import Optional

from ..models import CheckResult, CheckStatus


# Commonly dangerous ports that should not be exposed to 0.0.0.0
DANGEROUS_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}


def _run_command(cmd: list[str]) -> tuple[Optional[str], Optional[str]]:
    """Run a shell command and return stdout and error.

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
            return None, result.stderr.strip() or f"Command failed with code {result.returncode}"
        return result.stdout, None
    except FileNotFoundError:
        return None, "ufw not found - firewall may not be installed"
    except subprocess.TimeoutExpired:
        return None, "Command timed out"
    except Exception as e:
        return None, f"Error running command: {str(e)}"


def _check_ufw_status() -> tuple[CheckResult, Optional[str]]:
    """Check if UFW firewall is active.

    Returns:
        Tuple of (CheckResult, ufw_output). ufw_output is None if ufw is not active/installed.
    """
    output, error = _run_command(["ufw", "status"])

    if error:
        if "not found" in error.lower():
            return CheckResult(
                check="firewall_ufw_status",
                status=CheckStatus.FAIL,
                severity="critical",
                message="UFW firewall is not installed. Install with: apt install ufw",
                fix_available=True,
                fix_agent="joe/vps-fixer",
            ), None
        return CheckResult(
            check="firewall_ufw_status",
            status=CheckStatus.WARN,
            severity="critical",
            message=f"Could not check UFW status: {error}",
            fix_available=False,
            fix_agent=None,
        ), None

    if "Status: active" in output:
        return CheckResult(
            check="firewall_ufw_status",
            status=CheckStatus.PASS,
            severity="critical",
            message="UFW firewall is active",
            fix_available=False,
            fix_agent=None,
        ), output
    else:
        return CheckResult(
            check="firewall_ufw_status",
            status=CheckStatus.FAIL,
            severity="critical",
            message="UFW firewall is not active. Enable with: ufw enable",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        ), None


def _check_default_policy() -> CheckResult:
    """Check if default incoming policy is deny."""
    output, error = _run_command(["ufw", "status", "verbose"])

    if error:
        return CheckResult(
            check="firewall_default_policy",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not check UFW default policy: {error}",
            fix_available=False,
            fix_agent=None,
        )

    # Look for "Default: deny (incoming)" in the verbose output
    output_lower = output.lower()
    if "default: deny (incoming)" in output_lower:
        return CheckResult(
            check="firewall_default_policy",
            status=CheckStatus.PASS,
            severity="high",
            message="Default incoming policy is set to deny",
            fix_available=False,
            fix_agent=None,
        )
    elif "default: reject (incoming)" in output_lower:
        return CheckResult(
            check="firewall_default_policy",
            status=CheckStatus.PASS,
            severity="high",
            message="Default incoming policy is set to reject",
            fix_available=False,
            fix_agent=None,
        )
    elif "default: allow (incoming)" in output_lower:
        return CheckResult(
            check="firewall_default_policy",
            status=CheckStatus.FAIL,
            severity="high",
            message="Default incoming policy is set to ALLOW - this is overly permissive. Set to deny with: ufw default deny incoming",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )
    else:
        return CheckResult(
            check="firewall_default_policy",
            status=CheckStatus.WARN,
            severity="high",
            message="Could not determine default incoming policy from UFW output",
            fix_available=False,
            fix_agent=None,
        )


def _check_ssh_allowed(ufw_output: str) -> CheckResult:
    """Check if SSH port 22 is allowed through the firewall.

    Important to ensure SSH access is not blocked to avoid lockout.
    """
    output_lower = ufw_output.lower()

    # Check for various forms of SSH being allowed
    # UFW can show: 22/tcp, 22, OpenSSH, SSH
    ssh_patterns = ["22/tcp", "22 ", "openssh", "ssh"]
    ssh_allowed = any(pattern in output_lower for pattern in ssh_patterns)

    # Also check with ufw status verbose for more detail
    if not ssh_allowed:
        verbose_output, _ = _run_command(["ufw", "status", "verbose"])
        if verbose_output:
            verbose_lower = verbose_output.lower()
            ssh_allowed = any(pattern in verbose_lower for pattern in ssh_patterns)

    if ssh_allowed:
        return CheckResult(
            check="firewall_ssh_allowed",
            status=CheckStatus.PASS,
            severity="critical",
            message="SSH (port 22) is allowed through the firewall",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="firewall_ssh_allowed",
            status=CheckStatus.WARN,
            severity="critical",
            message="SSH (port 22) may not be explicitly allowed. Verify SSH access before enabling firewall to avoid lockout.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )


def _check_ssh_rate_limiting() -> CheckResult:
    """Check if SSH has rate limiting enabled."""
    output, error = _run_command(["ufw", "status"])

    if error:
        return CheckResult(
            check="firewall_ssh_rate_limit",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Could not check SSH rate limiting: {error}",
            fix_available=False,
            fix_agent=None,
        )

    output_lower = output.lower()

    # Check for LIMIT on SSH/port 22
    # UFW shows "LIMIT" for rate-limited rules
    lines = output_lower.splitlines()
    has_ssh_limit = False
    for line in lines:
        if ("22" in line or "ssh" in line or "openssh" in line) and "limit" in line:
            has_ssh_limit = True
            break

    if has_ssh_limit:
        return CheckResult(
            check="firewall_ssh_rate_limit",
            status=CheckStatus.PASS,
            severity="medium",
            message="SSH has rate limiting enabled (ufw limit)",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="firewall_ssh_rate_limit",
            status=CheckStatus.WARN,
            severity="medium",
            message="SSH does not have rate limiting. Consider: ufw limit ssh",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )


def _check_dangerous_ports() -> CheckResult:
    """Check for commonly dangerous ports exposed to all interfaces (0.0.0.0)."""
    output, error = _run_command(["ufw", "status"])

    if error:
        return CheckResult(
            check="firewall_dangerous_ports",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not audit open ports: {error}",
            fix_available=False,
            fix_agent=None,
        )

    output_lower = output.lower()
    exposed_dangerous = []

    for port, service in DANGEROUS_PORTS.items():
        port_str = str(port)
        # Check if port is in the rules (could be open)
        # Look for patterns like "3306" or "3306/tcp" in ALLOW rules
        for line in output_lower.splitlines():
            if port_str in line and "allow" in line:
                # Check if it's exposed to Anywhere (not just specific IPs)
                if "anywhere" in line:
                    exposed_dangerous.append(f"{port} ({service})")
                    break

    if not exposed_dangerous:
        return CheckResult(
            check="firewall_dangerous_ports",
            status=CheckStatus.PASS,
            severity="high",
            message="No commonly dangerous database ports (MySQL, PostgreSQL, Redis, MongoDB) exposed to all interfaces",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="firewall_dangerous_ports",
            status=CheckStatus.FAIL,
            severity="high",
            message=f"Dangerous ports exposed to Anywhere: {', '.join(exposed_dangerous)}. These should be restricted to specific IPs or localhost.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )


def run_firewall_checks() -> list[CheckResult]:
    """Run all firewall security checks.

    Returns:
        List of CheckResult objects for each firewall security check.
    """
    results: list[CheckResult] = []

    # First check UFW status - this also returns the output for other checks
    status_result, ufw_output = _check_ufw_status()
    results.append(status_result)

    # If UFW is not active or not installed, we can't run the other checks meaningfully
    if ufw_output is None:
        return results

    # Run remaining checks
    results.append(_check_default_policy())
    results.append(_check_ssh_allowed(ufw_output))
    results.append(_check_ssh_rate_limiting())
    results.append(_check_dangerous_ports())

    return results
