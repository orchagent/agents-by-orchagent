"""SSH security checks for VPS auditing."""

import subprocess
from typing import Optional

from ..models import CheckResult, CheckStatus


def _run_sshd_config() -> tuple[Optional[str], Optional[str]]:
    """Run sshd -T to get effective SSH configuration.

    Returns:
        Tuple of (output, error). If successful, error is None.
        If failed, output is None and error contains the error message.
    """
    try:
        result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None, f"sshd -T failed: {result.stderr.strip()}"
        return result.stdout.lower(), None
    except FileNotFoundError:
        return None, "sshd not found - OpenSSH server may not be installed"
    except subprocess.TimeoutExpired:
        return None, "sshd -T timed out"
    except Exception as e:
        return None, f"Error running sshd -T: {str(e)}"


def _get_config_value(config_output: str, key: str) -> Optional[str]:
    """Extract a configuration value from sshd -T output.

    Args:
        config_output: The full output from sshd -T (lowercase).
        key: The configuration key to search for (will be lowercased).

    Returns:
        The value if found, None otherwise.
    """
    key = key.lower()
    for line in config_output.splitlines():
        line = line.strip()
        if line.startswith(key + " "):
            return line.split(None, 1)[1] if " " in line else ""
    return None


def _check_password_auth(config_output: str) -> CheckResult:
    """Check if password authentication is disabled."""
    value = _get_config_value(config_output, "passwordauthentication")

    if value == "no":
        return CheckResult(
            check="ssh_password_auth",
            status=CheckStatus.PASS,
            severity="critical",
            message="Password authentication is disabled (key-based only)",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="ssh_password_auth",
            status=CheckStatus.FAIL,
            severity="critical",
            message=f"Password authentication is enabled (current: {value}). Should be disabled for security.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )


def _check_root_login(config_output: str) -> CheckResult:
    """Check if root login is properly restricted.

    Note: 'without-password' and 'prohibit-password' are equivalent in OpenSSH.
    'without-password' is the legacy name, 'prohibit-password' is the modern name.
    OpenSSH reports 'without-password' in sshd -T output even if config uses 'prohibit-password'.
    """
    value = _get_config_value(config_output, "permitrootlogin")

    # 'without-password' and 'prohibit-password' are equivalent - both allow key-only root login
    if value in ("no", "prohibit-password", "without-password"):
        return CheckResult(
            check="ssh_root_login",
            status=CheckStatus.PASS,
            severity="critical",
            message=f"Root login is properly restricted (permitrootlogin={value})",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="ssh_root_login",
            status=CheckStatus.FAIL,
            severity="critical",
            message=f"Root login is not properly restricted (current: {value}). Should be 'no' or 'prohibit-password'.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )


def _check_empty_passwords(config_output: str) -> CheckResult:
    """Check if empty passwords are prohibited."""
    value = _get_config_value(config_output, "permitemptypasswords")

    if value == "no":
        return CheckResult(
            check="ssh_empty_passwords",
            status=CheckStatus.PASS,
            severity="high",
            message="Empty passwords are not permitted",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="ssh_empty_passwords",
            status=CheckStatus.FAIL,
            severity="high",
            message=f"Empty passwords may be permitted (current: {value}). Should be 'no'.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )


def _check_max_auth_tries(config_output: str) -> CheckResult:
    """Check if MaxAuthTries is reasonably low."""
    value = _get_config_value(config_output, "maxauthtries")

    try:
        max_tries = int(value) if value else 6  # OpenSSH default is 6
    except ValueError:
        max_tries = 6

    if max_tries <= 3:
        return CheckResult(
            check="ssh_max_auth_tries",
            status=CheckStatus.PASS,
            severity="high",
            message=f"MaxAuthTries is set to {max_tries} (recommended: <= 3)",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="ssh_max_auth_tries",
            status=CheckStatus.WARN,
            severity="high",
            message=f"MaxAuthTries is set to {max_tries}. Consider reducing to 3 or less.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )


def _check_login_grace_time(config_output: str) -> CheckResult:
    """Check if LoginGraceTime is reasonably short."""
    value = _get_config_value(config_output, "logingracetime")

    try:
        # Value could be in seconds or have a suffix like 30s, 1m, etc.
        if value:
            if value.endswith("m"):
                grace_time = int(value[:-1]) * 60
            elif value.endswith("s"):
                grace_time = int(value[:-1])
            else:
                grace_time = int(value)
        else:
            grace_time = 120  # OpenSSH default
    except ValueError:
        grace_time = 120

    if grace_time <= 60:
        return CheckResult(
            check="ssh_login_grace_time",
            status=CheckStatus.PASS,
            severity="high",
            message=f"LoginGraceTime is set to {grace_time}s (recommended: <= 60s)",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="ssh_login_grace_time",
            status=CheckStatus.WARN,
            severity="high",
            message=f"LoginGraceTime is set to {grace_time}s. Consider reducing to 60s or less.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )


def _check_x11_forwarding(config_output: str) -> CheckResult:
    """Check if X11 forwarding is disabled."""
    value = _get_config_value(config_output, "x11forwarding")

    if value == "no":
        return CheckResult(
            check="ssh_x11_forwarding",
            status=CheckStatus.PASS,
            severity="high",
            message="X11 forwarding is disabled",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="ssh_x11_forwarding",
            status=CheckStatus.WARN,
            severity="high",
            message=f"X11 forwarding is enabled (current: {value}). Disable unless required.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )


def _check_protocol_version(config_output: str) -> CheckResult:
    """Check SSH protocol version.

    Note: Modern OpenSSH (7.0+) only supports protocol version 2.
    The 'protocol' directive is deprecated and not present in modern sshd -T output.
    This check verifies that the system is using a modern OpenSSH version.
    """
    # In modern OpenSSH, protocol directive doesn't exist (only v2 is supported)
    # If we can run sshd -T successfully, we're on a modern version
    value = _get_config_value(config_output, "protocol")

    if value is None:
        # Modern OpenSSH - protocol directive doesn't exist, only v2 is supported
        return CheckResult(
            check="ssh_protocol_version",
            status=CheckStatus.PASS,
            severity="high",
            message="SSH protocol version 2 only (modern OpenSSH)",
            fix_available=False,
            fix_agent=None,
        )
    elif value == "2":
        return CheckResult(
            check="ssh_protocol_version",
            status=CheckStatus.PASS,
            severity="high",
            message="SSH protocol version 2 only",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="ssh_protocol_version",
            status=CheckStatus.FAIL,
            severity="high",
            message=f"Insecure SSH protocol version detected (current: {value}). Use version 2 only.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )


def _check_weak_ciphers(config_output: str) -> CheckResult:
    """Check for weak ciphers, particularly CBC mode ciphers (Terrapin CVE-2023-48795)."""
    ciphers_value = _get_config_value(config_output, "ciphers")

    if not ciphers_value:
        return CheckResult(
            check="ssh_weak_ciphers",
            status=CheckStatus.WARN,
            severity="high",
            message="Could not determine configured ciphers",
            fix_available=False,
            fix_agent=None,
        )

    ciphers = [c.strip() for c in ciphers_value.split(",")]
    weak_ciphers = [c for c in ciphers if "-cbc" in c.lower()]

    if not weak_ciphers:
        return CheckResult(
            check="ssh_weak_ciphers",
            status=CheckStatus.PASS,
            severity="high",
            message="No weak CBC ciphers enabled (Terrapin CVE-2023-48795 mitigated)",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="ssh_weak_ciphers",
            status=CheckStatus.FAIL,
            severity="high",
            message=f"Weak CBC ciphers detected: {', '.join(weak_ciphers)}. These are vulnerable to Terrapin attack (CVE-2023-48795).",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )


def run_ssh_checks() -> list[CheckResult]:
    """Run all SSH security checks.

    Returns:
        List of CheckResult objects for each SSH security check.
    """
    results: list[CheckResult] = []

    # Get SSH configuration
    config_output, error = _run_sshd_config()

    if error:
        # Return a warning result if we can't read SSH config
        return [
            CheckResult(
                check="ssh_config_read",
                status=CheckStatus.WARN,
                severity="high",
                message=f"Could not read SSH configuration: {error}",
                fix_available=False,
                fix_agent=None,
            )
        ]

    # Run all individual checks
    results.append(_check_password_auth(config_output))
    results.append(_check_root_login(config_output))
    results.append(_check_empty_passwords(config_output))
    results.append(_check_max_auth_tries(config_output))
    results.append(_check_login_grace_time(config_output))
    results.append(_check_x11_forwarding(config_output))
    results.append(_check_protocol_version(config_output))
    results.append(_check_weak_ciphers(config_output))

    return results
