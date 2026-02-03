"""Kernel hardening checks for VPS auditing."""

import subprocess
from typing import Optional

from ..models import CheckResult, CheckStatus


def _run_sysctl(parameter: str) -> tuple[Optional[str], Optional[str]]:
    """Run sysctl -n to get a kernel parameter value.

    Args:
        parameter: The sysctl parameter name (e.g., 'kernel.randomize_va_space').

    Returns:
        Tuple of (value, error). If successful, error is None.
        If failed, value is None and error contains the error message.
    """
    try:
        result = subprocess.run(
            ["sysctl", "-n", parameter],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None, f"sysctl {parameter} failed: {result.stderr.strip()}"
        return result.stdout.strip(), None
    except FileNotFoundError:
        return None, "sysctl not found - may not be a Linux system"
    except subprocess.TimeoutExpired:
        return None, f"sysctl {parameter} timed out"
    except Exception as e:
        return None, f"Error running sysctl {parameter}: {str(e)}"


def _parse_int_value(value: Optional[str]) -> Optional[int]:
    """Parse a string value as an integer.

    Args:
        value: The string value to parse.

    Returns:
        The integer value if parseable, None otherwise.
    """
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _check_aslr() -> CheckResult:
    """Check if ASLR (Address Space Layout Randomization) is enabled.

    ASLR randomizes memory addresses to make exploitation harder.
    Value should be 2 for full randomization.
    """
    value, error = _run_sysctl("kernel.randomize_va_space")

    if error:
        return CheckResult(
            check="kernel_aslr",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not check ASLR: {error}",
            fix_available=False,
            fix_agent=None,
        )

    int_value = _parse_int_value(value)

    if int_value == 2:
        return CheckResult(
            check="kernel_aslr",
            status=CheckStatus.PASS,
            severity="high",
            message="ASLR is fully enabled (kernel.randomize_va_space=2)",
            fix_available=False,
            fix_agent=None,
        )
    elif int_value == 1:
        return CheckResult(
            check="kernel_aslr",
            status=CheckStatus.WARN,
            severity="high",
            message=f"ASLR is partially enabled (current: {value}). Should be 2 for full randomization.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )
    else:
        return CheckResult(
            check="kernel_aslr",
            status=CheckStatus.FAIL,
            severity="high",
            message=f"ASLR is disabled or misconfigured (current: {value}). Should be 2 for full randomization.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )


def _check_ptrace_scope() -> CheckResult:
    """Check if ptrace scope is restricted.

    Restricting ptrace prevents processes from attaching to other processes,
    which can prevent certain types of attacks.
    Value should be >= 1 (1 = restricted to parent processes only).
    """
    value, error = _run_sysctl("kernel.yama.ptrace_scope")

    if error:
        return CheckResult(
            check="kernel_ptrace_scope",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not check ptrace scope: {error}",
            fix_available=False,
            fix_agent=None,
        )

    int_value = _parse_int_value(value)

    if int_value is not None and int_value >= 1:
        return CheckResult(
            check="kernel_ptrace_scope",
            status=CheckStatus.PASS,
            severity="high",
            message=f"ptrace scope is restricted (kernel.yama.ptrace_scope={value})",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="kernel_ptrace_scope",
            status=CheckStatus.FAIL,
            severity="high",
            message=f"ptrace scope is not restricted (current: {value}). Should be >= 1 to prevent process attachment attacks.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )


def _check_syn_cookies() -> CheckResult:
    """Check if SYN cookies are enabled.

    SYN cookies protect against SYN flood attacks by not allocating resources
    until the three-way handshake is complete.
    Value should be 1 (enabled).
    """
    value, error = _run_sysctl("net.ipv4.tcp_syncookies")

    if error:
        return CheckResult(
            check="kernel_syn_cookies",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Could not check SYN cookies: {error}",
            fix_available=False,
            fix_agent=None,
        )

    int_value = _parse_int_value(value)

    if int_value == 1:
        return CheckResult(
            check="kernel_syn_cookies",
            status=CheckStatus.PASS,
            severity="medium",
            message="SYN cookies are enabled (net.ipv4.tcp_syncookies=1)",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="kernel_syn_cookies",
            status=CheckStatus.FAIL,
            severity="medium",
            message=f"SYN cookies are disabled (current: {value}). Should be 1 to protect against SYN flood attacks.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )


def _check_source_routing() -> CheckResult:
    """Check if source routing is disabled.

    Source routing allows packets to specify their own route through the network,
    which can be used for spoofing attacks.
    Value should be 0 (disabled).
    """
    value, error = _run_sysctl("net.ipv4.conf.all.accept_source_route")

    if error:
        return CheckResult(
            check="kernel_source_routing",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Could not check source routing: {error}",
            fix_available=False,
            fix_agent=None,
        )

    int_value = _parse_int_value(value)

    if int_value == 0:
        return CheckResult(
            check="kernel_source_routing",
            status=CheckStatus.PASS,
            severity="medium",
            message="Source routing is disabled (net.ipv4.conf.all.accept_source_route=0)",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="kernel_source_routing",
            status=CheckStatus.FAIL,
            severity="medium",
            message=f"Source routing is enabled (current: {value}). Should be 0 to prevent IP spoofing attacks.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )


def _check_icmp_redirects() -> CheckResult:
    """Check if ICMP redirects are disabled.

    ICMP redirects can be used to redirect traffic through a malicious router.
    Value should be 0 (disabled).
    """
    value, error = _run_sysctl("net.ipv4.conf.all.accept_redirects")

    if error:
        return CheckResult(
            check="kernel_icmp_redirects",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Could not check ICMP redirects: {error}",
            fix_available=False,
            fix_agent=None,
        )

    int_value = _parse_int_value(value)

    if int_value == 0:
        return CheckResult(
            check="kernel_icmp_redirects",
            status=CheckStatus.PASS,
            severity="medium",
            message="ICMP redirects are disabled (net.ipv4.conf.all.accept_redirects=0)",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="kernel_icmp_redirects",
            status=CheckStatus.FAIL,
            severity="medium",
            message=f"ICMP redirects are enabled (current: {value}). Should be 0 to prevent MITM attacks.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )


def run_kernel_checks() -> list[CheckResult]:
    """Run all kernel hardening security checks.

    Returns:
        List of CheckResult objects for each kernel security check.
    """
    results: list[CheckResult] = []

    # Run all individual checks
    results.append(_check_aslr())
    results.append(_check_ptrace_scope())
    results.append(_check_syn_cookies())
    results.append(_check_source_routing())
    results.append(_check_icmp_redirects())

    return results
