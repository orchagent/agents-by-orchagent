#!/usr/bin/env python3
"""Main entrypoint for vps-checker security scanner.

This script reads JSON input from stdin (ScanInput model), runs all security checks,
and outputs a ScanResult as JSON to stdout.
"""

import json
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional

# Add src directory to path for imports
sys.path.insert(0, "src")

from vps_checker.models import (
    AttackSummary,
    BreachIndicators,
    CheckResult,
    CheckStatus,
    ScanInput,
    ScanResult,
)
from vps_checker.scorer import calculate_score


def get_hostname() -> str:
    """Get the hostname of the server."""
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def get_os_info() -> str:
    """Get operating system information."""
    try:
        # Try to get detailed OS info from /etc/os-release
        try:
            with open("/etc/os-release", "r") as f:
                lines = f.readlines()
                pretty_name = None
                for line in lines:
                    if line.startswith("PRETTY_NAME="):
                        pretty_name = line.split("=", 1)[1].strip().strip('"')
                        break
                if pretty_name:
                    return pretty_name
        except FileNotFoundError:
            pass

        # Fallback to platform module
        system = platform.system()
        release = platform.release()
        return f"{system} {release}"
    except Exception:
        return "unknown"


def run_check_safely(check_name: str, check_func) -> list[CheckResult]:
    """Run a check function safely, catching any exceptions.

    Args:
        check_name: Name of the check for error reporting.
        check_func: The check function to call.

    Returns:
        List of CheckResult objects from the check, or a warning result on error.
    """
    try:
        return check_func()
    except Exception as e:
        return [
            CheckResult(
                check=check_name,
                status=CheckStatus.WARN,
                severity="medium",
                message=f"Error running {check_name}: {str(e)}",
                fix_available=False,
                fix_agent=None,
            )
        ]


def run_compromise_check_safely() -> tuple[list[CheckResult], BreachIndicators]:
    """Run compromise checks safely, catching any exceptions.

    Returns:
        Tuple of (list of CheckResult, BreachIndicators).
    """
    try:
        from vps_checker.checks.compromise import run_compromise_checks
        return run_compromise_checks()
    except Exception as e:
        return [
            CheckResult(
                check="compromise",
                status=CheckStatus.WARN,
                severity="medium",
                message=f"Error running compromise checks: {str(e)}",
                fix_available=False,
                fix_agent=None,
            )
        ], BreachIndicators()


def collect_attack_metrics_safely() -> AttackSummary:
    """Collect attack metrics safely, catching any exceptions.

    Returns:
        AttackSummary object with collected metrics, or empty summary on error.
    """
    try:
        from vps_checker.checks.attack_metrics import collect_attack_metrics
        return collect_attack_metrics()
    except Exception:
        return AttackSummary()


def generate_recommendations(
    critical_issues: list[CheckResult],
    warnings: list[CheckResult],
    breach_indicators: BreachIndicators,
) -> list[str]:
    """Generate prioritized recommendations based on scan findings.

    Args:
        critical_issues: List of critical/failed check results.
        warnings: List of warning check results.
        breach_indicators: Breach indicator findings.

    Returns:
        List of recommendation strings, ordered by priority.
    """
    recommendations: list[str] = []

    # Highest priority: breach indicators
    if breach_indicators.found:
        if breach_indicators.unknown_processes:
            recommendations.append(
                "URGENT: Potential malicious processes detected. Investigate immediately and consider isolating the server."
            )
        if breach_indicators.suspicious_files:
            recommendations.append(
                "WARNING: Suspicious hidden files found in temp directories. Review and remove if malicious."
            )
        if breach_indicators.unknown_ssh_keys:
            recommendations.append(
                "Review SSH authorized keys and remove any unrecognized keys to prevent unauthorized access."
            )

    # Critical issues with fixes
    fixable_critical = [issue for issue in critical_issues if issue.fix_available]
    if fixable_critical:
        # Group by fix agent
        recommendations.append(
            f"Found {len(fixable_critical)} critical issue(s) that can be auto-fixed. Consider running vps-fixer to remediate."
        )

    # Specific recommendations based on common critical issues
    check_names = {issue.check for issue in critical_issues}

    if "fail2ban_installed" in check_names or "fail2ban_service" in check_names:
        recommendations.append(
            "Install and enable fail2ban to protect against brute-force attacks: apt install fail2ban && systemctl enable --now fail2ban"
        )

    if "firewall_ufw_status" in check_names:
        recommendations.append(
            "Enable UFW firewall to protect against unauthorized access: ufw allow ssh && ufw enable"
        )

    if "ssh_password_auth" in check_names:
        recommendations.append(
            "Disable SSH password authentication and use key-based authentication only for improved security."
        )

    if "ssh_root_login" in check_names:
        recommendations.append(
            "Restrict root login via SSH. Set 'PermitRootLogin no' or 'prohibit-password' in sshd_config."
        )

    if "users_empty_passwords" in check_names:
        recommendations.append(
            "CRITICAL: Set passwords for all user accounts immediately to prevent unauthorized access."
        )

    if "users_multiple_uid_zero" in check_names:
        recommendations.append(
            "CRITICAL: Investigate non-root accounts with UID 0. This may indicate system compromise."
        )

    if "firewall_ssh_internet_exposed" in check_names:
        recommendations.append(
            "CRITICAL: SSH is open to the entire internet. Install Tailscale and restrict SSH to "
            "Tailscale interface only: ufw allow in on tailscale0 to any port 22, then delete "
            "the 'ufw allow 22' rules that are open to Anywhere."
        )

    # Warning-level recommendations
    warning_check_names = {issue.check for issue in warnings}

    if "auto_updates" in warning_check_names:
        recommendations.append(
            "Enable automatic security updates to ensure timely patching of vulnerabilities."
        )

    if "firewall_ssh_rate_limit" in warning_check_names:
        recommendations.append(
            "Consider enabling SSH rate limiting with UFW: ufw limit ssh"
        )

    if "tailscale_installed" in warning_check_names:
        recommendations.append(
            "Install Tailscale VPN to enable secure SSH access without exposing port 22 to the "
            "internet. See: https://tailscale.com/download/linux"
        )

    if "auto_reboot" in warning_check_names:
        recommendations.append(
            "Enable automatic reboot for unattended-upgrades so kernel security patches take "
            "effect without manual intervention."
        )

    if "firewall_web_port_cloudflare" in warning_check_names:
        recommendations.append(
            "Restrict web ports (80/443) to Cloudflare IP ranges only to prevent origin IP "
            "bypass attacks. See: https://www.cloudflare.com/ips/"
        )

    # Deduplicate while preserving order
    seen = set()
    unique_recommendations = []
    for rec in recommendations:
        if rec not in seen:
            seen.add(rec)
            unique_recommendations.append(rec)

    return unique_recommendations[:10]  # Limit to top 10 recommendations


def main() -> int:
    """Main entry point for the VPS checker.

    Reads ScanInput from stdin, runs all security checks, and outputs ScanResult to stdout.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    # Read input from stdin
    try:
        input_data = sys.stdin.read()
        if input_data.strip():
            scan_input = ScanInput.model_validate_json(input_data)
        else:
            # Default input if none provided
            scan_input = ScanInput()
    except Exception as e:
        error_result = {
            "error": f"Failed to parse input: {str(e)}",
            "expected_format": {
                "dry_run": True,
                "skip_attack_metrics": False,
            }
        }
        print(json.dumps(error_result), file=sys.stdout)
        return 1

    # Collect system info
    hostname = get_hostname()
    os_info = get_os_info()
    scan_time = datetime.now(timezone.utc)

    # Run all security checks
    all_results: list[CheckResult] = []

    # Import check modules
    try:
        from vps_checker.checks.ssh import run_ssh_checks
        all_results.extend(run_check_safely("ssh", run_ssh_checks))
    except ImportError as e:
        all_results.append(CheckResult(
            check="ssh_import",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not import SSH checks: {str(e)}",
            fix_available=False,
            fix_agent=None,
        ))

    try:
        from vps_checker.checks.firewall import run_firewall_checks
        all_results.extend(run_check_safely("firewall", run_firewall_checks))
    except ImportError as e:
        all_results.append(CheckResult(
            check="firewall_import",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not import firewall checks: {str(e)}",
            fix_available=False,
            fix_agent=None,
        ))

    try:
        from vps_checker.checks.fail2ban import run_fail2ban_checks
        all_results.extend(run_check_safely("fail2ban", run_fail2ban_checks))
    except ImportError as e:
        all_results.append(CheckResult(
            check="fail2ban_import",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not import fail2ban checks: {str(e)}",
            fix_available=False,
            fix_agent=None,
        ))

    try:
        from vps_checker.checks.kernel import run_kernel_checks
        all_results.extend(run_check_safely("kernel", run_kernel_checks))
    except ImportError as e:
        all_results.append(CheckResult(
            check="kernel_import",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not import kernel checks: {str(e)}",
            fix_available=False,
            fix_agent=None,
        ))

    try:
        from vps_checker.checks.filesystem import run_filesystem_checks
        all_results.extend(run_check_safely("filesystem", run_filesystem_checks))
    except ImportError as e:
        all_results.append(CheckResult(
            check="filesystem_import",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not import filesystem checks: {str(e)}",
            fix_available=False,
            fix_agent=None,
        ))

    try:
        from vps_checker.checks.users import run_user_checks
        all_results.extend(run_check_safely("users", run_user_checks))
    except ImportError as e:
        all_results.append(CheckResult(
            check="users_import",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not import user checks: {str(e)}",
            fix_available=False,
            fix_agent=None,
        ))

    try:
        from vps_checker.checks.services import run_services_checks
        all_results.extend(run_check_safely("services", run_services_checks))
    except ImportError as e:
        all_results.append(CheckResult(
            check="services_import",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not import services checks: {str(e)}",
            fix_available=False,
            fix_agent=None,
        ))

    # Run compromise checks (returns both results and breach indicators)
    compromise_results, breach_indicators = run_compromise_check_safely()
    all_results.extend(compromise_results)

    # Collect attack metrics if not skipped
    if scan_input.skip_attack_metrics:
        attack_summary = AttackSummary()
    else:
        attack_summary = collect_attack_metrics_safely()

    # Sort results into categories
    critical_issues: list[CheckResult] = []
    warnings: list[CheckResult] = []
    passed: list[CheckResult] = []

    for result in all_results:
        if result.status == CheckStatus.PASS:
            passed.append(result)
        elif result.status == CheckStatus.FAIL:
            critical_issues.append(result)
        elif result.status == CheckStatus.WARN:
            # Warnings with critical/high severity go to critical_issues
            if result.severity in ("critical", "high"):
                critical_issues.append(result)
            else:
                warnings.append(result)

    # Calculate security score
    security_score = calculate_score(critical_issues, warnings)

    # Generate recommendations
    recommendations = generate_recommendations(critical_issues, warnings, breach_indicators)

    # Build result
    scan_result = ScanResult(
        host=hostname,
        os=os_info,
        scan_time=scan_time,
        security_score=security_score,
        max_score=100,
        critical_issues=critical_issues,
        warnings=warnings,
        passed=passed,
        attack_summary=attack_summary,
        breach_indicators=breach_indicators,
        recommendations=recommendations,
    )

    # Output result as JSON
    print(scan_result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
