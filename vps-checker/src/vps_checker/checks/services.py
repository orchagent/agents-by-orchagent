"""Services security checks for VPS auditing."""

import subprocess
from typing import Optional

from ..models import CheckResult, CheckStatus


# Dangerous legacy services that should never be running
DANGEROUS_SERVICES = ["telnet", "rsh", "rlogin", "rexec"]

# Services that should typically bind to localhost, not 0.0.0.0
LOCALHOST_ONLY_SERVICES = [
    "mysql",
    "mysqld",
    "mariadb",
    "postgres",
    "postgresql",
    "redis",
    "redis-server",
    "memcached",
    "mongodb",
    "mongod",
]


def _run_command(cmd: list[str], timeout: int = 10) -> tuple[Optional[str], Optional[str]]:
    """Run a shell command and return output.

    Args:
        cmd: Command and arguments as a list.
        timeout: Timeout in seconds.

    Returns:
        Tuple of (stdout, error). If successful, error is None.
        If failed, stdout may be None and error contains the error message.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return result.stdout, result.stderr.strip() if result.stderr else None
        return result.stdout, None
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, f"Command timed out: {' '.join(cmd)}"
    except Exception as e:
        return None, f"Error running command: {str(e)}"


def _check_service_active(service: str) -> Optional[bool]:
    """Check if a systemd service is active.

    Args:
        service: The service name to check.

    Returns:
        True if active, False if inactive, None if unknown/error.
    """
    output, error = _run_command(["systemctl", "is-active", service])
    if error and "Command not found" in error:
        return None
    if output:
        return output.strip() == "active"
    return None


def _check_dangerous_services() -> CheckResult:
    """Check if any dangerous legacy services are running."""
    running_services = []

    for service in DANGEROUS_SERVICES:
        is_active = _check_service_active(service)
        if is_active is True:
            running_services.append(service)

    if running_services:
        return CheckResult(
            check="dangerous_services",
            status=CheckStatus.FAIL,
            severity="critical",
            message=f"Dangerous services running: {', '.join(running_services)}. These are insecure and should be disabled.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )
    else:
        return CheckResult(
            check="dangerous_services",
            status=CheckStatus.PASS,
            severity="critical",
            message="No dangerous legacy services (telnet, rsh, rlogin, rexec) are running",
            fix_available=False,
            fix_agent=None,
        )


def _get_listening_services() -> tuple[Optional[list[dict]], Optional[str]]:
    """Get list of listening services and their bindings.

    Returns:
        Tuple of (services_list, error). services_list is a list of dicts
        with 'address', 'port', and 'process' keys.
    """
    # Try ss first (modern), then fall back to netstat
    output, error = _run_command(["ss", "-tlnp"])

    if error and "Command not found" in error:
        # Fall back to netstat
        output, error = _run_command(["netstat", "-tlnp"])
        if error and "Command not found" in error:
            return None, "Neither ss nor netstat available"

    if not output:
        return None, error or "No output from listening services command"

    services = []
    lines = output.strip().split("\n")

    for line in lines[1:]:  # Skip header
        parts = line.split()
        if len(parts) < 4:
            continue

        # ss format: State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        # netstat format: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program
        try:
            # Handle both ss and netstat output formats
            if "ss" in output or "LISTEN" not in line:
                # ss format - Local Address:Port is typically in column 4 (index 3)
                local_addr = parts[3] if len(parts) > 3 else parts[-3]
            else:
                # netstat format
                local_addr = parts[3]

            # Parse address and port
            if "]:" in local_addr:
                # IPv6 format like [::]:22
                addr, port = local_addr.rsplit(":", 1)
                addr = addr.strip("[]")
            elif local_addr.count(":") == 1:
                # IPv4 format like 0.0.0.0:22
                addr, port = local_addr.rsplit(":", 1)
            else:
                # IPv6 without brackets or other format
                continue

            # Get process name if available
            process = ""
            for part in parts:
                if "users:" in part or "/" in part:
                    # ss format: users:(("sshd",pid=1234,fd=3))
                    # netstat format: 1234/sshd
                    if "users:" in part:
                        # Extract process name from ss format
                        if '(("' in part:
                            process = part.split('(("')[1].split('"')[0]
                    elif "/" in part:
                        # netstat format
                        process = part.split("/")[-1]
                    break

            services.append({
                "address": addr,
                "port": port,
                "process": process.lower(),
            })
        except (IndexError, ValueError):
            continue

    return services, None


def _check_service_binding() -> CheckResult:
    """Check for services bound to 0.0.0.0 that should be localhost-only."""
    services, error = _get_listening_services()

    if error:
        return CheckResult(
            check="service_binding",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Could not check service bindings: {error}",
            fix_available=False,
            fix_agent=None,
        )

    if not services:
        return CheckResult(
            check="service_binding",
            status=CheckStatus.PASS,
            severity="medium",
            message="No listening services detected",
            fix_available=False,
            fix_agent=None,
        )

    exposed_services = []
    for svc in services:
        # Check if this service should be localhost-only but is exposed
        if svc["address"] in ("0.0.0.0", "::", "*"):
            for local_svc in LOCALHOST_ONLY_SERVICES:
                if local_svc in svc["process"]:
                    exposed_services.append(f"{svc['process']}:{svc['port']}")
                    break

    if exposed_services:
        return CheckResult(
            check="service_binding",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Services bound to 0.0.0.0 that should be localhost-only: {', '.join(exposed_services)}",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )
    else:
        return CheckResult(
            check="service_binding",
            status=CheckStatus.PASS,
            severity="medium",
            message="No database/cache services exposed to all interfaces",
            fix_available=False,
            fix_agent=None,
        )


def _check_auto_updates() -> CheckResult:
    """Check if automatic security updates are enabled."""
    # Check if unattended-upgrades service is active
    is_active = _check_service_active("unattended-upgrades")

    if is_active is True:
        return CheckResult(
            check="auto_updates",
            status=CheckStatus.PASS,
            severity="medium",
            message="Automatic security updates (unattended-upgrades) are enabled",
            fix_available=False,
            fix_agent=None,
        )

    # If service is not active, check if the package is configured
    # Look for the apt configuration
    config_paths = [
        "/etc/apt/apt.conf.d/20auto-upgrades",
        "/etc/apt/apt.conf.d/50unattended-upgrades",
    ]

    for config_path in config_paths:
        try:
            with open(config_path, "r") as f:
                content = f.read()
                if 'APT::Periodic::Unattended-Upgrade "1"' in content:
                    return CheckResult(
                        check="auto_updates",
                        status=CheckStatus.PASS,
                        severity="medium",
                        message="Automatic security updates are configured in APT",
                        fix_available=False,
                        fix_agent=None,
                    )
        except (FileNotFoundError, PermissionError):
            continue

    # Also check for dnf-automatic on RHEL/CentOS systems
    dnf_active = _check_service_active("dnf-automatic.timer")
    if dnf_active is True:
        return CheckResult(
            check="auto_updates",
            status=CheckStatus.PASS,
            severity="medium",
            message="Automatic security updates (dnf-automatic) are enabled",
            fix_available=False,
            fix_agent=None,
        )

    return CheckResult(
        check="auto_updates",
        status=CheckStatus.WARN,
        severity="medium",
        message="Automatic security updates are not enabled. Consider enabling unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL/CentOS).",
        fix_available=True,
        fix_agent="orchagent/vps-fixer",
    )


def run_services_checks() -> list[CheckResult]:
    """Run all services security checks.

    Returns:
        List of CheckResult objects for each services security check.
    """
    results: list[CheckResult] = []

    # Check for dangerous legacy services
    results.append(_check_dangerous_services())

    # Check service binding (0.0.0.0 vs localhost)
    results.append(_check_service_binding())

    # Check for automatic updates
    results.append(_check_auto_updates())

    return results
