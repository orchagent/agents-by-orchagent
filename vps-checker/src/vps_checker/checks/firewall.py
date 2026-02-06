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

# Cloudflare IPv4 ranges - used to check if web ports are properly restricted
CLOUDFLARE_IPV4_PREFIXES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

# Tailscale CGNAT subnet
TAILSCALE_SUBNET = "100.64.0.0/10"

# Common web ports that should be behind Cloudflare
WEB_PORTS = {"80", "443", "3000", "8080", "8443"}


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
                fix_agent="orchagent/vps-fixer",
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
            fix_agent="orchagent/vps-fixer",
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
            fix_agent="orchagent/vps-fixer",
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
            fix_agent="orchagent/vps-fixer",
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
            fix_agent="orchagent/vps-fixer",
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
            fix_agent="orchagent/vps-fixer",
        )


def _check_ssh_internet_exposed(ufw_output: str) -> CheckResult:
    """Check if SSH port 22 is open to the entire internet (Anywhere) instead of restricted IPs.

    SSH should be restricted to a VPN subnet (e.g. Tailscale 100.64.0.0/10) or specific
    trusted IPs, not open to the entire world.
    """
    lines = ufw_output.strip().splitlines()
    ssh_open_to_anywhere = False
    ssh_restricted = False

    for line in lines:
        line_lower = line.lower()
        # Look for SSH/port 22 rules
        if "22" not in line_lower:
            continue
        if "allow" not in line_lower:
            continue

        # Check if the source is "Anywhere" (wide open) vs a specific subnet
        if "anywhere" in line_lower:
            ssh_open_to_anywhere = True
        elif "100.64.0.0/10" in line or "100." in line or "tailscale" in line_lower:
            ssh_restricted = True

    if ssh_restricted and not ssh_open_to_anywhere:
        return CheckResult(
            check="firewall_ssh_internet_exposed",
            status=CheckStatus.PASS,
            severity="high",
            message="SSH is restricted to Tailscale/specific IPs only (not open to the internet)",
            fix_available=False,
            fix_agent=None,
        )
    elif ssh_open_to_anywhere:
        return CheckResult(
            check="firewall_ssh_internet_exposed",
            status=CheckStatus.FAIL,
            severity="high",
            message="SSH (port 22) is open to the ENTIRE INTERNET. Restrict to Tailscale subnet "
                    "(100.64.0.0/10) or specific trusted IPs. Install Tailscale and use: "
                    "ufw allow in on tailscale0 to any port 22, then delete the open SSH rules.",
            fix_available=True,
            fix_agent="orchagent/vps-fixer",
        )
    else:
        return CheckResult(
            check="firewall_ssh_internet_exposed",
            status=CheckStatus.PASS,
            severity="high",
            message="SSH does not appear to be open to Anywhere",
            fix_available=False,
            fix_agent=None,
        )


def _check_web_port_cloudflare_restricted(ufw_output: str) -> list[CheckResult]:
    """Check if web-facing ports (80, 443, 3000, etc.) are restricted to Cloudflare IP ranges.

    If a web port is open to Anywhere instead of Cloudflare IPs only, attackers can bypass
    Cloudflare's WAF/DDoS protection by hitting the origin IP directly.
    """
    results = []
    lines = ufw_output.strip().splitlines()

    # Find web ports that are open to Anywhere
    ports_open_to_anywhere = set()
    ports_restricted = set()

    for line in lines:
        line_lower = line.lower()
        if "allow" not in line_lower:
            continue

        for port in WEB_PORTS:
            if port not in line:
                continue
            # Check if the source is Anywhere vs a specific subnet
            if "anywhere" in line_lower:
                ports_open_to_anywhere.add(port)
            else:
                # Check if restricted to Cloudflare-like ranges
                for cf_prefix in CLOUDFLARE_IPV4_PREFIXES:
                    prefix_start = cf_prefix.split(".")[0]
                    if prefix_start in line:
                        ports_restricted.add(port)
                        break

    # Only flag ports that are open to Anywhere and NOT also restricted
    exposed_ports = ports_open_to_anywhere - ports_restricted

    if exposed_ports:
        port_list = ", ".join(sorted(exposed_ports))
        results.append(CheckResult(
            check="firewall_web_port_cloudflare",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Web port(s) {port_list} open to the entire internet. If using Cloudflare, "
                    f"restrict to Cloudflare IP ranges only to prevent origin IP bypass. "
                    f"See: https://www.cloudflare.com/ips/",
            fix_available=False,
            fix_agent=None,
        ))
    elif ports_restricted:
        results.append(CheckResult(
            check="firewall_web_port_cloudflare",
            status=CheckStatus.PASS,
            severity="high",
            message="Web ports are restricted to specific IP ranges (not open to Anywhere)",
            fix_available=False,
            fix_agent=None,
        ))

    return results


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
    results.append(_check_ssh_internet_exposed(ufw_output))
    results.extend(_check_web_port_cloudflare_restricted(ufw_output))

    return results
