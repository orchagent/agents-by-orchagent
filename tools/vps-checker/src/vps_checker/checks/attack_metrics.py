"""Attack metrics collection for VPS security auditing."""

import subprocess
from typing import Optional

from ..models import AttackSummary


def _run_command(cmd: list[str], timeout: int = 10) -> tuple[Optional[str], Optional[str]]:
    """Run a shell command and return output.

    Args:
        cmd: Command and arguments as a list.
        timeout: Command timeout in seconds.

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
        # For these metrics commands, we accept returncode 0 or output
        # Some commands may return non-zero but still have useful output
        if result.stdout.strip():
            return result.stdout.strip(), None
        if result.returncode != 0:
            return None, result.stderr.strip() if result.stderr.strip() else f"Command failed with code {result.returncode}"
        return result.stdout.strip(), None
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, f"Command timed out: {' '.join(cmd)}"
    except Exception as e:
        return None, f"Error running command: {str(e)}"


def _get_total_failed_logins() -> int:
    """Get total number of failed login attempts from lastb.

    Returns:
        Total count of failed login attempts, or 0 if unavailable.
    """
    output, error = _run_command(["lastb"])
    if output:
        lines = output.strip().splitlines()
        # Filter out empty lines and the "btmp begins" summary line
        count = 0
        for line in lines:
            line = line.strip()
            if line and not line.startswith("btmp begins"):
                count += 1
        return count
    return 0


def _get_failed_logins_24h() -> int:
    """Get failed login attempts in the last 24 hours.

    Returns:
        Count of failed logins in last 24 hours, or 0 if unavailable.
    """
    output, error = _run_command(["lastb", "-s", "-24hours"])
    if output:
        lines = output.strip().splitlines()
        # Filter out empty lines and the "btmp begins" summary line
        count = 0
        for line in lines:
            line = line.strip()
            if line and not line.startswith("btmp begins"):
                count += 1
        return count
    return 0


def _get_unique_attacker_ips() -> int:
    """Get count of unique attacker IP addresses from lastb.

    Returns:
        Count of unique attacker IPs, or 0 if unavailable.
    """
    output, error = _run_command(["lastb"])
    if output:
        ips = set()
        for line in output.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("btmp begins"):
                # lastb output format: username terminal ip/hostname date time
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[2]
                    # Only add if it looks like an IP or hostname (not empty)
                    if ip and ip != "-":
                        ips.add(ip)
        return len(ips)
    return 0


def _get_top_usernames(count: int = 5) -> list[str]:
    """Get the most commonly targeted usernames in failed login attempts.

    Args:
        count: Number of top usernames to return.

    Returns:
        List of most targeted usernames, or empty list if unavailable.
    """
    output, error = _run_command(["lastb"])
    if output:
        username_counts: dict[str, int] = {}
        for line in output.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("btmp begins"):
                # lastb output format: username terminal ip/hostname date time
                parts = line.split()
                if len(parts) >= 1:
                    username = parts[0]
                    if username:
                        username_counts[username] = username_counts.get(username, 0) + 1

        # Sort by count descending and return top N usernames
        sorted_usernames = sorted(username_counts.items(), key=lambda x: x[1], reverse=True)
        return [username for username, _ in sorted_usernames[:count]]
    return []


def _get_currently_banned() -> int:
    """Get count of currently banned IPs from fail2ban.

    Returns:
        Number of currently banned IPs, or 0 if fail2ban is not running or unavailable.
    """
    output, error = _run_command(["fail2ban-client", "status", "sshd"])
    if output:
        # Parse output to find banned count
        # Output format includes: "Currently banned:   X"
        for line in output.splitlines():
            line = line.strip()
            if "currently banned" in line.lower():
                try:
                    # Extract number from "Currently banned:   X"
                    parts = line.split(":")
                    if len(parts) >= 2:
                        return int(parts[1].strip())
                except (ValueError, IndexError):
                    pass
    return 0


def collect_attack_metrics() -> AttackSummary:
    """Collect attack metrics from system logs and security tools.

    This function gathers information about failed login attempts,
    attacker IPs, and banned IPs from lastb and fail2ban.

    Returns:
        AttackSummary object containing collected metrics.
        All fields default to 0/empty if data is unavailable.
    """
    return AttackSummary(
        failed_logins_total=_get_total_failed_logins(),
        failed_logins_24h=_get_failed_logins_24h(),
        unique_attacker_ips=_get_unique_attacker_ips(),
        top_usernames=_get_top_usernames(5),
        currently_banned=_get_currently_banned(),
    )
