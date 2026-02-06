"""SSH Tailscale restriction fix module.

Restricts SSH access to the Tailscale VPN interface only, removing SSH from
the public internet. Requires Tailscale to already be installed and running.
"""

import subprocess
from typing import Optional

from ..models import FixAction, FixResult, FixType


def _run_command(cmd: list[str], timeout: int = 30) -> tuple[Optional[str], Optional[str]]:
    """Run a shell command and return stdout and error."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return None, result.stderr.strip() or f"Command failed with code {result.returncode}"
        return result.stdout, None
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, "Command timed out"
    except Exception as e:
        return None, f"Error running command: {str(e)}"


def _is_tailscale_running() -> bool:
    """Check if Tailscale is installed and running."""
    output, error = _run_command(["tailscale", "status"])
    return error is None and output is not None


def _get_ufw_ssh_rule_numbers() -> list[int]:
    """Get UFW rule numbers for SSH rules that are open to Anywhere."""
    output, error = _run_command(["ufw", "status", "numbered"])
    if error or not output:
        return []

    rule_numbers = []
    for line in output.strip().splitlines():
        line_lower = line.lower()
        # Look for SSH rules open to Anywhere
        if "22" in line_lower and "allow" in line_lower and "anywhere" in line_lower:
            # Extract rule number from format like "[ 1] 22/tcp ALLOW IN Anywhere"
            try:
                num_str = line.split("]")[0].split("[")[1].strip()
                rule_numbers.append(int(num_str))
            except (IndexError, ValueError):
                continue

    # Return in reverse order so we can delete from highest to lowest
    # (deleting changes rule numbers)
    return sorted(rule_numbers, reverse=True)


def get_ssh_tailscale_fix_actions() -> list[FixAction]:
    """Get actions to restrict SSH to Tailscale interface only.

    Returns:
        List of FixAction objects describing the planned actions.
    """
    actions = []

    # Action 1: Verify Tailscale is running
    actions.append(
        FixAction(
            fix_type=FixType.SSH_TAILSCALE,
            description="Verify Tailscale VPN is installed and running",
            commands=["tailscale status"],
            backup_files=[],
            rollback_commands=[],
        )
    )

    # Action 2: Add SSH allow on tailscale0 interface
    actions.append(
        FixAction(
            fix_type=FixType.SSH_TAILSCALE,
            description="Allow SSH connections on Tailscale interface only",
            commands=["ufw allow in on tailscale0 to any port 22 proto tcp"],
            backup_files=[],
            rollback_commands=["ufw delete allow in on tailscale0 to any port 22 proto tcp"],
        )
    )

    # Action 3: Remove SSH rules open to Anywhere
    actions.append(
        FixAction(
            fix_type=FixType.SSH_TAILSCALE,
            description="Remove SSH rules that are open to the entire internet (Anywhere)",
            commands=[
                "ufw delete allow 22/tcp",
                "ufw delete allow 22",
                "(removes all Anywhere SSH rules)",
            ],
            backup_files=[],
            rollback_commands=["ufw allow 22/tcp"],
        )
    )

    return actions


def apply_ssh_tailscale_fix() -> FixResult:
    """Restrict SSH to Tailscale interface only.

    1. Verifies Tailscale is running
    2. Adds UFW rule: allow SSH on tailscale0 interface
    3. Removes UFW rules that allow SSH from Anywhere

    IMPORTANT: This will lock you out if Tailscale is not properly configured!

    Returns:
        FixResult indicating success or failure.
    """
    output_lines: list[str] = []

    # Step 1: Verify Tailscale is running
    if not _is_tailscale_running():
        return FixResult(
            fix_type=FixType.SSH_TAILSCALE,
            success=False,
            message="Tailscale is not installed or not running. Install and configure Tailscale "
                    "first: curl -fsSL https://tailscale.com/install.sh | sh && tailscale up",
            output="Tailscale not available",
            applied=False,
            backup_path=None,
        )
    output_lines.append("Tailscale is running")

    # Step 2: Verify the tailscale0 interface exists
    ts_output, ts_error = _run_command(["tailscale", "ip", "-4"])
    if ts_error:
        return FixResult(
            fix_type=FixType.SSH_TAILSCALE,
            success=False,
            message=f"Could not get Tailscale IP: {ts_error}. Ensure Tailscale is connected.",
            output=ts_error,
            applied=False,
            backup_path=None,
        )
    tailscale_ip = ts_output.strip() if ts_output else "unknown"
    output_lines.append(f"Tailscale IP: {tailscale_ip}")

    # Step 3: Add SSH allow on tailscale0 interface FIRST (before removing open rules)
    output, error = _run_command(["ufw", "allow", "in", "on", "tailscale0", "to", "any", "port", "22", "proto", "tcp"])
    if error:
        return FixResult(
            fix_type=FixType.SSH_TAILSCALE,
            success=False,
            message=f"Failed to add Tailscale SSH rule: {error}",
            output="\n".join(output_lines) + f"\nError: {error}",
            applied=False,
            backup_path=None,
        )
    output_lines.append(f"Added SSH rule on tailscale0: {output.strip() if output else 'OK'}")

    # Step 4: Remove SSH rules open to Anywhere
    rule_numbers = _get_ufw_ssh_rule_numbers()
    if rule_numbers:
        for rule_num in rule_numbers:
            output, error = _run_command(["ufw", "--force", "delete", str(rule_num)])
            if error:
                output_lines.append(f"Warning: Failed to delete rule {rule_num}: {error}")
            else:
                output_lines.append(f"Deleted open SSH rule #{rule_num}")
    else:
        # Try deleting by rule specification as fallback
        for rule in ["22/tcp", "22"]:
            output, error = _run_command(["ufw", "delete", "allow", rule])
            if not error:
                output_lines.append(f"Deleted rule: allow {rule}")

    # Step 5: Reload UFW
    output, error = _run_command(["ufw", "reload"])
    if error:
        output_lines.append(f"Warning: UFW reload returned: {error}")
    else:
        output_lines.append("UFW reloaded")

    return FixResult(
        fix_type=FixType.SSH_TAILSCALE,
        success=True,
        message=f"SSH restricted to Tailscale interface only (tailscale0, IP: {tailscale_ip}). "
                f"SSH from the public internet is now blocked.",
        output="\n".join(output_lines),
        applied=True,
        backup_path=None,
    )
