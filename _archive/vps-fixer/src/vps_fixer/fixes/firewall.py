"""Firewall (UFW) fix module for VPS security hardening."""

import subprocess
from typing import Optional

from ..models import FixAction, FixResult, FixType


def _run_command(cmd: list[str], timeout: int = 30) -> tuple[Optional[str], Optional[str]]:
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


def _is_ufw_active() -> bool:
    """Check if UFW firewall is currently active."""
    output, error = _run_command(["ufw", "status"])
    if error:
        return False
    return "Status: active" in output


def _is_ufw_installed() -> bool:
    """Check if UFW is installed."""
    output, error = _run_command(["which", "ufw"])
    return error is None and output is not None and output.strip() != ""


def get_firewall_fix_actions() -> list[FixAction]:
    """Get the list of actions that will be taken to fix/enable firewall.

    Returns:
        List of FixAction objects describing the planned actions.
    """
    actions = []

    # Action 1: Install UFW
    actions.append(
        FixAction(
            fix_type=FixType.FIREWALL,
            description="Install UFW firewall package",
            commands=["apt-get install -y ufw"],
            backup_files=[],
            rollback_commands=["apt-get remove -y ufw"],
        )
    )

    # Action 2: Set default deny incoming
    actions.append(
        FixAction(
            fix_type=FixType.FIREWALL,
            description="Set default policy to deny incoming connections",
            commands=["ufw default deny incoming"],
            backup_files=[],
            rollback_commands=["ufw default allow incoming"],
        )
    )

    # Action 3: Set default allow outgoing
    actions.append(
        FixAction(
            fix_type=FixType.FIREWALL,
            description="Set default policy to allow outgoing connections",
            commands=["ufw default allow outgoing"],
            backup_files=[],
            rollback_commands=["ufw default deny outgoing"],
        )
    )

    # Action 4: Allow SSH (CRITICAL - must be before enabling)
    actions.append(
        FixAction(
            fix_type=FixType.FIREWALL,
            description="Allow SSH connections on port 22 (prevents lockout)",
            commands=["ufw allow 22/tcp"],
            backup_files=[],
            rollback_commands=["ufw delete allow 22/tcp"],
        )
    )

    # Action 5: Enable UFW
    actions.append(
        FixAction(
            fix_type=FixType.FIREWALL,
            description="Enable UFW firewall",
            commands=["ufw --force enable"],
            backup_files=[],
            rollback_commands=["ufw disable"],
        )
    )

    return actions


def apply_firewall_fix() -> FixResult:
    """Apply firewall fix by installing and configuring UFW.

    IMPORTANT: Always allows SSH before enabling firewall to prevent lockout!

    Returns:
        FixResult indicating success or failure of the fix.
    """
    output_lines: list[str] = []

    # Step 1: Check if UFW is already active
    if _is_ufw_active():
        return FixResult(
            fix_type=FixType.FIREWALL,
            success=True,
            message="UFW firewall is already active and configured",
            output="UFW is already active. No changes needed.",
            applied=False,
            backup_path=None,
        )

    # Step 2: Install UFW if not installed
    if not _is_ufw_installed():
        output, error = _run_command(["apt-get", "install", "-y", "ufw"], timeout=120)
        if error:
            return FixResult(
                fix_type=FixType.FIREWALL,
                success=False,
                message=f"Failed to install UFW: {error}",
                output=error,
                applied=False,
                backup_path=None,
            )
        output_lines.append(f"Installed UFW: {output.strip() if output else 'OK'}")

    # Step 3: Set default deny incoming
    output, error = _run_command(["ufw", "default", "deny", "incoming"])
    if error:
        return FixResult(
            fix_type=FixType.FIREWALL,
            success=False,
            message=f"Failed to set default deny incoming: {error}",
            output="\n".join(output_lines) + f"\nError: {error}",
            applied=False,
            backup_path=None,
        )
    output_lines.append(f"Set default deny incoming: {output.strip() if output else 'OK'}")

    # Step 4: Set default allow outgoing
    output, error = _run_command(["ufw", "default", "allow", "outgoing"])
    if error:
        return FixResult(
            fix_type=FixType.FIREWALL,
            success=False,
            message=f"Failed to set default allow outgoing: {error}",
            output="\n".join(output_lines) + f"\nError: {error}",
            applied=False,
            backup_path=None,
        )
    output_lines.append(f"Set default allow outgoing: {output.strip() if output else 'OK'}")

    # Step 5: CRITICAL - Allow SSH before enabling firewall to prevent lockout!
    output, error = _run_command(["ufw", "allow", "22/tcp"])
    if error:
        return FixResult(
            fix_type=FixType.FIREWALL,
            success=False,
            message=f"Failed to allow SSH (port 22): {error}",
            output="\n".join(output_lines) + f"\nError: {error}",
            applied=False,
            backup_path=None,
        )
    output_lines.append(f"Allowed SSH (22/tcp): {output.strip() if output else 'OK'}")

    # Step 6: Enable UFW (using --force to skip interactive prompt)
    output, error = _run_command(["ufw", "--force", "enable"])
    if error:
        return FixResult(
            fix_type=FixType.FIREWALL,
            success=False,
            message=f"Failed to enable UFW: {error}",
            output="\n".join(output_lines) + f"\nError: {error}",
            applied=False,
            backup_path=None,
        )
    output_lines.append(f"Enabled UFW: {output.strip() if output else 'OK'}")

    # Verify UFW is now active
    if not _is_ufw_active():
        return FixResult(
            fix_type=FixType.FIREWALL,
            success=False,
            message="UFW was enabled but verification failed - firewall may not be active",
            output="\n".join(output_lines),
            applied=True,
            backup_path=None,
        )

    return FixResult(
        fix_type=FixType.FIREWALL,
        success=True,
        message="UFW firewall successfully installed, configured, and enabled",
        output="\n".join(output_lines),
        applied=True,
        backup_path=None,
    )
