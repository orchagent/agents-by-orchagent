"""Fail2ban installation and configuration fix module."""

import os
import shutil
import subprocess
from datetime import datetime
from typing import Optional

from ..models import FixAction, FixResult, FixType


JAIL_LOCAL_PATH = "/etc/fail2ban/jail.local"
JAIL_LOCAL_CONTENT = """[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
"""


def get_fail2ban_fix_actions() -> list[FixAction]:
    """Return the list of actions that will be taken to install and configure fail2ban.

    Returns:
        List of FixAction objects describing what will be done.
    """
    actions = [
        FixAction(
            fix_type=FixType.FAIL2BAN,
            description="Install fail2ban package",
            commands=["apt-get install -y fail2ban"],
            backup_files=[],
            rollback_commands=["apt-get remove -y fail2ban"],
        ),
        FixAction(
            fix_type=FixType.FAIL2BAN,
            description="Enable and start fail2ban service",
            commands=["systemctl enable --now fail2ban"],
            backup_files=[],
            rollback_commands=["systemctl disable --now fail2ban"],
        ),
        FixAction(
            fix_type=FixType.FAIL2BAN,
            description="Configure SSH jail in /etc/fail2ban/jail.local",
            commands=[],
            backup_files=[JAIL_LOCAL_PATH] if os.path.exists(JAIL_LOCAL_PATH) else [],
            rollback_commands=[],
        ),
        FixAction(
            fix_type=FixType.FAIL2BAN,
            description="Reload fail2ban to apply configuration",
            commands=["systemctl reload fail2ban"],
            backup_files=[],
            rollback_commands=[],
        ),
    ]
    return actions


def _is_fail2ban_installed() -> bool:
    """Check if fail2ban is already installed.

    Returns:
        True if fail2ban is installed, False otherwise.
    """
    try:
        result = subprocess.run(
            ["dpkg", "-s", "fail2ban"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def _run_command(args: list[str]) -> tuple[bool, str]:
    """Run a command and return success status and output.

    Args:
        args: Command and arguments as a list.

    Returns:
        Tuple of (success, output_or_error_message).
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return True, result.stdout
        return False, result.stderr or f"Command failed with return code {result.returncode}"
    except Exception as e:
        return False, str(e)


def _backup_file(file_path: str) -> Optional[str]:
    """Create a backup of a file if it exists.

    Args:
        file_path: Path to the file to backup.

    Returns:
        Path to the backup file, or None if no backup was needed.
    """
    if not os.path.exists(file_path):
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{file_path}.backup.{timestamp}"
    try:
        shutil.copy2(file_path, backup_path)
        return backup_path
    except Exception:
        return None


def _write_jail_local() -> tuple[bool, str, Optional[str]]:
    """Write the jail.local configuration file.

    Returns:
        Tuple of (success, message, backup_path).
    """
    backup_path = _backup_file(JAIL_LOCAL_PATH)

    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(JAIL_LOCAL_PATH), exist_ok=True)

        with open(JAIL_LOCAL_PATH, "w") as f:
            f.write(JAIL_LOCAL_CONTENT)

        return True, f"Wrote {JAIL_LOCAL_PATH}", backup_path
    except Exception as e:
        return False, f"Failed to write {JAIL_LOCAL_PATH}: {e}", backup_path


def apply_fail2ban_fix() -> FixResult:
    """Apply the fail2ban fix by installing and configuring fail2ban.

    Returns:
        FixResult indicating success or failure.
    """
    actions_taken: list[str] = []
    errors: list[str] = []
    backup_path: Optional[str] = None

    # Check if already installed
    already_installed = _is_fail2ban_installed()

    # Step 1: Install fail2ban
    if already_installed:
        actions_taken.append("fail2ban already installed, skipping installation")
    else:
        success, output = _run_command(["apt-get", "install", "-y", "fail2ban"])
        if success:
            actions_taken.append("Installed fail2ban package")
        else:
            errors.append(f"Failed to install fail2ban: {output}")
            return FixResult(
                fix_type=FixType.FAIL2BAN,
                success=False,
                message="Failed to install fail2ban",
                output=output,
                applied=True,
                backup_path=None,
            )

    # Step 2: Write jail.local configuration
    write_success, write_msg, backup_path = _write_jail_local()
    if write_success:
        actions_taken.append(write_msg)
        if backup_path:
            actions_taken.append(f"Created backup at {backup_path}")
    else:
        errors.append(write_msg)
        return FixResult(
            fix_type=FixType.FAIL2BAN,
            success=False,
            message="Failed to write jail.local configuration",
            output=write_msg,
            applied=True,
            backup_path=backup_path,
        )

    # Step 3: Enable and start fail2ban service
    success, output = _run_command(["systemctl", "enable", "--now", "fail2ban"])
    if success:
        actions_taken.append("Enabled and started fail2ban service")
    else:
        errors.append(f"Failed to enable fail2ban service: {output}")
        # Continue anyway, reload might work

    # Step 4: Reload fail2ban
    success, output = _run_command(["systemctl", "reload", "fail2ban"])
    if success:
        actions_taken.append("Reloaded fail2ban configuration")
    else:
        # Try restart if reload fails
        success, output = _run_command(["systemctl", "restart", "fail2ban"])
        if success:
            actions_taken.append("Restarted fail2ban service (reload failed)")
        else:
            errors.append(f"Failed to reload/restart fail2ban: {output}")

    # Determine overall success
    overall_success = len(errors) == 0

    return FixResult(
        fix_type=FixType.FAIL2BAN,
        success=overall_success,
        message="Successfully installed and configured fail2ban" if overall_success else "Completed with errors",
        output="\n".join(actions_taken + errors),
        applied=True,
        backup_path=backup_path,
    )
