"""SSH hardening fix module for VPS security."""

import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..models import FixAction, FixResult, FixType

# Configuration file path for SSH hardening
SSHD_HARDENING_CONF = "/etc/ssh/sshd_config.d/90-hardening.conf"
SSHD_CONFIG_DIR = "/etc/ssh/sshd_config.d"


def _get_backup_path(file_path: str) -> str:
    """Generate a backup path with timestamp.

    Args:
        file_path: Original file path to backup.

    Returns:
        Backup path with timestamp suffix.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{file_path}.backup.{timestamp}"


def _test_sshd_config() -> tuple[bool, str]:
    """Test SSH configuration validity.

    Returns:
        Tuple of (success, output/error message).
    """
    try:
        result = subprocess.run(
            ["sshd", "-t"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return True, "SSH configuration test passed"
        return False, f"SSH configuration test failed: {result.stderr.strip()}"
    except FileNotFoundError:
        return False, "sshd not found - OpenSSH server may not be installed"
    except subprocess.TimeoutExpired:
        return False, "sshd -t timed out"
    except Exception as e:
        return False, f"Error testing SSH config: {str(e)}"


def _reload_sshd() -> tuple[bool, str]:
    """Reload SSH daemon to apply configuration changes.

    Returns:
        Tuple of (success, output/error message).
    """
    try:
        result = subprocess.run(
            ["systemctl", "reload", "sshd"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return True, "SSH daemon reloaded successfully"
        return False, f"Failed to reload SSH daemon: {result.stderr.strip()}"
    except FileNotFoundError:
        return False, "systemctl not found - systemd may not be available"
    except subprocess.TimeoutExpired:
        return False, "SSH reload timed out"
    except Exception as e:
        return False, f"Error reloading SSH: {str(e)}"


def _read_existing_config() -> Optional[str]:
    """Read existing hardening config if it exists.

    Returns:
        Content of existing config file, or None if it doesn't exist.
    """
    try:
        if os.path.exists(SSHD_HARDENING_CONF):
            with open(SSHD_HARDENING_CONF, "r") as f:
                return f.read()
    except Exception:
        pass
    return None


def _write_config(content: str) -> tuple[bool, str]:
    """Write content to the hardening config file.

    Args:
        content: Configuration content to write.

    Returns:
        Tuple of (success, message).
    """
    try:
        # Ensure the config directory exists
        os.makedirs(SSHD_CONFIG_DIR, exist_ok=True)

        with open(SSHD_HARDENING_CONF, "w") as f:
            f.write(content)
        return True, f"Wrote configuration to {SSHD_HARDENING_CONF}"
    except PermissionError:
        return False, f"Permission denied writing to {SSHD_HARDENING_CONF}"
    except Exception as e:
        return False, f"Error writing config: {str(e)}"


def _backup_config() -> tuple[bool, Optional[str], str]:
    """Backup existing hardening config if it exists.

    Returns:
        Tuple of (success, backup_path or None, message).
    """
    if not os.path.exists(SSHD_HARDENING_CONF):
        return True, None, "No existing config to backup"

    backup_path = _get_backup_path(SSHD_HARDENING_CONF)
    try:
        shutil.copy2(SSHD_HARDENING_CONF, backup_path)
        return True, backup_path, f"Backed up to {backup_path}"
    except Exception as e:
        return False, None, f"Failed to backup: {str(e)}"


def _ensure_config_line(content: str, line: str) -> str:
    """Ensure a configuration line exists in content.

    If the line's setting already exists, it will be updated.
    Otherwise, the line will be added.

    Args:
        content: Existing configuration content.
        line: Line to ensure exists (e.g., "PasswordAuthentication no").

    Returns:
        Updated configuration content.
    """
    setting = line.split()[0]
    lines = content.strip().split("\n") if content.strip() else []

    # Check if setting already exists and update it
    found = False
    for i, existing_line in enumerate(lines):
        if existing_line.strip().startswith(setting):
            lines[i] = line
            found = True
            break

    if not found:
        lines.append(line)

    return "\n".join(lines) + "\n"


# =============================================================================
# Public API: Get Fix Actions (for dry-run/preview)
# =============================================================================


def get_ssh_password_auth_fix_actions() -> list[FixAction]:
    """Get the actions needed to disable SSH password authentication.

    Returns:
        List of FixAction objects describing what will be done.
    """
    backup_files = []
    if os.path.exists(SSHD_HARDENING_CONF):
        backup_files.append(SSHD_HARDENING_CONF)

    return [
        FixAction(
            fix_type=FixType.SSH_PASSWORD_AUTH,
            description="Disable SSH password authentication to enforce key-based authentication only",
            commands=[
                f"Create/update {SSHD_HARDENING_CONF} with: PasswordAuthentication no",
                "sshd -t  # Test SSH configuration",
                "systemctl reload sshd  # Apply changes",
            ],
            backup_files=backup_files,
            rollback_commands=[
                f"Restore {SSHD_HARDENING_CONF} from backup (if exists)",
                "# Or remove PasswordAuthentication line from config",
                "systemctl reload sshd",
            ],
        )
    ]


def get_ssh_root_login_fix_actions() -> list[FixAction]:
    """Get the actions needed to disable SSH root login.

    Returns:
        List of FixAction objects describing what will be done.
    """
    backup_files = []
    if os.path.exists(SSHD_HARDENING_CONF):
        backup_files.append(SSHD_HARDENING_CONF)

    return [
        FixAction(
            fix_type=FixType.SSH_ROOT_LOGIN,
            description="Restrict SSH root login to prohibit password authentication (key-based only)",
            commands=[
                f"Create/update {SSHD_HARDENING_CONF} with: PermitRootLogin prohibit-password",
                "sshd -t  # Test SSH configuration",
                "systemctl reload sshd  # Apply changes",
            ],
            backup_files=backup_files,
            rollback_commands=[
                f"Restore {SSHD_HARDENING_CONF} from backup (if exists)",
                "# Or remove PermitRootLogin line from config",
                "systemctl reload sshd",
            ],
        )
    ]


# =============================================================================
# Public API: Apply Fixes
# =============================================================================


def apply_ssh_password_auth_fix() -> FixResult:
    """Apply the SSH password authentication fix.

    Disables password authentication by adding PasswordAuthentication no
    to /etc/ssh/sshd_config.d/90-hardening.conf.

    Returns:
        FixResult indicating success or failure.
    """
    output_lines: list[str] = []

    # Step 1: Backup existing config if present
    backup_ok, backup_path, backup_msg = _backup_config()
    output_lines.append(backup_msg)
    if not backup_ok:
        return FixResult(
            fix_type=FixType.SSH_PASSWORD_AUTH,
            success=False,
            message="Failed to backup existing configuration",
            output="\n".join(output_lines),
            applied=False,
            backup_path=None,
        )

    # Step 2: Read existing config and add/update the setting
    existing_content = _read_existing_config() or ""
    new_content = _ensure_config_line(existing_content, "PasswordAuthentication no")

    # Step 3: Write the updated config
    write_ok, write_msg = _write_config(new_content)
    output_lines.append(write_msg)
    if not write_ok:
        return FixResult(
            fix_type=FixType.SSH_PASSWORD_AUTH,
            success=False,
            message="Failed to write SSH configuration",
            output="\n".join(output_lines),
            applied=False,
            backup_path=backup_path,
        )

    # Step 4: Test the configuration
    test_ok, test_msg = _test_sshd_config()
    output_lines.append(test_msg)
    if not test_ok:
        # Restore backup if test fails
        if backup_path and os.path.exists(backup_path):
            try:
                shutil.copy2(backup_path, SSHD_HARDENING_CONF)
                output_lines.append(f"Restored backup from {backup_path}")
            except Exception as e:
                output_lines.append(f"Warning: Failed to restore backup: {e}")
        return FixResult(
            fix_type=FixType.SSH_PASSWORD_AUTH,
            success=False,
            message="SSH configuration test failed - changes rolled back",
            output="\n".join(output_lines),
            applied=False,
            backup_path=backup_path,
        )

    # Step 5: Reload SSH daemon
    reload_ok, reload_msg = _reload_sshd()
    output_lines.append(reload_msg)
    if not reload_ok:
        return FixResult(
            fix_type=FixType.SSH_PASSWORD_AUTH,
            success=False,
            message="Failed to reload SSH daemon - config written but not active",
            output="\n".join(output_lines),
            applied=True,  # Config was written, just not reloaded
            backup_path=backup_path,
        )

    return FixResult(
        fix_type=FixType.SSH_PASSWORD_AUTH,
        success=True,
        message="SSH password authentication has been disabled",
        output="\n".join(output_lines),
        applied=True,
        backup_path=backup_path,
    )


def apply_ssh_root_login_fix() -> FixResult:
    """Apply the SSH root login restriction fix.

    Restricts root login by adding PermitRootLogin prohibit-password
    to /etc/ssh/sshd_config.d/90-hardening.conf.

    Returns:
        FixResult indicating success or failure.
    """
    output_lines: list[str] = []

    # Step 1: Backup existing config if present
    backup_ok, backup_path, backup_msg = _backup_config()
    output_lines.append(backup_msg)
    if not backup_ok:
        return FixResult(
            fix_type=FixType.SSH_ROOT_LOGIN,
            success=False,
            message="Failed to backup existing configuration",
            output="\n".join(output_lines),
            applied=False,
            backup_path=None,
        )

    # Step 2: Read existing config and add/update the setting
    existing_content = _read_existing_config() or ""
    new_content = _ensure_config_line(existing_content, "PermitRootLogin prohibit-password")

    # Step 3: Write the updated config
    write_ok, write_msg = _write_config(new_content)
    output_lines.append(write_msg)
    if not write_ok:
        return FixResult(
            fix_type=FixType.SSH_ROOT_LOGIN,
            success=False,
            message="Failed to write SSH configuration",
            output="\n".join(output_lines),
            applied=False,
            backup_path=backup_path,
        )

    # Step 4: Test the configuration
    test_ok, test_msg = _test_sshd_config()
    output_lines.append(test_msg)
    if not test_ok:
        # Restore backup if test fails
        if backup_path and os.path.exists(backup_path):
            try:
                shutil.copy2(backup_path, SSHD_HARDENING_CONF)
                output_lines.append(f"Restored backup from {backup_path}")
            except Exception as e:
                output_lines.append(f"Warning: Failed to restore backup: {e}")
        return FixResult(
            fix_type=FixType.SSH_ROOT_LOGIN,
            success=False,
            message="SSH configuration test failed - changes rolled back",
            output="\n".join(output_lines),
            applied=False,
            backup_path=backup_path,
        )

    # Step 5: Reload SSH daemon
    reload_ok, reload_msg = _reload_sshd()
    output_lines.append(reload_msg)
    if not reload_ok:
        return FixResult(
            fix_type=FixType.SSH_ROOT_LOGIN,
            success=False,
            message="Failed to reload SSH daemon - config written but not active",
            output="\n".join(output_lines),
            applied=True,  # Config was written, just not reloaded
            backup_path=backup_path,
        )

    return FixResult(
        fix_type=FixType.SSH_ROOT_LOGIN,
        success=True,
        message="SSH root login has been restricted to prohibit-password",
        output="\n".join(output_lines),
        applied=True,
        backup_path=backup_path,
    )
