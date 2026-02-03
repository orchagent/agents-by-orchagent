"""Auto-updates fix module for enabling automatic security updates."""

import subprocess
from ..models import FixAction, FixResult, FixType


def get_auto_updates_fix_actions() -> list[FixAction]:
    """Return actions to enable automatic security updates.

    Returns:
        List of FixAction objects describing the steps to enable auto-updates.
    """
    return [
        FixAction(
            fix_type=FixType.AUTO_UPDATES,
            description="Install unattended-upgrades package for automatic security updates",
            commands=["apt-get install -y unattended-upgrades"],
            backup_files=[],
            rollback_commands=["apt-get remove -y unattended-upgrades"],
        ),
        FixAction(
            fix_type=FixType.AUTO_UPDATES,
            description="Configure unattended-upgrades with non-interactive mode",
            commands=["dpkg-reconfigure -f noninteractive unattended-upgrades"],
            backup_files=["/etc/apt/apt.conf.d/20auto-upgrades"],
            rollback_commands=[],
        ),
    ]


def apply_auto_updates_fix() -> FixResult:
    """Enable automatic security updates on the system.

    This function installs and configures the unattended-upgrades package
    to automatically apply security updates.

    Returns:
        FixResult indicating success or failure of the operation.
    """
    output_lines: list[str] = []

    # Check if unattended-upgrades is already installed
    check_result = subprocess.run(
        ["dpkg", "-l", "unattended-upgrades"],
        capture_output=True,
        text=True,
    )

    already_installed = check_result.returncode == 0 and "ii" in check_result.stdout

    if already_installed:
        output_lines.append("unattended-upgrades is already installed")
    else:
        # Install unattended-upgrades package
        output_lines.append("Installing unattended-upgrades package...")
        install_result = subprocess.run(
            ["apt-get", "install", "-y", "unattended-upgrades"],
            capture_output=True,
            text=True,
        )

        if install_result.returncode != 0:
            return FixResult(
                fix_type=FixType.AUTO_UPDATES,
                success=False,
                message="Failed to install unattended-upgrades package",
                output=install_result.stderr or install_result.stdout,
                applied=True,
                backup_path=None,
            )

        output_lines.append(install_result.stdout)
        output_lines.append("unattended-upgrades installed successfully")

    # Configure unattended-upgrades with dpkg-reconfigure
    output_lines.append("Configuring unattended-upgrades...")
    configure_result = subprocess.run(
        ["dpkg-reconfigure", "-f", "noninteractive", "unattended-upgrades"],
        capture_output=True,
        text=True,
    )

    if configure_result.returncode != 0:
        return FixResult(
            fix_type=FixType.AUTO_UPDATES,
            success=False,
            message="Failed to configure unattended-upgrades",
            output=configure_result.stderr or configure_result.stdout,
            applied=True,
            backup_path=None,
        )

    output_lines.append("unattended-upgrades configured successfully")

    return FixResult(
        fix_type=FixType.AUTO_UPDATES,
        success=True,
        message="Automatic security updates enabled successfully",
        output="\n".join(output_lines),
        applied=True,
        backup_path=None,
    )
