"""Auto-updates fix module for enabling automatic security updates and auto-reboot."""

import os
import subprocess
from datetime import datetime
from ..models import FixAction, FixResult, FixType

UNATTENDED_UPGRADES_CONFIG = "/etc/apt/apt.conf.d/50unattended-upgrades"


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


def get_auto_reboot_fix_actions() -> list[FixAction]:
    """Return actions to enable automatic reboot for unattended-upgrades.

    Returns:
        List of FixAction objects describing the steps to enable auto-reboot.
    """
    return [
        FixAction(
            fix_type=FixType.AUTO_REBOOT,
            description="Enable automatic reboot in unattended-upgrades config so kernel "
                        "updates take effect without manual intervention",
            commands=[
                f"Modify {UNATTENDED_UPGRADES_CONFIG} to set Automatic-Reboot true and reboot time 03:00",
            ],
            backup_files=[UNATTENDED_UPGRADES_CONFIG],
            rollback_commands=[
                f"Restore {UNATTENDED_UPGRADES_CONFIG} from backup",
            ],
        ),
    ]


def apply_auto_reboot_fix() -> FixResult:
    """Enable automatic reboot in unattended-upgrades configuration.

    Uncomments/adds Automatic-Reboot "true" and sets reboot time to 03:00.

    Returns:
        FixResult indicating success or failure.
    """
    output_lines: list[str] = []

    # Read existing config
    try:
        with open(UNATTENDED_UPGRADES_CONFIG, "r") as f:
            content = f.read()
    except FileNotFoundError:
        return FixResult(
            fix_type=FixType.AUTO_REBOOT,
            success=False,
            message=f"{UNATTENDED_UPGRADES_CONFIG} not found. Install unattended-upgrades first.",
            output="Config file not found",
            applied=False,
            backup_path=None,
        )

    # Check if already enabled
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        if "Automatic-Reboot" in stripped and '"true"' in stripped.lower():
            if "Reboot-Time" not in stripped:
                return FixResult(
                    fix_type=FixType.AUTO_REBOOT,
                    success=True,
                    message="Automatic reboot is already enabled",
                    output="Already configured",
                    applied=False,
                    backup_path=None,
                )

    # Backup existing config
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{UNATTENDED_UPGRADES_CONFIG}.backup.{timestamp}"
    try:
        with open(backup_path, "w") as f:
            f.write(content)
        output_lines.append(f"Backed up config to {backup_path}")
    except Exception as e:
        return FixResult(
            fix_type=FixType.AUTO_REBOOT,
            success=False,
            message=f"Failed to create backup: {e}",
            output=str(e),
            applied=False,
            backup_path=None,
        )

    # Modify content: uncomment or add auto-reboot lines
    new_lines = []
    reboot_set = False
    reboot_time_set = False

    for line in content.splitlines():
        stripped = line.strip()

        # Uncomment Automatic-Reboot "false" -> set to "true"
        if "Automatic-Reboot" in stripped and "Reboot-Time" not in stripped and "Reboot-With" not in stripped:
            if stripped.startswith("//"):
                new_lines.append('Unattended-Upgrade::Automatic-Reboot "true";')
                reboot_set = True
                output_lines.append("Enabled Automatic-Reboot")
                continue
            elif '"false"' in stripped.lower():
                new_lines.append('Unattended-Upgrade::Automatic-Reboot "true";')
                reboot_set = True
                output_lines.append("Changed Automatic-Reboot from false to true")
                continue

        # Uncomment/set Automatic-Reboot-Time
        if "Automatic-Reboot-Time" in stripped:
            if stripped.startswith("//"):
                new_lines.append('Unattended-Upgrade::Automatic-Reboot-Time "03:00";')
                reboot_time_set = True
                output_lines.append("Set Automatic-Reboot-Time to 03:00")
                continue

        new_lines.append(line)

    # If we didn't find the lines to modify, append them
    if not reboot_set:
        new_lines.append('')
        new_lines.append('Unattended-Upgrade::Automatic-Reboot "true";')
        output_lines.append("Added Automatic-Reboot setting")

    if not reboot_time_set:
        new_lines.append('Unattended-Upgrade::Automatic-Reboot-Time "03:00";')
        output_lines.append("Added Automatic-Reboot-Time 03:00")

    # Write modified config
    try:
        with open(UNATTENDED_UPGRADES_CONFIG, "w") as f:
            f.write("\n".join(new_lines))
        output_lines.append("Config written successfully")
    except Exception as e:
        return FixResult(
            fix_type=FixType.AUTO_REBOOT,
            success=False,
            message=f"Failed to write config: {e}",
            output="\n".join(output_lines) + f"\nError: {e}",
            applied=False,
            backup_path=backup_path,
        )

    return FixResult(
        fix_type=FixType.AUTO_REBOOT,
        success=True,
        message="Automatic reboot enabled for unattended-upgrades (reboot at 03:00)",
        output="\n".join(output_lines),
        applied=True,
        backup_path=backup_path,
    )
