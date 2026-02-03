"""Filesystem security checks for VPS auditing."""

import os
import stat
import subprocess
from typing import Optional

from ..models import CheckResult, CheckStatus


# Expected locations for SUID binaries (common legitimate paths)
EXPECTED_SUID_PATHS = {
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/lib/openssh",
    "/usr/lib/dbus-1.0",
    "/usr/lib/polkit-1",
    "/usr/lib/snapd",
    "/snap",
}

# Known legitimate SUID binaries
KNOWN_SUID_BINARIES = {
    "su",
    "sudo",
    "passwd",
    "chsh",
    "chfn",
    "newgrp",
    "gpasswd",
    "mount",
    "umount",
    "ping",
    "ping6",
    "fusermount",
    "fusermount3",
    "pkexec",
    "dbus-daemon-launch-helper",
    "ssh-keysign",
    "at",
    "crontab",
    "wall",
    "write",
    "expiry",
    "chage",
    "unix_chkpwd",
    "pam_timestamp_check",
    "staprun",
}


def _get_file_mode(path: str) -> tuple[Optional[int], Optional[str]]:
    """Get the permission mode of a file.

    Returns:
        Tuple of (mode, error). If successful, error is None.
        If failed, mode is None and error contains the error message.
    """
    try:
        file_stat = os.stat(path)
        return file_stat.st_mode, None
    except FileNotFoundError:
        return None, f"File not found: {path}"
    except PermissionError:
        return None, f"Permission denied: {path}"
    except Exception as e:
        return None, f"Error checking {path}: {str(e)}"


def _check_shadow_permissions() -> CheckResult:
    """Check if /etc/shadow has secure permissions (640 or stricter)."""
    shadow_path = "/etc/shadow"
    mode, error = _get_file_mode(shadow_path)

    if error:
        return CheckResult(
            check="fs_shadow_permissions",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not check shadow file permissions: {error}",
            fix_available=False,
            fix_agent=None,
        )

    # Extract permission bits (last 9 bits)
    perms = mode & 0o777

    # Acceptable modes: 600, 400, 640 (or stricter)
    # World-readable (o+r) or world-writable (o+w) is bad
    # Group-writable (g+w) is also bad
    world_read = perms & stat.S_IROTH
    world_write = perms & stat.S_IWOTH
    group_write = perms & stat.S_IWGRP

    if world_read or world_write or group_write:
        return CheckResult(
            check="fs_shadow_permissions",
            status=CheckStatus.FAIL,
            severity="high",
            message=f"/etc/shadow has insecure permissions ({oct(perms)}). Should be 640 or stricter (600, 400).",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )

    # Check if permissions are 640 or stricter
    if perms <= 0o640:
        return CheckResult(
            check="fs_shadow_permissions",
            status=CheckStatus.PASS,
            severity="high",
            message=f"/etc/shadow has secure permissions ({oct(perms)})",
            fix_available=False,
            fix_agent=None,
        )
    else:
        return CheckResult(
            check="fs_shadow_permissions",
            status=CheckStatus.FAIL,
            severity="high",
            message=f"/etc/shadow has insecure permissions ({oct(perms)}). Should be 640 or stricter.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )


def _check_sshd_config_permissions() -> CheckResult:
    """Check if /etc/ssh/sshd_config is not world-readable."""
    sshd_config_path = "/etc/ssh/sshd_config"
    mode, error = _get_file_mode(sshd_config_path)

    if error:
        return CheckResult(
            check="fs_sshd_config_permissions",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not check sshd_config permissions: {error}",
            fix_available=False,
            fix_agent=None,
        )

    # Extract permission bits
    perms = mode & 0o777

    # Check for world-readable bit
    world_read = perms & stat.S_IROTH

    if world_read:
        return CheckResult(
            check="fs_sshd_config_permissions",
            status=CheckStatus.FAIL,
            severity="high",
            message=f"/etc/ssh/sshd_config is world-readable ({oct(perms)}). Remove world-read permission.",
            fix_available=True,
            fix_agent="joe/vps-fixer",
        )
    else:
        return CheckResult(
            check="fs_sshd_config_permissions",
            status=CheckStatus.PASS,
            severity="high",
            message=f"/etc/ssh/sshd_config is not world-readable ({oct(perms)})",
            fix_available=False,
            fix_agent=None,
        )


def _check_world_writable_etc() -> CheckResult:
    """Check for world-writable files in /etc."""
    try:
        result = subprocess.run(
            ["find", "/etc", "-type", "f", "-perm", "-002"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Get list of world-writable files
        world_writable_files = [
            f.strip() for f in result.stdout.strip().split("\n") if f.strip()
        ]

        if not world_writable_files:
            return CheckResult(
                check="fs_world_writable_etc",
                status=CheckStatus.PASS,
                severity="medium",
                message="No world-writable files found in /etc",
                fix_available=False,
                fix_agent=None,
            )
        else:
            # Limit the number of files shown in message
            files_preview = world_writable_files[:5]
            more_count = len(world_writable_files) - 5 if len(world_writable_files) > 5 else 0
            files_str = ", ".join(files_preview)
            if more_count > 0:
                files_str += f" (and {more_count} more)"

            return CheckResult(
                check="fs_world_writable_etc",
                status=CheckStatus.FAIL,
                severity="medium",
                message=f"World-writable files found in /etc: {files_str}",
                fix_available=True,
                fix_agent="joe/vps-fixer",
            )

    except FileNotFoundError:
        return CheckResult(
            check="fs_world_writable_etc",
            status=CheckStatus.WARN,
            severity="medium",
            message="Could not check for world-writable files: 'find' command not found",
            fix_available=False,
            fix_agent=None,
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            check="fs_world_writable_etc",
            status=CheckStatus.WARN,
            severity="medium",
            message="World-writable file check timed out",
            fix_available=False,
            fix_agent=None,
        )
    except PermissionError:
        return CheckResult(
            check="fs_world_writable_etc",
            status=CheckStatus.WARN,
            severity="medium",
            message="Permission denied while checking for world-writable files in /etc",
            fix_available=False,
            fix_agent=None,
        )
    except Exception as e:
        return CheckResult(
            check="fs_world_writable_etc",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Error checking world-writable files: {str(e)}",
            fix_available=False,
            fix_agent=None,
        )


def _is_in_expected_path(filepath: str) -> bool:
    """Check if a file is in an expected SUID binary location."""
    for expected_path in EXPECTED_SUID_PATHS:
        if filepath.startswith(expected_path + "/"):
            return True
    return False


def _check_suspicious_suid() -> CheckResult:
    """Check for SUID binaries outside expected locations."""
    try:
        # Find all SUID files on the system
        result = subprocess.run(
            ["find", "/", "-type", "f", "-perm", "-4000", "-xdev"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        suid_files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]

        suspicious_files = []
        for suid_file in suid_files:
            # Check if file is in an expected location
            if not _is_in_expected_path(suid_file):
                suspicious_files.append(suid_file)
            else:
                # Even in expected location, check if it's a known binary
                basename = os.path.basename(suid_file)
                if basename not in KNOWN_SUID_BINARIES:
                    # Not a known binary - could be suspicious
                    # But don't flag it as high priority since it's in an expected location
                    pass

        if not suspicious_files:
            return CheckResult(
                check="fs_suspicious_suid",
                status=CheckStatus.PASS,
                severity="medium",
                message="No SUID binaries found outside expected locations",
                fix_available=False,
                fix_agent=None,
            )
        else:
            # Limit the number of files shown
            files_preview = suspicious_files[:5]
            more_count = len(suspicious_files) - 5 if len(suspicious_files) > 5 else 0
            files_str = ", ".join(files_preview)
            if more_count > 0:
                files_str += f" (and {more_count} more)"

            return CheckResult(
                check="fs_suspicious_suid",
                status=CheckStatus.WARN,
                severity="medium",
                message=f"SUID binaries found outside expected locations: {files_str}",
                fix_available=False,
                fix_agent=None,
            )

    except FileNotFoundError:
        return CheckResult(
            check="fs_suspicious_suid",
            status=CheckStatus.WARN,
            severity="medium",
            message="Could not check for SUID files: 'find' command not found",
            fix_available=False,
            fix_agent=None,
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            check="fs_suspicious_suid",
            status=CheckStatus.WARN,
            severity="medium",
            message="SUID file check timed out",
            fix_available=False,
            fix_agent=None,
        )
    except PermissionError:
        return CheckResult(
            check="fs_suspicious_suid",
            status=CheckStatus.WARN,
            severity="medium",
            message="Permission denied while checking for SUID files",
            fix_available=False,
            fix_agent=None,
        )
    except Exception as e:
        return CheckResult(
            check="fs_suspicious_suid",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Error checking SUID files: {str(e)}",
            fix_available=False,
            fix_agent=None,
        )


def run_filesystem_checks() -> list[CheckResult]:
    """Run all filesystem security checks.

    Returns:
        List of CheckResult objects for each filesystem security check.
    """
    results: list[CheckResult] = []

    # Run all individual checks
    results.append(_check_shadow_permissions())
    results.append(_check_sshd_config_permissions())
    results.append(_check_world_writable_etc())
    results.append(_check_suspicious_suid())

    return results
