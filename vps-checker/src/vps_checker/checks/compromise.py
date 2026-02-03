"""Compromise indicators checks for VPS auditing."""

import glob
import os
import subprocess
from typing import Optional

from ..models import BreachIndicators, CheckResult, CheckStatus


# Known crypto miner process names
MINER_PATTERNS = [
    "xmrig",
    "minerd",
    "cpuminer",
    "cryptonight",
    "stratum",
    "ethminer",
    "cgminer",
    "bfgminer",
    "ccminer",
    "nheqminer",
    "kthreaddi",  # Disguised miner
    "kworkerds",  # Disguised miner
    "ksoftirqds",  # Disguised miner
]

# Common legitimate hidden files to ignore
LEGITIMATE_HIDDEN_FILES = {
    ".X0-lock",
    ".X11-unix",
    ".font-unix",
    ".ICE-unix",
    ".XIM-unix",
}


def _run_command(cmd: list[str], timeout: int = 10) -> tuple[Optional[str], Optional[str]]:
    """Run a shell command and return output.

    Args:
        cmd: Command and arguments as a list.
        timeout: Timeout in seconds.

    Returns:
        Tuple of (stdout, error). If successful, error is None.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, None
    except subprocess.TimeoutExpired:
        return None, f"Command timed out: {' '.join(cmd)}"
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0]}"
    except Exception as e:
        return None, f"Error running command: {str(e)}"


def _find_hidden_files_in_dir(directory: str) -> list[str]:
    """Find hidden files in a directory.

    Args:
        directory: Directory path to search.

    Returns:
        List of hidden file paths found.
    """
    hidden_files = []
    try:
        if not os.path.isdir(directory):
            return []

        for root, dirs, files in os.walk(directory):
            # Check hidden files
            for f in files:
                if f.startswith(".") and f not in LEGITIMATE_HIDDEN_FILES:
                    hidden_files.append(os.path.join(root, f))
            # Check hidden directories (but don't recurse into system ones)
            for d in dirs[:]:  # Copy list to modify during iteration
                if d.startswith(".") and d not in LEGITIMATE_HIDDEN_FILES:
                    # Include the directory itself as suspicious
                    pass
    except PermissionError:
        pass
    except Exception:
        pass

    return hidden_files


def _check_hidden_files() -> tuple[CheckResult, list[str]]:
    """Check for hidden/suspicious files in temp directories.

    Returns:
        Tuple of (CheckResult, list of suspicious files found).
    """
    suspicious_files: list[str] = []

    # Check /tmp and /var/tmp for hidden files
    for temp_dir in ["/tmp", "/var/tmp"]:
        files = _find_hidden_files_in_dir(temp_dir)
        suspicious_files.extend(files)

    if suspicious_files:
        return CheckResult(
            check="hidden_files",
            status=CheckStatus.WARN,
            severity="medium",
            message=f"Found {len(suspicious_files)} hidden file(s) in temp directories: {', '.join(suspicious_files[:5])}{'...' if len(suspicious_files) > 5 else ''}",
            fix_available=False,
            fix_agent=None,
        ), suspicious_files
    else:
        return CheckResult(
            check="hidden_files",
            status=CheckStatus.PASS,
            severity="medium",
            message="No suspicious hidden files found in temp directories",
            fix_available=False,
            fix_agent=None,
        ), []


def _check_crypto_miners() -> tuple[CheckResult, list[str]]:
    """Check for crypto miner processes.

    Returns:
        Tuple of (CheckResult, list of suspicious processes found).
    """
    suspicious_processes: list[str] = []

    # Get process list using ps aux
    output, error = _run_command(["ps", "aux"])

    if error:
        return CheckResult(
            check="crypto_miners",
            status=CheckStatus.WARN,
            severity="critical",
            message=f"Could not check for crypto miners: {error}",
            fix_available=False,
            fix_agent=None,
        ), []

    if not output:
        return CheckResult(
            check="crypto_miners",
            status=CheckStatus.WARN,
            severity="critical",
            message="Could not retrieve process list",
            fix_available=False,
            fix_agent=None,
        ), []

    # Check each line for miner patterns
    for line in output.strip().split("\n"):
        line_lower = line.lower()
        for pattern in MINER_PATTERNS:
            if pattern in line_lower:
                # Skip the grep command itself if present
                if "grep" not in line_lower:
                    suspicious_processes.append(line.strip())
                break

    if suspicious_processes:
        # Extract just the command names for the message
        proc_names = []
        for proc in suspicious_processes:
            parts = proc.split()
            if len(parts) >= 11:
                proc_names.append(parts[10])  # Command column in ps aux
            else:
                proc_names.append(proc[:50])

        return CheckResult(
            check="crypto_miners",
            status=CheckStatus.FAIL,
            severity="critical",
            message=f"CRITICAL: Potential crypto miner process(es) detected: {', '.join(proc_names[:3])}{'...' if len(proc_names) > 3 else ''}",
            fix_available=False,
            fix_agent=None,
        ), suspicious_processes
    else:
        return CheckResult(
            check="crypto_miners",
            status=CheckStatus.PASS,
            severity="critical",
            message="No known crypto miner processes detected",
            fix_available=False,
            fix_agent=None,
        ), []


def _check_listening_ports() -> tuple[CheckResult, list[str]]:
    """Check for unexpected high-numbered listening ports.

    Returns:
        Tuple of (CheckResult, list of suspicious ports/processes).
    """
    suspicious_ports: list[str] = []

    # Get listening TCP ports using ss
    output, error = _run_command(["ss", "-tlnp"])

    if error:
        return CheckResult(
            check="listening_ports",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Could not check listening ports: {error}",
            fix_available=False,
            fix_agent=None,
        ), []

    if not output:
        return CheckResult(
            check="listening_ports",
            status=CheckStatus.WARN,
            severity="high",
            message="Could not retrieve listening ports information",
            fix_available=False,
            fix_agent=None,
        ), []

    # Parse ss output
    # Format: State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
    lines = output.strip().split("\n")[1:]  # Skip header

    for line in lines:
        parts = line.split()
        if len(parts) >= 4:
            local_addr = parts[3]
            # Extract port number
            if ":" in local_addr:
                port_str = local_addr.rsplit(":", 1)[-1]
                try:
                    port = int(port_str)
                    # Flag high-numbered ports (>10000) that are not common
                    if port > 10000:
                        # Get process info if available
                        proc_info = parts[-1] if len(parts) > 4 else "unknown"
                        suspicious_ports.append(f"port {port} ({proc_info})")
                except ValueError:
                    continue

    if suspicious_ports:
        return CheckResult(
            check="listening_ports",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Found {len(suspicious_ports)} high-numbered listening port(s) for review: {', '.join(suspicious_ports[:5])}{'...' if len(suspicious_ports) > 5 else ''}",
            fix_available=False,
            fix_agent=None,
        ), suspicious_ports
    else:
        return CheckResult(
            check="listening_ports",
            status=CheckStatus.PASS,
            severity="high",
            message="No suspicious high-numbered listening ports detected",
            fix_available=False,
            fix_agent=None,
        ), []


def _check_ssh_keys() -> tuple[CheckResult, list[str]]:
    """Check for SSH authorized keys that should be reviewed.

    Returns:
        Tuple of (CheckResult, list of SSH keys for review).
    """
    ssh_keys: list[str] = []

    # Check root authorized_keys
    root_keys_path = "/root/.ssh/authorized_keys"
    try:
        with open(root_keys_path, "r") as f:
            keys = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            for key in keys:
                # Extract key comment/identifier (usually last field)
                parts = key.split()
                if len(parts) >= 3:
                    key_id = f"root: {parts[-1]}"
                elif len(parts) >= 2:
                    key_id = f"root: {parts[0][:20]}..."
                else:
                    key_id = f"root: {key[:30]}..."
                ssh_keys.append(key_id)
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    except Exception:
        pass

    # Check home directories for authorized_keys
    home_dirs = glob.glob("/home/*")
    for home_dir in home_dirs:
        user = home_dir.split("/")[-1]
        auth_keys_path = f"{home_dir}/.ssh/authorized_keys"
        try:
            with open(auth_keys_path, "r") as f:
                keys = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                for key in keys:
                    parts = key.split()
                    if len(parts) >= 3:
                        key_id = f"{user}: {parts[-1]}"
                    elif len(parts) >= 2:
                        key_id = f"{user}: {parts[0][:20]}..."
                    else:
                        key_id = f"{user}: {key[:30]}..."
                    ssh_keys.append(key_id)
        except FileNotFoundError:
            continue
        except PermissionError:
            continue
        except Exception:
            continue

    if ssh_keys:
        return CheckResult(
            check="ssh_authorized_keys",
            status=CheckStatus.WARN,
            severity="high",
            message=f"Found {len(ssh_keys)} SSH authorized key(s) for manual review: {', '.join(ssh_keys[:3])}{'...' if len(ssh_keys) > 3 else ''}",
            fix_available=False,
            fix_agent=None,
        ), ssh_keys
    else:
        return CheckResult(
            check="ssh_authorized_keys",
            status=CheckStatus.PASS,
            severity="high",
            message="No SSH authorized keys found (or unable to read key files)",
            fix_available=False,
            fix_agent=None,
        ), []


def run_compromise_checks() -> tuple[list[CheckResult], BreachIndicators]:
    """Run all compromise indicator checks.

    Returns:
        Tuple of (list of CheckResult objects, BreachIndicators object).
    """
    results: list[CheckResult] = []
    breach_indicators = BreachIndicators()

    # Check for hidden/suspicious files
    hidden_result, suspicious_files = _check_hidden_files()
    results.append(hidden_result)
    if suspicious_files:
        breach_indicators.suspicious_files.extend(suspicious_files)
        breach_indicators.found = True

    # Check for crypto miner processes
    miner_result, miner_processes = _check_crypto_miners()
    results.append(miner_result)
    if miner_processes:
        breach_indicators.unknown_processes.extend(miner_processes)
        breach_indicators.found = True

    # Check for unexpected listening ports
    ports_result, suspicious_ports = _check_listening_ports()
    results.append(ports_result)
    # Note: suspicious ports don't go into breach_indicators directly
    # but they trigger investigation

    # Check SSH authorized keys
    keys_result, ssh_keys = _check_ssh_keys()
    results.append(keys_result)
    if ssh_keys:
        breach_indicators.unknown_ssh_keys.extend(ssh_keys)
        breach_indicators.found = True

    return results, breach_indicators
