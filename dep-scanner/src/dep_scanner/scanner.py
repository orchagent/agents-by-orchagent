"""Unified scanner orchestration module."""

import logging
import uuid
from pathlib import Path

from .git_utils import cloned_repo
from .models import Finding, ScanResponse, ScanSummary
from .scanners.npm import detect_npm, run_npm_audit, get_npm_package_count
from .scanners.pip import detect_python_deps, run_pip_audit, get_pip_package_count

logger = logging.getLogger(__name__)


def scan_repository(
    repo_url: str,
    package_managers: list[str] | None = None,
) -> ScanResponse:
    """
    Scan a repository for dependency vulnerabilities.

    Args:
        repo_url: URL of the git repository to scan
        package_managers: Optional list of package managers to scan (auto-detect if None)

    Returns:
        ScanResponse with findings and summary
    """
    scan_id = str(uuid.uuid4())
    all_findings: list[Finding] = []
    detected_managers: list[str] = []
    total_packages = 0

    with cloned_repo(repo_url) as repo_path:
        # Determine which scanners to run
        scanners_to_run = _determine_scanners(repo_path, package_managers)

        # Run each scanner
        for manager in scanners_to_run:
            logger.info(f"Running {manager} scanner...")

            if manager == "npm":
                findings = run_npm_audit(repo_path)
                all_findings.extend(findings)
                detected_managers.append("npm")
                total_packages += get_npm_package_count(repo_path)

            elif manager == "pip":
                findings = run_pip_audit(repo_path)
                all_findings.extend(findings)
                detected_managers.append("pip")
                total_packages += get_pip_package_count(repo_path)

    # Build summary from findings
    summary = _build_summary(all_findings, total_packages)

    return ScanResponse(
        scan_id=scan_id,
        detected_managers=detected_managers,
        findings=all_findings,
        summary=summary,
    )


def _determine_scanners(
    repo_path: Path, package_managers: list[str] | None
) -> list[str]:
    """
    Determine which scanners to run based on request and repo contents.

    Args:
        repo_path: Path to the cloned repository
        package_managers: Optional list of requested package managers

    Returns:
        List of package manager names to scan
    """
    if package_managers:
        # User specified which managers to scan
        return package_managers

    # Auto-detect based on files present
    scanners = []

    if detect_npm(repo_path):
        scanners.append("npm")

    if detect_python_deps(repo_path):
        scanners.append("pip")

    return scanners


def _build_summary(findings: list[Finding], total_packages: int) -> ScanSummary:
    """
    Build a summary of findings by severity.

    Args:
        findings: List of all findings
        total_packages: Total number of packages scanned

    Returns:
        ScanSummary with counts by severity
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for finding in findings:
        severity = finding.severity.lower()
        if severity in counts:
            counts[severity] += 1

    return ScanSummary(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        total_packages_scanned=total_packages,
    )
