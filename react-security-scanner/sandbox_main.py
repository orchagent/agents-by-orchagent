#!/usr/bin/env python3
"""
Sandbox entrypoint for react-security-scanner.
Reads scan parameters from stdin JSON, performs security scanning, outputs JSON to stdout.
"""

import asyncio
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent / "src"))

from git.exc import GitCommandError

from orchagent import AgentClient
from react_security_scanner.git_utils import cloned_repo
from react_security_scanner.models import (
    DependencyFinding,
    Finding,
    ScanReport,
    ScanSummary,
    Severity,
)
from react_security_scanner.detector import detect_framework, detect_features
from react_security_scanner.scanners import (
    scan_rsc_patterns,
    scan_env_patterns,
    scan_xss_patterns,
    scan_api_route_patterns,
    scan_config_patterns,
)
from react_security_scanner.recommendations import generate_recommendations

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

VALID_SCAN_MODES = {"full", "deps-only", "patterns-only"}
VALID_FRAMEWORKS = {"auto", "nextjs", "react", "remix"}


async def _call_dep_scanner(
    client: AgentClient,
    repo_url: str | None = None,
    path: str | None = None,
) -> dict[str, Any] | None:
    """Call orchagent/dep-scanner for CVE scanning."""
    try:
        input_data: dict[str, Any] = {}
        if repo_url:
            input_data["repo_url"] = repo_url
        if path:
            input_data["path"] = path
        return await client.call("orchagent/dep-scanner@v1", input_data)
    except Exception as e:
        logger.error(f"dep-scanner call failed: {e}")
        return None


def _parse_dep_scanner_results(result: dict[str, Any] | None) -> list[DependencyFinding]:
    """Parse dep-scanner results into DependencyFinding objects."""
    if not result:
        return []

    findings: list[DependencyFinding] = []
    for finding in result.get("findings", []):
        severity_str = finding.get("severity", "medium").lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.medium

        findings.append(
            DependencyFinding(
                package=finding.get("package", "unknown"),
                version=finding.get("version", "unknown"),
                severity=severity,
                cve=finding.get("cve", ""),
                title=finding.get("title", ""),
                fixed_in=finding.get("fixed_in", ""),
                recommendation=finding.get("recommendation", ""),
            )
        )

    return findings


def _run_pattern_scanners(scan_path: Path) -> list[Finding]:
    """Run all local pattern scanners on the given path."""
    all_findings: list[Finding] = []

    all_findings.extend(scan_rsc_patterns(scan_path))
    all_findings.extend(scan_env_patterns(scan_path))
    all_findings.extend(scan_xss_patterns(scan_path))
    all_findings.extend(scan_api_route_patterns(scan_path))
    all_findings.extend(scan_config_patterns(scan_path))

    return all_findings


def _calculate_summary(
    findings: list[Finding],
    dep_findings: list[DependencyFinding],
    framework: str,
    features: dict,
) -> ScanSummary:
    """Calculate summary counts from all findings."""
    summary = ScanSummary(
        framework_detected=framework,
        has_app_router=features.get("has_app_router", False),
        has_server_components=features.get("has_server_components", False),
    )

    all_severities: list[str] = []
    for f in findings:
        all_severities.append(f.severity.value)
    for d in dep_findings:
        all_severities.append(d.severity.value)

    for sev in all_severities:
        if sev == "critical":
            summary.critical += 1
        elif sev == "high":
            summary.high += 1
        elif sev == "medium":
            summary.medium += 1
        elif sev == "low":
            summary.low += 1

    summary.total = summary.critical + summary.high + summary.medium + summary.low

    return summary


async def _run_scan(
    repo_url: str | None = None,
    local_path: str | None = None,
    scan_mode: str = "full",
    framework: str = "auto",
) -> ScanReport:
    """Run the full security scan."""
    pattern_findings: list[Finding] = []
    dep_findings: list[DependencyFinding] = []
    detected_framework = "unknown"
    features: dict = {}

    should_scan_deps = scan_mode in ("full", "deps-only")
    should_scan_patterns = scan_mode in ("full", "patterns-only")

    # Call dep-scanner sub-agent for CVE scanning
    if should_scan_deps:
        client = AgentClient()
        dep_result = await _call_dep_scanner(client, repo_url=repo_url, path=local_path)
        dep_findings = _parse_dep_scanner_results(dep_result)

    # Run local pattern scanners
    if should_scan_patterns:
        if local_path:
            scan_path = Path(local_path).resolve()
            if not scan_path.exists():
                raise ValueError(f"Path does not exist: {local_path}")
            if not scan_path.is_dir():
                raise ValueError(f"Path is not a directory: {local_path}")

            detected_framework = framework if framework != "auto" else detect_framework(scan_path)
            features = detect_features(scan_path)
            pattern_findings = _run_pattern_scanners(scan_path)
        else:
            try:
                with cloned_repo(repo_url) as repo_path:
                    detected_framework = framework if framework != "auto" else detect_framework(repo_path)
                    features = detect_features(repo_path)
                    pattern_findings = _run_pattern_scanners(repo_path)
            except GitCommandError as e:
                raise RuntimeError(f"Failed to clone repository: {e}") from e

    summary = _calculate_summary(pattern_findings, dep_findings, detected_framework, features)
    recommendations = generate_recommendations(
        pattern_findings, summary, dependency_findings=dep_findings,
    )

    return ScanReport(
        scan_id=str(uuid.uuid4()),
        repo_url=repo_url,
        findings=pattern_findings,
        dependency_findings=dep_findings,
        summary=summary,
        recommendations=recommendations,
    )


def main() -> None:
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(1)

    repo_url = input_data.get("repo_url")
    local_path = input_data.get("path") or input_data.get("directory")

    if not repo_url and not local_path:
        print(
            json.dumps(
                {
                    "error": "Missing required input. Provide either 'repo_url' or 'path'/'directory'.",
                    "examples": {
                        "remote": {"repo_url": "https://github.com/user/repo"},
                        "local": {"path": "."},
                    },
                }
            )
        )
        sys.exit(1)

    scan_mode = input_data.get("scan_mode", "full")
    if scan_mode not in VALID_SCAN_MODES:
        print(
            json.dumps(
                {
                    "error": f"Invalid scan_mode '{scan_mode}'",
                    "valid_modes": sorted(VALID_SCAN_MODES),
                }
            )
        )
        sys.exit(1)

    framework = input_data.get("framework", "auto")
    if framework not in VALID_FRAMEWORKS:
        print(
            json.dumps(
                {
                    "error": f"Invalid framework '{framework}'",
                    "valid_frameworks": sorted(VALID_FRAMEWORKS),
                }
            )
        )
        sys.exit(1)

    try:
        report = asyncio.run(_run_scan(
            repo_url=repo_url,
            local_path=local_path,
            scan_mode=scan_mode,
            framework=framework,
        ))
        print(json.dumps(report.model_dump()))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
