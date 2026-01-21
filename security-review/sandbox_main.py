#!/usr/bin/env python3
"""
Sandbox entrypoint for security-review.
Reads scan parameters from stdin JSON, performs a security review, outputs JSON to stdout.
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
from security_review.git_utils import cloned_repo
from security_review.models import (
    FindingsCollection,
    ReviewResponse,
    ReviewSummary,
    SecretFinding,
    DependencyFinding,
)
from security_review.scanners import (
    scan_frontend_patterns,
    scan_api_patterns,
    scan_logging_patterns,
)
from security_review.recommendations import generate_recommendations

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

VALID_SCAN_MODES = {"full", "secrets-only", "deps-only", "patterns-only"}


async def _call_leak_finder(
    client: AgentClient,
    repo_url: str | None = None,
    path: str | None = None,
) -> dict[str, Any] | None:
    try:
        return await client.call_leak_finder(repo_url=repo_url, path=path)
    except Exception as e:
        logger.error(f"leak-finder call failed: {e}")
        return None


async def _call_dep_scanner(
    client: AgentClient,
    repo_url: str | None = None,
    path: str | None = None,
) -> dict[str, Any] | None:
    try:
        return await client.call_dep_scanner(repo_url=repo_url, path=path)
    except Exception as e:
        logger.error(f"dep-scanner call failed: {e}")
        return None


def _parse_leak_finder_results(result: dict[str, Any] | None) -> list[SecretFinding]:
    if not result:
        return []

    findings: list[SecretFinding] = []
    for finding in result.get("findings", []):
        findings.append(
            SecretFinding(
                type=finding.get("type", "unknown"),
                severity=finding.get("severity", "medium"),
                file=finding.get("file", ""),
                line=finding.get("line", 0),
                preview=finding.get("preview", ""),
                recommendation=finding.get("recommendation", ""),
            )
        )

    for finding in result.get("history_findings", []):
        findings.append(
            SecretFinding(
                type=finding.get("type", "unknown"),
                severity=finding.get("severity", "medium"),
                file=finding.get("file", ""),
                line=finding.get("line", 0),
                preview=finding.get("preview", "") + " [in git history]",
                recommendation=finding.get("recommendation", ""),
            )
        )

    return findings


def _parse_dep_scanner_results(result: dict[str, Any] | None) -> list[DependencyFinding]:
    if not result:
        return []

    findings: list[DependencyFinding] = []
    for finding in result.get("findings", []):
        findings.append(
            DependencyFinding(
                package=finding.get("package", "unknown"),
                version=finding.get("version", "unknown"),
                severity=finding.get("severity", "medium"),
                cve=finding.get("cve", ""),
                title=finding.get("title", ""),
                fixed_in=finding.get("fixed_in", ""),
                recommendation=finding.get("recommendation", ""),
            )
        )

    return findings


def _calculate_summary(findings: FindingsCollection) -> ReviewSummary:
    summary = ReviewSummary()

    all_severities = []
    for secret in findings.secrets:
        all_severities.append(secret.severity)
    for dep in findings.dependencies:
        all_severities.append(dep.severity)
    for pattern in findings.frontend_security:
        all_severities.append(pattern.severity)
    for pattern in findings.api_security:
        all_severities.append(pattern.severity)
    for pattern in findings.logging:
        all_severities.append(pattern.severity)

    for severity in all_severities:
        severity_lower = severity.lower()
        if severity_lower == "critical":
            summary.critical += 1
        elif severity_lower == "high":
            summary.high += 1
        elif severity_lower == "medium":
            summary.medium += 1
        elif severity_lower == "low":
            summary.low += 1

    return summary


async def _run_review(
    repo_url: str | None = None,
    local_path: str | None = None,
    scan_mode: str = "full",
) -> ReviewResponse:
    findings = FindingsCollection()

    should_scan_secrets = scan_mode in ("full", "secrets-only")
    should_scan_deps = scan_mode in ("full", "deps-only")
    should_scan_patterns = scan_mode in ("full", "patterns-only")

    # Sub-agent calls only work with repo_url (server-side execution can't access local paths)
    # For local paths, we skip sub-agent calls and rely on pattern scanning only
    if repo_url:
        async with AgentClient() as client:
            tasks = []

            if should_scan_secrets:
                tasks.append(_call_leak_finder(client, repo_url=repo_url))
            if should_scan_deps:
                tasks.append(_call_dep_scanner(client, repo_url=repo_url))

            if tasks:
                results = await asyncio.gather(*tasks)
                result_idx = 0

                if should_scan_secrets:
                    findings.secrets = _parse_leak_finder_results(results[result_idx])
                    result_idx += 1
                if should_scan_deps:
                    findings.dependencies = _parse_dep_scanner_results(results[result_idx])
                    result_idx += 1
    elif local_path and (should_scan_secrets or should_scan_deps):
        logger.info("Local path provided - skipping sub-agent calls (leak-finder/dep-scanner). Use repo_url for full scan.")

    if should_scan_patterns:
        if local_path:
            # Use local path directly
            scan_path = Path(local_path).resolve()
            if not scan_path.exists():
                raise ValueError(f"Path does not exist: {local_path}")
            if not scan_path.is_dir():
                raise ValueError(f"Path is not a directory: {local_path}")
            findings.frontend_security = scan_frontend_patterns(scan_path)
            findings.api_security = scan_api_patterns(scan_path)
            findings.logging = scan_logging_patterns(scan_path)
        else:
            # Clone repo for pattern scanning
            try:
                with cloned_repo(repo_url) as repo_path:
                    findings.frontend_security = scan_frontend_patterns(repo_path)
                    findings.api_security = scan_api_patterns(repo_path)
                    findings.logging = scan_logging_patterns(repo_path)
            except GitCommandError as e:
                raise RuntimeError(f"Failed to clone repository: {e}") from e

    summary = _calculate_summary(findings)
    recommendations = generate_recommendations(findings, max_recommendations=3)

    return ReviewResponse(
        scan_id=str(uuid.uuid4()),
        findings=findings,
        summary=summary,
        recommendations=recommendations,
    )


def main() -> None:
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(1)

    # Support multiple input formats:
    # - repo_url: Clone and scan a remote repository
    # - path/directory: Scan a local directory
    repo_url = input_data.get("repo_url")
    local_path = input_data.get("path") or input_data.get("directory")

    if not repo_url and not local_path:
        print(
            json.dumps(
                {
                    "error": "Missing required input. Provide either 'repo_url' (GitHub URL) or 'path'/'directory' (local path)",
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

    try:
        response = asyncio.run(_run_review(
            repo_url=repo_url,
            local_path=local_path,
            scan_mode=scan_mode,
        ))
        print(json.dumps(response.model_dump()))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
