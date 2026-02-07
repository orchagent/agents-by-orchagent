#!/usr/bin/env python3
"""
Sandbox entrypoint for ai-data-leak-scanner.
Reads scan parameters from stdin JSON, performs AI data leak scanning, outputs JSON to stdout.
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
from ai_data_leak_scanner.git_utils import cloned_repo
from ai_data_leak_scanner.models import (
    Finding,
    SecretFinding,
    AIIntegration,
    ScanSummary,
    ScanReport,
    RiskLevel,
)
from ai_data_leak_scanner.scanners import (
    scan_pii_patterns,
    scan_ai_integrations,
    scan_schema_exposure,
    scan_logging_leaks,
)
from ai_data_leak_scanner.policy import generate_policy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

VALID_SCAN_MODES = {"full", "secrets-only", "pii-only", "ai-integrations-only"}


async def _call_leak_finder(
    client: AgentClient,
    repo_url: str | None = None,
    path: str | None = None,
) -> dict[str, Any] | None:
    """Call orchagent/leak-finder sub-agent for secret scanning."""
    try:
        input_data = {}
        if repo_url:
            input_data["repo_url"] = repo_url
        if path:
            input_data["path"] = path
        return await client.call("orchagent/leak-finder@v1", input_data)
    except Exception as e:
        logger.error(f"leak-finder call failed: {e}")
        return None


def _parse_leak_finder_results(result: dict[str, Any] | None) -> list[SecretFinding]:
    """Parse leak-finder sub-agent results into SecretFinding models."""
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


def _calculate_summary(
    findings: list[Finding],
    secret_findings: list[SecretFinding],
    ai_integrations: list[AIIntegration],
) -> ScanSummary:
    """Calculate scan summary from all findings."""
    total = len(findings) + len(secret_findings)
    critical = 0
    high = 0

    for f in findings:
        if f.risk_level == RiskLevel.critical:
            critical += 1
        elif f.risk_level == RiskLevel.high:
            high += 1

    for sf in secret_findings:
        if sf.severity == "critical":
            critical += 1
        elif sf.severity == "high":
            high += 1

    # Collect PII types
    pii_types: set[str] = set()
    for f in findings:
        pii_types.update(f.data_types_at_risk)

    # Collect AI providers
    ai_providers = list(set(i.provider for i in ai_integrations))

    # Count unprotected AI calls
    unprotected = sum(1 for i in ai_integrations if not i.is_protected)

    return ScanSummary(
        total_findings=total,
        critical=critical,
        high=high,
        pii_types_found=sorted(pii_types),
        ai_providers_found=sorted(ai_providers),
        unprotected_ai_calls=unprotected,
    )


async def _run_scan(
    repo_url: str | None = None,
    local_path: str | None = None,
    scan_mode: str = "full",
    do_generate_policy: bool = True,
) -> ScanReport:
    """Run the AI data leak scan."""
    all_findings: list[Finding] = []
    secret_findings: list[SecretFinding] = []
    ai_integrations: list[AIIntegration] = []

    should_scan_secrets = scan_mode in ("full", "secrets-only")
    should_scan_pii = scan_mode in ("full", "pii-only")
    should_scan_ai = scan_mode in ("full", "ai-integrations-only")
    should_scan_schema = scan_mode == "full"
    should_scan_logging = scan_mode == "full"

    # Call leak-finder sub-agent for secret scanning
    if should_scan_secrets:
        client = AgentClient()
        result = await _call_leak_finder(client, repo_url=repo_url, path=local_path)
        secret_findings = _parse_leak_finder_results(result)

    # Run local scanners on the codebase
    needs_local_scan = should_scan_pii or should_scan_ai or should_scan_schema or should_scan_logging

    if needs_local_scan:
        if local_path:
            scan_path = Path(local_path).resolve()
            if not scan_path.exists():
                raise ValueError(f"Path does not exist: {local_path}")
            if not scan_path.is_dir():
                raise ValueError(f"Path is not a directory: {local_path}")
            _run_local_scanners(
                scan_path, all_findings, ai_integrations,
                should_scan_pii, should_scan_ai, should_scan_schema, should_scan_logging,
            )
        else:
            try:
                with cloned_repo(repo_url) as repo_path:
                    _run_local_scanners(
                        repo_path, all_findings, ai_integrations,
                        should_scan_pii, should_scan_ai, should_scan_schema, should_scan_logging,
                    )
            except GitCommandError as e:
                raise RuntimeError(f"Failed to clone repository: {e}") from e

    # Calculate summary
    summary = _calculate_summary(all_findings, secret_findings, ai_integrations)

    # Generate DLP policy recommendations
    policy_recommendations = []
    if do_generate_policy and (all_findings or ai_integrations):
        policy_recommendations = generate_policy(all_findings, ai_integrations)

    return ScanReport(
        scan_id=str(uuid.uuid4()),
        findings=all_findings,
        secret_findings=secret_findings,
        ai_integrations=ai_integrations,
        summary=summary,
        policy_recommendations=policy_recommendations,
    )


def _run_local_scanners(
    scan_path: Path,
    all_findings: list[Finding],
    ai_integrations: list[AIIntegration],
    should_scan_pii: bool,
    should_scan_ai: bool,
    should_scan_schema: bool,
    should_scan_logging: bool,
) -> None:
    """Run all local scanners against a directory."""
    if should_scan_pii:
        pii_findings = scan_pii_patterns(scan_path)
        all_findings.extend(pii_findings)

    if should_scan_ai:
        ai_findings, integrations = scan_ai_integrations(scan_path)
        all_findings.extend(ai_findings)
        ai_integrations.extend(integrations)

    if should_scan_schema:
        schema_findings = scan_schema_exposure(scan_path)
        all_findings.extend(schema_findings)

    if should_scan_logging:
        logging_findings = scan_logging_leaks(scan_path)
        all_findings.extend(logging_findings)


def main() -> None:
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(1)

    # Support multiple input formats
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
    do_generate_policy = input_data.get("generate_policy", True)

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
        report = asyncio.run(
            _run_scan(
                repo_url=repo_url,
                local_path=local_path,
                scan_mode=scan_mode,
                do_generate_policy=do_generate_policy,
            )
        )
        print(json.dumps(report.model_dump()))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
