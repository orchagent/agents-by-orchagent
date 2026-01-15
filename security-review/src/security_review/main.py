"""FastAPI application for security review orchestrator."""

import asyncio
import logging
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .agent_client import AgentClient
from .models import (
    ReviewRequest,
    ReviewResponse,
    FindingsCollection,
    ReviewSummary,
    SecretFinding,
    DependencyFinding,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Security Review",
    description="Comprehensive security review combining secret scanning, dependency auditing, and code pattern analysis",
    version="0.1.0",
)

# CORS - allow common development origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8000",
    ],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


async def _call_leak_finder(client: AgentClient, repo_url: str) -> dict[str, Any] | None:
    """Call leak-finder agent with error handling."""
    try:
        return await client.call_leak_finder(repo_url)
    except Exception as e:
        logger.error(f"leak-finder call failed: {e}")
        return None


async def _call_dep_scanner(client: AgentClient, repo_url: str) -> dict[str, Any] | None:
    """Call dep-scanner agent with error handling."""
    try:
        return await client.call_dep_scanner(repo_url)
    except Exception as e:
        logger.error(f"dep-scanner call failed: {e}")
        return None


def _parse_leak_finder_results(result: dict[str, Any] | None) -> list[SecretFinding]:
    """Parse leak-finder results into SecretFinding models."""
    if not result:
        return []

    findings = []
    # leak-finder returns findings and history_findings
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
    # Also include history findings
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
    """Parse dep-scanner results into DependencyFinding models."""
    if not result:
        return []

    findings = []
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
    """Calculate summary counts from all findings."""
    summary = ReviewSummary()

    # Count severities from all finding types
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


@app.post("/review", response_model=ReviewResponse)
async def review(request: ReviewRequest) -> ReviewResponse:
    """
    Perform a comprehensive security review of a repository.

    - **repo_url**: URL of the git repository to review
    - **scan_mode**: What to scan (full, secrets-only, deps-only, patterns-only)
    """
    try:
        logger.info(f"Reviewing repository: {request.repo_url} (mode: {request.scan_mode})")

        findings = FindingsCollection()

        # Determine which scans to run based on scan_mode
        should_scan_secrets = request.scan_mode in ("full", "secrets-only")
        should_scan_deps = request.scan_mode in ("full", "deps-only")
        # patterns-only mode will be handled in SR-004+

        async with AgentClient() as client:
            # Build list of tasks to run in parallel
            tasks = []
            task_names = []

            if should_scan_secrets:
                tasks.append(_call_leak_finder(client, request.repo_url))
                task_names.append("leak-finder")
            if should_scan_deps:
                tasks.append(_call_dep_scanner(client, request.repo_url))
                task_names.append("dep-scanner")

            # Execute all agent calls in parallel
            if tasks:
                results = await asyncio.gather(*tasks)

                # Process results
                result_idx = 0
                if should_scan_secrets:
                    findings.secrets = _parse_leak_finder_results(results[result_idx])
                    result_idx += 1
                if should_scan_deps:
                    findings.dependencies = _parse_dep_scanner_results(results[result_idx])
                    result_idx += 1

        # Calculate summary from all findings
        summary = _calculate_summary(findings)

        # Recommendations will be generated in SR-007
        recommendations: list[str] = []

        return ReviewResponse(
            scan_id=str(uuid.uuid4()),
            findings=findings,
            summary=summary,
            recommendations=recommendations,
        )

    except Exception as e:
        logger.error(f"Review failed: {e}")
        raise HTTPException(status_code=500, detail=f"Review failed: {str(e)}")
