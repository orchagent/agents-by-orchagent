#!/usr/bin/env python3
"""
Sandbox entrypoint for security-assessment-report.
Reads assessment parameters from stdin JSON, calls orchagent/security-review,
transforms results into an executive-level assessment report, outputs JSON to stdout.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent / "src"))

from orchagent import AgentClient
from security_assessment_report.models import AssessmentInput
from security_assessment_report.report_builder import build_report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def _call_security_review(
    client: AgentClient,
    repo_url: str | None = None,
    path: str | None = None,
) -> dict[str, Any] | None:
    """Call orchagent/security-review and return the raw result."""
    try:
        input_data: dict[str, Any] = {}
        if repo_url:
            input_data["repo_url"] = repo_url
        if path:
            input_data["path"] = path
        # Full scan mode to get comprehensive findings for the assessment
        input_data["scan_mode"] = "full"
        return await client.call("orchagent/security-review@v1", input_data)
    except Exception as e:
        logger.error(f"security-review call failed: {e}")
        return None


async def _run_assessment(input_params: AssessmentInput) -> dict[str, Any]:
    """Run the full assessment pipeline."""
    client = AgentClient()

    # Call security-review sub-agent
    review_result = await _call_security_review(
        client,
        repo_url=input_params.repo_url,
        path=input_params.path,
    )

    if review_result is None:
        return {
            "error": "security-review agent returned no results. "
            "The target repository may be inaccessible or the scan timed out.",
        }

    # Check if security-review returned an error
    if "error" in review_result:
        return {
            "error": f"security-review agent error: {review_result['error']}",
        }

    # Transform security-review output into an executive assessment report
    report = build_report(review_result, input_params)
    return report.model_dump()


def main() -> None:
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(1)

    # Support multiple input formats for path
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

    # Parse input parameters with defaults
    try:
        input_params = AssessmentInput(
            repo_url=repo_url,
            path=local_path,
            org_name=input_data.get("org_name", "Organization"),
            annual_revenue_usd=input_data.get("annual_revenue_usd"),
            industry=input_data.get("industry", "technology"),
        )
    except Exception as e:
        print(json.dumps({"error": f"Invalid input parameters: {e}"}))
        sys.exit(1)

    try:
        result = asyncio.run(_run_assessment(input_params))
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
