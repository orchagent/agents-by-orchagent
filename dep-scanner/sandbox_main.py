#!/usr/bin/env python3
"""
Sandbox entrypoint for dep-scanner.
Reads scan parameters from stdin JSON, scans repository dependencies, outputs JSON to stdout.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from dep_scanner.scanner import scan_repository


def main() -> None:
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(1)

    repo_url = input_data.get("repo_url")
    if not repo_url:
        print(
            json.dumps(
                {
                    "error": "Missing required input: 'repo_url'",
                    "example": {"repo_url": "https://github.com/user/repo"},
                }
            )
        )
        sys.exit(1)

    package_managers = input_data.get("package_managers")
    severity_threshold = input_data.get("severity_threshold", "low")

    try:
        response = scan_repository(
            repo_url=repo_url,
            package_managers=package_managers,
            severity_threshold=severity_threshold,
        )
        print(json.dumps(response.model_dump()))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
