#!/usr/bin/env python3
"""
Backend Security Auditor — sandbox entrypoint.

Inspired by @0xlelouch_ (https://x.com/0xlelouch_/status/2016874653059522802)
Audits backend codebases against a 15-point security hardening checklist.

Reads JSON input from stdin, outputs JSON audit report to stdout.
"""

import json
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from backend_security_auditor.models import (
    CheckStatus,
    Finding,
    ScanResult,
    CATEGORIES,
)
from backend_security_auditor.file_walker import walk_repo, detect_project_type
from backend_security_auditor.scorer import (
    build_checklist,
    compute_score,
    generate_recommendations,
)
from backend_security_auditor.checks import (
    run_auth_checks,
    run_injection_checks,
    run_infrastructure_checks,
    run_data_handling_checks,
    run_dependency_checks,
    run_api_config_checks,
)


def clone_repo(repo_url: str) -> Path:
    """Shallow-clone a git repository to a temp directory."""
    from git import Repo

    temp_dir = tempfile.mkdtemp(prefix="security_audit_")
    Repo.clone_from(repo_url, temp_dir, depth=1)
    return Path(temp_dir)


def extract_archive(archive_path: str, dest_dir: str) -> str:
    """Extract a zip or tar archive and return the root directory to scan.

    If the archive contains a single top-level directory (common when zipping
    a project folder), descend into it automatically.
    """
    archive_path_lower = archive_path.lower()

    if archive_path_lower.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dest_dir)
    elif archive_path_lower.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive_path, "r:*") as tf:
            tf.extractall(dest_dir)
    else:
        raise ValueError(
            f"Unsupported archive format: {os.path.basename(archive_path)}. "
            "Supported formats: .zip, .tar.gz, .tgz, .tar"
        )

    # Auto-descend into single top-level directory
    entries = [e for e in os.listdir(dest_dir) if not e.startswith(".")]
    if len(entries) == 1:
        single = os.path.join(dest_dir, entries[0])
        if os.path.isdir(single):
            return single

    return dest_dir


def run_all_checks(files: list[dict], project_type: str) -> list[Finding]:
    """Run all check modules and collect findings."""
    all_findings = []

    check_runners = [
        ("auth", run_auth_checks),
        ("injection", run_injection_checks),
        ("infrastructure", run_infrastructure_checks),
        ("data_handling", run_data_handling_checks),
        ("dependencies", run_dependency_checks),
        ("api_config", run_api_config_checks),
    ]

    for name, runner in check_runners:
        try:
            findings = runner(files, project_type)
            all_findings.extend(findings)
        except Exception as e:
            # Don't let one check module crash the whole audit
            all_findings.append(Finding(
                category=name,
                category_id=0,
                check=f"{name}_error",
                status=CheckStatus.WARN,
                severity="low",
                message=f"Check module '{name}' encountered an error: {type(e).__name__}",
            ))

    return all_findings


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(1)

    uploaded_files = input_data.get("files", [])
    repo_url = input_data.get("repo_url")

    if not uploaded_files and not repo_url:
        print(json.dumps({
            "error": "Missing required input. Upload a zip/tar.gz archive or provide a public repo_url.",
            "examples": {
                "upload": "orch call orchagent/backend-security-auditor --file code.zip",
                "remote": {"repo_url": "https://github.com/user/repo"},
            },
        }))
        sys.exit(1)

    exclude = set(input_data.get("exclude", []))
    repo_path = None
    cleanup_path = None

    try:
        if uploaded_files:
            # Files uploaded via gateway — each entry has {path, original_name, ...}
            archive_entry = uploaded_files[0] if isinstance(uploaded_files, list) else None
            if not archive_entry or not isinstance(archive_entry, dict):
                print(json.dumps({"error": "Invalid file upload data."}))
                sys.exit(1)

            archive_path = archive_entry.get("path", "")
            if not archive_path or not os.path.isfile(archive_path):
                print(json.dumps({"error": f"Uploaded file not found: {archive_entry.get('original_name', 'unknown')}"}))
                sys.exit(1)

            temp_dir = tempfile.mkdtemp(prefix="security_audit_")
            cleanup_path = temp_dir
            repo_path = extract_archive(archive_path, temp_dir)
        else:
            clone_dir = str(clone_repo(repo_url))
            repo_path = clone_dir
            cleanup_path = clone_dir

        # Walk the repository
        files = walk_repo(repo_path, extra_skip=exclude or None)
        project_type = detect_project_type(files)

        if not files:
            print(json.dumps({
                "error": "No scannable files found in the repository.",
                "hint": "Ensure the repository contains backend source code (.py, .js, .ts, etc.)",
            }))
            sys.exit(1)

        # Run all checks
        all_findings = run_all_checks(files, project_type)

        # Build checklist and score
        checklist = build_checklist(all_findings)
        score, grade = compute_score(checklist)
        recommendations = generate_recommendations(checklist)

        # Separate critical issues and warnings
        critical_issues = [
            f for f in all_findings
            if f.status == CheckStatus.FAIL and f.severity in ("critical", "high")
        ]
        warnings = [
            f for f in all_findings
            if f.status == CheckStatus.WARN or (f.status == CheckStatus.FAIL and f.severity in ("medium", "low"))
        ]
        passed_categories = [
            cat.name for cat in checklist if cat.status == CheckStatus.PASS
        ]

        # Build summary
        source_count = sum(1 for f in files if f["extension"] in (".py", ".js", ".ts"))
        summary = (
            f"Scanned {len(files)} files ({source_count} source). "
            f"Score: {score}/100 (Grade {grade}). "
            f"{len(critical_issues)} critical/high issues, {len(warnings)} warnings. "
            f"{len(passed_categories)}/15 categories passed."
        )

        result = ScanResult(
            score=score,
            grade=grade,
            checklist=checklist,
            critical_issues=critical_issues,
            warnings=warnings,
            passed_categories=passed_categories,
            recommendations=recommendations,
            files_scanned=len(files),
            summary=summary,
        )

        print(json.dumps(result.model_dump(), default=str))

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    finally:
        if cleanup_path:
            shutil.rmtree(cleanup_path, ignore_errors=True)


if __name__ == "__main__":
    main()
