"""
Check #12: Dependency Hygiene.

#12 Dependency hygiene (SCA scans, lockfiles, patch cadence, SBOMs)
"""

import json
import re

from ..models import Finding, CheckStatus


# Lockfile mapping: package manager -> expected lockfile
_LOCKFILE_MAP = {
    "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"],
    "pyproject.toml": ["poetry.lock", "pdm.lock", "uv.lock"],
    "Pipfile": ["Pipfile.lock"],
    "Gemfile": ["Gemfile.lock"],
    "go.mod": ["go.sum"],
    "Cargo.toml": ["Cargo.lock"],
    "build.gradle": ["gradle.lockfile"],
}

# Known vulnerable / deprecated packages
_DEPRECATED_PACKAGES = {
    # npm
    "request": "Use 'got', 'axios', or 'node-fetch' instead (request is deprecated)",
    "node-uuid": "Use 'uuid' instead (node-uuid is deprecated)",
    "crypto-js": "Use Node.js built-in 'crypto' module or 'libsodium' instead",
    # pip
    "pycrypto": "Use 'pycryptodome' or 'cryptography' instead (pycrypto is unmaintained)",
    "python-jose": "Use 'PyJWT' or 'joserfc' instead (python-jose has known issues)",
}


def run_checks(files: list[dict], project_type: str = "unknown") -> list[Finding]:
    """Run dependency hygiene checks."""
    findings = []
    file_names = {f["name"] for f in files}
    file_map = {f["name"]: f for f in files}

    # Check for lockfiles
    for manifest, lockfiles in _LOCKFILE_MAP.items():
        if manifest in file_names and lockfiles:
            has_lockfile = any(lf in file_names for lf in lockfiles)
            if not has_lockfile:
                findings.append(Finding(
                    category="dependency_hygiene",
                    category_id=12,
                    check="no_lockfile",
                    status=CheckStatus.FAIL,
                    severity="high",
                    message=f"'{manifest}' found but no lockfile ({', '.join(lockfiles)}) — builds are not reproducible",
                    fix="Generate a lockfile: npm install / poetry lock / go mod tidy",
                ))

    # Check .gitignore exists
    if ".gitignore" not in file_names:
        findings.append(Finding(
            category="dependency_hygiene",
            category_id=12,
            check="no_gitignore",
            status=CheckStatus.WARN,
            severity="medium",
            message="No .gitignore file — build artifacts and secrets may be committed",
            fix="Add a .gitignore with patterns for node_modules, __pycache__, .env, dist, etc.",
        ))

    # Check package.json for deprecated packages and loose versions
    if "package.json" in file_map:
        try:
            pkg = json.loads(file_map["package.json"]["content"])
            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))

            for dep_name, version in all_deps.items():
                if dep_name in _DEPRECATED_PACKAGES:
                    findings.append(Finding(
                        category="dependency_hygiene",
                        category_id=12,
                        check="deprecated_package",
                        status=CheckStatus.WARN,
                        severity="medium",
                        message=f"Deprecated package '{dep_name}': {_DEPRECATED_PACKAGES[dep_name]}",
                        file="package.json",
                        fix=_DEPRECATED_PACKAGES[dep_name],
                    ))
                if version == "*":
                    findings.append(Finding(
                        category="dependency_hygiene",
                        category_id=12,
                        check="wildcard_version",
                        status=CheckStatus.FAIL,
                        severity="high",
                        message=f"Package '{dep_name}' uses wildcard version '*' — any version will be installed",
                        file="package.json",
                        fix=f"Pin to a specific version range: npm install {dep_name}@latest --save-exact",
                    ))
        except (json.JSONDecodeError, KeyError):
            pass

    # Check requirements.txt for deprecated packages and unpinned versions
    if "requirements.txt" in file_map:
        content = file_map["requirements.txt"]["content"]
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg_name = re.split(r"[>=<!\[]", line)[0].strip().lower()
            for dep_name, msg in _DEPRECATED_PACKAGES.items():
                if pkg_name == dep_name.lower():
                    findings.append(Finding(
                        category="dependency_hygiene",
                        category_id=12,
                        check="deprecated_package",
                        status=CheckStatus.WARN,
                        severity="medium",
                        message=f"Deprecated package '{dep_name}': {msg}",
                        file="requirements.txt",
                        fix=msg,
                    ))

    return findings
