"""Framework detection for React/Next.js/Remix projects."""

import json
from pathlib import Path


def detect_framework(project_path: str | Path) -> str:
    """Detect the primary framework used in a project.

    Checks package.json dependencies and project structure to determine
    whether the project uses Next.js, Remix, or plain React.

    Args:
        project_path: Path to the project root.

    Returns:
        One of: "nextjs", "remix", "react", or "unknown".
    """
    project_path = Path(project_path)
    pkg_json_path = project_path / "package.json"

    deps: dict[str, str] = {}
    if pkg_json_path.exists():
        try:
            with open(pkg_json_path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            deps.update(pkg.get("dependencies", {}))
            deps.update(pkg.get("devDependencies", {}))
        except (json.JSONDecodeError, IOError):
            pass

    # Check for Next.js
    if "next" in deps:
        return "nextjs"

    # Check for Next.js config files even without package.json entry
    for config_name in ("next.config.js", "next.config.ts", "next.config.mjs"):
        if (project_path / config_name).exists():
            return "nextjs"

    # Check for Remix
    if "@remix-run/react" in deps or "@remix-run/node" in deps:
        return "remix"

    # Check for React
    if "react" in deps:
        return "react"

    return "unknown"


def detect_features(project_path: str | Path) -> dict:
    """Detect framework-specific features in a project.

    Args:
        project_path: Path to the project root.

    Returns:
        Dict with boolean flags for detected features.
    """
    project_path = Path(project_path)

    features = {
        "has_app_router": False,
        "has_pages_router": False,
        "has_server_components": False,
        "has_server_actions": False,
        "has_middleware": False,
        "has_api_routes": False,
    }

    # App Router: app/ directory with layout.tsx/jsx/js
    app_dir = project_path / "app"
    src_app_dir = project_path / "src" / "app"
    for candidate in (app_dir, src_app_dir):
        if candidate.is_dir():
            for ext in (".tsx", ".jsx", ".ts", ".js"):
                if (candidate / f"layout{ext}").exists():
                    features["has_app_router"] = True
                    break

    # Pages Router: pages/ directory
    pages_dir = project_path / "pages"
    src_pages_dir = project_path / "src" / "pages"
    for candidate in (pages_dir, src_pages_dir):
        if candidate.is_dir():
            features["has_pages_router"] = True
            break

    # Server Components and Server Actions detection
    use_server_str = '"use server"'
    use_server_str2 = "'use server'"
    for search_dir in (app_dir, src_app_dir):
        if not search_dir.is_dir():
            continue
        for file_path in search_dir.rglob("*.tsx"):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                if use_server_str in content or use_server_str2 in content:
                    features["has_server_components"] = True
                    features["has_server_actions"] = True
                    break
            except (IOError, OSError):
                continue
        for file_path in search_dir.rglob("*.ts"):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                if use_server_str in content or use_server_str2 in content:
                    features["has_server_actions"] = True
                    break
            except (IOError, OSError):
                continue

    # Middleware
    for middleware_name in ("middleware.ts", "middleware.js"):
        if (project_path / middleware_name).exists():
            features["has_middleware"] = True
            break
        if (project_path / "src" / middleware_name).exists():
            features["has_middleware"] = True
            break

    # API Routes
    for api_candidate in (
        project_path / "app" / "api",
        project_path / "src" / "app" / "api",
        project_path / "pages" / "api",
        project_path / "src" / "pages" / "api",
    ):
        if api_candidate.is_dir():
            features["has_api_routes"] = True
            break

    return features
