#!/usr/bin/env python3
"""
Code Stats Agent - Entry point for E2B sandbox execution.

Input (stdin JSON):
{
  "files": [
    {
      "path": "/tmp/uploads/0_main.py",
      "original_name": "main.py",
      "content_type": "text/plain",
      "size_bytes": 1234
    }
  ],
  "metadata": {
    "max_file_lines": 300,  // optional, default 300
    "max_function_lines": 50  // optional, default 50
  }
}

Legacy JSON input (still supported):
{
  "code": "def hello():\n    print('hi')\n...",
  "language": "python",  // optional, auto-detected if not provided
  "max_file_lines": 300,  // optional, default 300
  "max_function_lines": 50  // optional, default 50
}

Output (stdout JSON):
{
  "metrics": {
    "total_lines": 150,
    "code_lines": 120,
    "blank_lines": 20,
    "comment_lines": 10,
    "functions": 5,
    "classes": 2
  },
  "functions": [
    {"name": "process_data", "lines": 45, "start_line": 10},
    {"name": "validate", "lines": 12, "start_line": 60}
  ],
  "warnings": [
    "Function 'handle_request' is 65 lines (exceeds 50 line limit)",
    "File has 450 total lines (exceeds 300 line limit)"
  ],
  "summary": "5 functions, 2 classes, 150 lines. 2 warnings."
}
"""

import json
import os
import sys
import re
from dataclasses import dataclass, asdict
from typing import Optional


EXTENSION_LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".go": "go",
    ".rs": "rust",
}


@dataclass
class FunctionInfo:
    name: str
    lines: int
    start_line: int


@dataclass
class Metrics:
    total_lines: int
    code_lines: int
    blank_lines: int
    comment_lines: int
    functions: int
    classes: int


def detect_language(code: str) -> str:
    """Simple language detection based on common patterns."""
    if re.search(r'\bdef\s+\w+\s*\(', code):
        return 'python'
    if re.search(r'\bfunction\s+\w+\s*\(', code) or re.search(r'=>', code):
        return 'javascript'
    if re.search(r'\bfunc\s+\w+\s*\(', code):
        return 'go'
    if re.search(r'\bfn\s+\w+\s*\(', code):
        return 'rust'
    return 'unknown'


def detect_language_from_extension(filename: str) -> Optional[str]:
    """Detect language based on file extension."""
    if not filename:
        return None
    _, ext = os.path.splitext(filename.lower())
    return EXTENSION_LANGUAGE_MAP.get(ext)


def read_file_safe(file_path: str) -> tuple[str, Optional[str]]:
    """Read file content with friendly errors."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(), None
    except FileNotFoundError:
        return "", f"File not found: {file_path}"
    except PermissionError:
        return "", f"Permission denied: {file_path}"
    except OSError as exc:
        return "", f"Failed to read file: {file_path} ({exc})"


def analyze_python(code: str) -> tuple[Metrics, list[FunctionInfo]]:
    """Analyze Python code."""
    lines = code.split('\n')
    total_lines = len(lines)
    blank_lines = sum(1 for line in lines if not line.strip())
    comment_lines = sum(1 for line in lines if line.strip().startswith('#'))
    code_lines = total_lines - blank_lines - comment_lines

    # Find functions
    functions: list[FunctionInfo] = []
    class_count = 0

    # Simple regex-based function detection
    func_pattern = re.compile(r'^(\s*)def\s+(\w+)\s*\(')
    class_pattern = re.compile(r'^class\s+\w+')

    current_func: Optional[tuple[str, int, int]] = None  # (name, start_line, indent)

    for i, line in enumerate(lines, 1):
        # Check for class
        if class_pattern.match(line):
            class_count += 1

        # Check for function start
        func_match = func_pattern.match(line)
        if func_match:
            # Save previous function if exists
            if current_func:
                name, start, indent = current_func
                functions.append(FunctionInfo(
                    name=name,
                    lines=i - start,
                    start_line=start
                ))

            indent_level = len(func_match.group(1))
            func_name = func_match.group(2)
            current_func = (func_name, i, indent_level)

    # Don't forget the last function
    if current_func:
        name, start, indent = current_func
        functions.append(FunctionInfo(
            name=name,
            lines=total_lines - start + 1,
            start_line=start
        ))

    metrics = Metrics(
        total_lines=total_lines,
        code_lines=code_lines,
        blank_lines=blank_lines,
        comment_lines=comment_lines,
        functions=len(functions),
        classes=class_count
    )

    return metrics, functions


def analyze_javascript(code: str) -> tuple[Metrics, list[FunctionInfo]]:
    """Analyze JavaScript/TypeScript code."""
    lines = code.split('\n')
    total_lines = len(lines)
    blank_lines = sum(1 for line in lines if not line.strip())
    comment_lines = sum(1 for line in lines if line.strip().startswith('//') or line.strip().startswith('*'))
    code_lines = total_lines - blank_lines - comment_lines

    # Find functions (simplified)
    functions: list[FunctionInfo] = []
    class_count = len(re.findall(r'\bclass\s+\w+', code))

    # Match function declarations, arrow functions, and methods
    func_patterns = [
        re.compile(r'^\s*(?:async\s+)?function\s+(\w+)\s*\('),
        re.compile(r'^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>)'),
        re.compile(r'^\s*(\w+)\s*\([^)]*\)\s*\{'),  # method shorthand
    ]

    for i, line in enumerate(lines, 1):
        for pattern in func_patterns:
            match = pattern.match(line)
            if match:
                functions.append(FunctionInfo(
                    name=match.group(1),
                    lines=1,  # Simplified - would need brace matching for accurate count
                    start_line=i
                ))
                break

    metrics = Metrics(
        total_lines=total_lines,
        code_lines=code_lines,
        blank_lines=blank_lines,
        comment_lines=comment_lines,
        functions=len(functions),
        classes=class_count
    )

    return metrics, functions


def analyze_generic(code: str) -> tuple[Metrics, list[FunctionInfo]]:
    """Generic analysis for unknown languages."""
    lines = code.split('\n')
    total_lines = len(lines)
    blank_lines = sum(1 for line in lines if not line.strip())

    metrics = Metrics(
        total_lines=total_lines,
        code_lines=total_lines - blank_lines,
        blank_lines=blank_lines,
        comment_lines=0,
        functions=0,
        classes=0
    )

    return metrics, []


def analyze_code(code: str, language: Optional[str] = None) -> tuple[Metrics, list[FunctionInfo], str]:
    """Analyze code and return metrics."""
    if not language:
        language = detect_language(code)

    if language == 'python':
        metrics, functions = analyze_python(code)
    elif language in ('javascript', 'typescript', 'js', 'ts'):
        metrics, functions = analyze_javascript(code)
    else:
        metrics, functions = analyze_generic(code)

    return metrics, functions, language


def analyze_single_file(
    file_info: dict,
    max_file_lines: int,
    max_function_lines: int
) -> dict:
    """Analyze a single file based on manifest data."""
    file_path = file_info.get("path")
    original_name = file_info.get("original_name") or file_info.get("filename") or ""
    filename = original_name or (os.path.basename(file_path) if file_path else "")
    if not file_path:
        return {
            "filename": filename or "unknown",
            "error": "File path missing in file manifest"
        }

    content, error = read_file_safe(file_path)
    if error:
        return {"filename": filename or file_path, "error": error}

    language_hint = detect_language_from_extension(filename or file_path)
    metrics, functions, detected_language = analyze_code(content, language_hint)
    warnings = generate_warnings(metrics, functions, max_file_lines, max_function_lines)

    return {
        "filename": filename or file_path,
        "language": detected_language,
        "metrics": asdict(metrics),
        "functions": [asdict(f) for f in functions],
        "warnings": warnings,
    }


def analyze_multiple_files(
    files: list,
    max_file_lines: int,
    max_function_lines: int,
    summary_only: bool = False
) -> dict:
    """Analyze multiple files and return aggregated results."""
    results = []
    aggregate = {
        "total_lines": 0,
        "total_functions": 0,
        "total_classes": 0,
        "total_warnings": 0,
        "errors": 0,
    }

    for file_info in files:
        result = analyze_single_file(file_info, max_file_lines, max_function_lines)
        results.append(result)
        if "error" in result:
            aggregate["errors"] += 1
            continue

        metrics = result.get("metrics", {})
        aggregate["total_lines"] += metrics.get("total_lines", 0)
        aggregate["total_functions"] += metrics.get("functions", 0)
        aggregate["total_classes"] += metrics.get("classes", 0)
        aggregate["total_warnings"] += len(result.get("warnings", []))

    files_analyzed = len(results)
    warning_total = aggregate["total_warnings"]
    summary = (
        f"{files_analyzed} file{'s' if files_analyzed != 1 else ''} analyzed. "
        f"{warning_total} warning{'s' if warning_total != 1 else ''} total."
    )

    if summary_only:
        return {
            "files_analyzed": files_analyzed,
            "summary": summary,
            "aggregate": aggregate,
        }

    return {
        "files_analyzed": files_analyzed,
        "results": results,
        "summary": summary,
        "aggregate": aggregate,
    }


def generate_warnings(
    metrics: Metrics,
    functions: list[FunctionInfo],
    max_file_lines: int,
    max_function_lines: int
) -> list[str]:
    """Generate warnings for code quality issues."""
    warnings = []

    if metrics.total_lines > max_file_lines:
        warnings.append(
            f"File has {metrics.total_lines} total lines (exceeds {max_file_lines} line limit)"
        )

    for func in functions:
        if func.lines > max_function_lines:
            warnings.append(
                f"Function '{func.name}' is {func.lines} lines (exceeds {max_function_lines} line limit)"
            )

    return warnings


# Supported file extensions for directory scanning
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs"}

# Directories to skip when scanning
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    ".env", "dist", "build", ".next", ".nuxt", "target", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "coverage", ".coverage"
}


def collect_files_from_directory(directory: str, max_files: int = 100) -> list[dict]:
    """
    Collect all supported code files from a directory.

    Args:
        directory: Path to the directory to scan
        max_files: Maximum number of files to collect

    Returns:
        List of file info dicts compatible with analyze_multiple_files
    """
    from pathlib import Path

    dir_path = Path(directory).resolve()
    if not dir_path.exists():
        raise ValueError(f"Path does not exist: {directory}")
    if not dir_path.is_dir():
        raise ValueError(f"Path is not a directory: {directory}")

    files = []
    for file_path in dir_path.rglob("*"):
        # Skip directories in SKIP_DIRS
        if any(skip_dir in file_path.parts for skip_dir in SKIP_DIRS):
            continue

        # Only include supported file types
        if file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue

        if not file_path.is_file():
            continue

        # Create file info dict
        files.append({
            "path": str(file_path),
            "original_name": str(file_path.relative_to(dir_path)),
        })

        if len(files) >= max_files:
            break

    return files


def main():
    """Main entry point."""
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)

        metadata = input_data.get("metadata")
        if isinstance(metadata, dict):
            max_file_lines = metadata.get(
                "max_file_lines", input_data.get("max_file_lines", 300)
            )
            max_function_lines = metadata.get(
                "max_function_lines", input_data.get("max_function_lines", 50)
            )
        else:
            max_file_lines = input_data.get("max_file_lines", 300)
            max_function_lines = input_data.get("max_function_lines", 50)

        summary_only = input_data.get("summary", False)

        # Support multiple input formats:
        # - path/directory: Scan a local directory
        # - files: List of file objects
        # - code: Raw code string
        local_path = input_data.get("path") or input_data.get("directory")

        if local_path:
            # Scan directory for code files
            try:
                files = collect_files_from_directory(local_path)
                if not files:
                    result = {
                        'error': f'No supported code files found in {local_path}',
                        'supported_extensions': sorted(SUPPORTED_EXTENSIONS),
                    }
                    print(json.dumps(result))
                    return
                result = analyze_multiple_files(files, max_file_lines, max_function_lines, summary_only)
                print(json.dumps(result, indent=2))
            except ValueError as e:
                print(json.dumps({'error': str(e)}))
            return

        files = input_data.get("files", [])
        if isinstance(files, list) and files:
            result = analyze_multiple_files(files, max_file_lines, max_function_lines, summary_only)
            print(json.dumps(result, indent=2))
            return

        code = input_data.get('code', '')
        language = input_data.get('language')

        if not code:
            result = {
                'error': "Missing required input. Provide 'path'/'directory' (local path), 'files' (array), or 'code' (string).",
                'examples': {
                    'local': {'path': '.'},
                    'files': {'files': [{'path': '/tmp/file.py', 'original_name': 'file.py'}]},
                    'code': {'code': 'def hello(): pass'},
                },
            }
            print(json.dumps(result))
            return

        # Analyze
        metrics, functions, detected_language = analyze_code(code, language)
        warnings = generate_warnings(metrics, functions, max_file_lines, max_function_lines)

        # Build summary
        parts = []
        if metrics.functions:
            parts.append(f"{metrics.functions} function{'s' if metrics.functions != 1 else ''}")
        if metrics.classes:
            parts.append(f"{metrics.classes} class{'es' if metrics.classes != 1 else ''}")
        parts.append(f"{metrics.total_lines} lines")
        if warnings:
            parts.append(f"{len(warnings)} warning{'s' if len(warnings) != 1 else ''}")

        summary = ', '.join(parts) + '.'

        # Build result
        result = {
            'language': detected_language,
            'metrics': asdict(metrics),
            'functions': [asdict(f) for f in functions],
            'warnings': warnings,
            'summary': summary
        }

        print(json.dumps(result, indent=2))

    except json.JSONDecodeError as e:
        result = {'error': f'Invalid JSON input: {e}'}
        print(json.dumps(result))
    except Exception as e:
        result = {'error': f'Analysis failed: {e}'}
        print(json.dumps(result))


if __name__ == '__main__':
    main()
