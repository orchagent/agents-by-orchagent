import io
import json
import os
import sys
from pathlib import Path

import pytest

import main


class TestDetectLanguage:
    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            ("def foo():\n    pass", "python"),
            ("function foo() {}", "javascript"),
            ("const foo = () => {}", "javascript"),
            ("func foo() {}", "go"),
            ("fn foo() {}", "rust"),
            ("<?xml version=\"1.0\"?>", "unknown"),
        ],
    )
    def test_detect_language(self, code, expected):
        assert main.detect_language(code) == expected


class TestDetectLanguageFromExtension:
    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("main.py", "python"),
            ("app.js", "javascript"),
            ("index.ts", "typescript"),
            ("view.tsx", "typescript"),
            ("component.jsx", "javascript"),
            ("service.go", "go"),
            ("lib.rs", "rust"),
            ("README.md", None),
            ("", None),
        ],
    )
    def test_detect_language_from_extension(self, filename, expected):
        assert main.detect_language_from_extension(filename) == expected


class TestAnalyzePython:
    def test_analyze_python_metrics(self):
        code_lines = [
            "class Foo:",
            "    pass",
            "",
            "def alpha():",
            "    return 1",
            "",
            "# comment",
            "def beta():",
            "    pass",
        ]
        code = "\n".join(code_lines)
        metrics, functions = main.analyze_python(code)

        assert metrics.total_lines == len(code_lines)
        assert metrics.blank_lines == 2
        assert metrics.comment_lines == 1
        assert metrics.functions == 2
        assert metrics.classes == 1

        assert functions[0].name == "alpha"
        assert functions[0].start_line == 4
        assert functions[0].lines == 4

        assert functions[1].name == "beta"
        assert functions[1].start_line == 8
        assert functions[1].lines == 2


class TestAnalyzeJavaScript:
    def test_analyze_javascript_metrics(self):
        code_lines = [
            "function foo() {",
            "  return 1;",
            "}",
            "const bar = () => {",
            "  return 2;",
            "};",
            "class Baz {",
            "  method() {",
            "    return 3;",
            "  }",
            "}",
        ]
        code = "\n".join(code_lines)
        metrics, functions = main.analyze_javascript(code)

        assert metrics.total_lines == len(code_lines)
        assert metrics.functions == 3
        assert metrics.classes == 1
        assert len(functions) == 3


class TestGenerateWarnings:
    def test_generate_warnings(self):
        metrics = main.Metrics(
            total_lines=10,
            code_lines=8,
            blank_lines=1,
            comment_lines=1,
            functions=1,
            classes=0,
        )
        functions = [main.FunctionInfo(name="foo", lines=6, start_line=1)]

        warnings = main.generate_warnings(metrics, functions, max_file_lines=5, max_function_lines=5)
        assert any("File has 10 total lines" in warning for warning in warnings)
        assert any("Function 'foo' is 6 lines" in warning for warning in warnings)


class TestReadFileSafe:
    def test_read_file_safe_success(self, tmp_path: Path):
        file_path = tmp_path / "sample.py"
        file_path.write_text("print('hi')", encoding="utf-8")

        content, error = main.read_file_safe(str(file_path))

        assert error is None
        assert "print('hi')" in content

    def test_read_file_safe_missing(self, tmp_path: Path):
        file_path = tmp_path / "missing.py"
        content, error = main.read_file_safe(str(file_path))

        assert content == ""
        assert error == f"File not found: {file_path}"

    def test_read_file_safe_permission(self, tmp_path: Path):
        file_path = tmp_path / "private.py"
        file_path.write_text("print('secret')", encoding="utf-8")

        try:
            os.chmod(file_path, 0)
            content, error = main.read_file_safe(str(file_path))
            if error is None:
                pytest.skip("Permission error not enforced on this platform")
            assert content == ""
            assert error == f"Permission denied: {file_path}"
        finally:
            os.chmod(file_path, 0o644)


class TestAnalyzeSingleFile:
    def test_analyze_single_file(self, tmp_path: Path):
        file_path = tmp_path / "sample.py"
        file_path.write_text("def foo():\n    pass", encoding="utf-8")
        file_info = {"path": str(file_path), "original_name": "sample.py"}

        result = main.analyze_single_file(file_info, max_file_lines=1, max_function_lines=1)

        assert result["filename"] == "sample.py"
        assert result["language"] == "python"
        assert result["metrics"]["total_lines"] == 2
        assert len(result["warnings"]) == 2


class TestAnalyzeMultipleFiles:
    def test_analyze_multiple_files(self, tmp_path: Path):
        file_one = tmp_path / "one.py"
        file_one.write_text("def foo():\n    pass", encoding="utf-8")
        file_two = tmp_path / "two.js"
        file_two.write_text("function bar() {\n  return 1;\n}", encoding="utf-8")
        missing = tmp_path / "missing.py"

        files = [
            {"path": str(file_one), "original_name": "one.py"},
            {"path": str(file_two), "original_name": "two.js"},
            {"path": str(missing), "original_name": "missing.py"},
        ]

        result = main.analyze_multiple_files(files, max_file_lines=300, max_function_lines=50)

        assert result["files_analyzed"] == 3
        assert len(result["results"]) == 3
        assert result["aggregate"]["errors"] == 1
        assert result["aggregate"]["total_lines"] == 5
        assert result["aggregate"]["total_functions"] == 2
        assert result["aggregate"]["total_classes"] == 0
        assert result["aggregate"]["total_warnings"] == 0
        assert result["summary"].startswith("3 files analyzed.")


class TestBackwardCompatibility:
    def test_main_with_code_input(self, monkeypatch, capsys):
        payload = {"code": "def foo():\n    pass"}
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))

        main.main()

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["language"] == "python"
        assert result["metrics"]["functions"] == 1
