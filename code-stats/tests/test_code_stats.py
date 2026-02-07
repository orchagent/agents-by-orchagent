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
    def test_basic_metrics(self):
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
        assert functions[0].lines == 2  # def + return (not the blank/comment after)

        assert functions[1].name == "beta"
        assert functions[1].start_line == 8
        assert functions[1].lines == 2

    def test_class_methods_detected(self):
        code = "\n".join([
            "class Calculator:",
            "    def add(self, x, y):",
            "        return x + y",
            "",
            "    def subtract(self, x, y):",
            "        return x - y",
        ])
        metrics, functions = main.analyze_python(code)

        assert metrics.functions == 2
        assert metrics.classes == 1
        assert functions[0].name == "add"
        assert functions[0].lines == 2
        assert functions[1].name == "subtract"
        assert functions[1].lines == 2

    def test_nested_function_detected(self):
        code = "\n".join([
            "def outer():",
            "    def inner():",
            "        return 1",
            "    return inner()",
        ])
        metrics, functions = main.analyze_python(code)

        assert metrics.functions == 2
        names = [f.name for f in functions]
        assert "outer" in names
        assert "inner" in names

    def test_multiline_function_body(self):
        code = "\n".join([
            "def long_func():",
            "    a = 1",
            "    b = 2",
            "    c = 3",
            "    d = 4",
            "    return a + b + c + d",
        ])
        metrics, functions = main.analyze_python(code)

        assert len(functions) == 1
        assert functions[0].name == "long_func"
        assert functions[0].lines == 6

    def test_empty_file(self):
        metrics, functions = main.analyze_python("")
        assert metrics.total_lines == 1  # split('\n') on "" gives ['']
        assert metrics.functions == 0
        assert functions == []

    def test_no_functions(self):
        code = "x = 1\ny = 2\nprint(x + y)"
        metrics, functions = main.analyze_python(code)

        assert metrics.functions == 0
        assert functions == []
        assert metrics.total_lines == 3

    def test_function_lines_exclude_trailing_blanks(self):
        """Function line count should not include blank lines after the body."""
        code = "\n".join([
            "def first():",
            "    return 1",
            "",
            "",
            "",
            "def second():",
            "    return 2",
        ])
        metrics, functions = main.analyze_python(code)

        assert functions[0].name == "first"
        assert functions[0].lines == 2  # just def + return
        assert functions[1].name == "second"
        assert functions[1].lines == 2

    def test_indented_class_detected(self):
        """class keyword with leading whitespace (e.g. nested class)."""
        code = "\n".join([
            "if True:",
            "    class Inner:",
            "        pass",
        ])
        metrics, _ = main.analyze_python(code)
        assert metrics.classes == 1


class TestAnalyzeJavaScript:
    def test_basic_metrics(self):
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

    def test_control_structures_not_counted(self):
        """if/while/for/switch must NOT be detected as functions."""
        code = "\n".join([
            "if (x) {",
            "  doStuff();",
            "}",
            "while (true) {",
            "  loop();",
            "}",
            "for (let i = 0; i < 10; i++) {",
            "  count();",
            "}",
            "switch (val) {",
            "  case 1: break;",
            "}",
        ])
        metrics, functions = main.analyze_javascript(code)

        assert metrics.functions == 0
        assert functions == []

    def test_function_line_count_accurate(self):
        """Function line counts should use brace matching, not be 1."""
        code = "\n".join([
            "function process() {",
            "  const a = 1;",
            "  const b = 2;",
            "  return a + b;",
            "}",
        ])
        _, functions = main.analyze_javascript(code)

        assert len(functions) == 1
        assert functions[0].name == "process"
        assert functions[0].lines == 5

    def test_async_function(self):
        code = "\n".join([
            "async function fetchData() {",
            "  const res = await fetch(url);",
            "  return res.json();",
            "}",
        ])
        _, functions = main.analyze_javascript(code)

        assert len(functions) == 1
        assert functions[0].name == "fetchData"
        assert functions[0].lines == 4

    def test_arrow_function_assigned(self):
        code = "\n".join([
            "const add = (a, b) => {",
            "  return a + b;",
            "};",
        ])
        _, functions = main.analyze_javascript(code)

        assert len(functions) == 1
        assert functions[0].name == "add"

    def test_comment_counting(self):
        code = "\n".join([
            "// single line comment",
            "/* block start",
            "   block middle",
            "   block end */",
            "const x = 1;",
        ])
        metrics, _ = main.analyze_javascript(code)

        assert metrics.comment_lines == 4
        assert metrics.code_lines == 1

    def test_export_function(self):
        code = "export function handler() {\n  return true;\n}"
        _, functions = main.analyze_javascript(code)

        assert len(functions) == 1
        assert functions[0].name == "handler"

    def test_empty_file(self):
        metrics, functions = main.analyze_javascript("")
        assert metrics.functions == 0
        assert functions == []

    def test_long_function_warning_fires(self):
        """JS function warnings must work now that line counts are accurate."""
        lines = ["function big() {"]
        for i in range(10):
            lines.append(f"  const x{i} = {i};")
        lines.append("}")
        code = "\n".join(lines)

        _, functions = main.analyze_javascript(code)
        assert functions[0].lines == 12

        warnings = main.generate_warnings(
            main.Metrics(0, 0, 0, 0, 1, 0), functions,
            max_file_lines=9999, max_function_lines=5,
        )
        assert any("big" in w for w in warnings)


class TestAnalyzeGo:
    def test_basic_go(self):
        code = "\n".join([
            "package main",
            "",
            "import \"fmt\"",
            "",
            "// greet prints a greeting",
            "func greet(name string) {",
            "    fmt.Println(name)",
            "}",
            "",
            "func main() {",
            "    greet(\"world\")",
            "}",
        ])
        metrics, functions = main.analyze_go(code)

        assert metrics.functions == 2
        assert metrics.total_lines == 12
        assert metrics.comment_lines == 1
        names = [f.name for f in functions]
        assert "greet" in names
        assert "main" in names

    def test_method_with_receiver(self):
        code = "\n".join([
            "type Server struct {",
            "    port int",
            "}",
            "",
            "func (s *Server) Start() {",
            "    listen(s.port)",
            "}",
        ])
        metrics, functions = main.analyze_go(code)

        assert metrics.functions == 1
        assert metrics.classes == 1  # struct counts as class
        assert functions[0].name == "Start"

    def test_function_line_count(self):
        code = "\n".join([
            "func compute() {",
            "    a := 1",
            "    b := 2",
            "    fmt.Println(a + b)",
            "}",
        ])
        _, functions = main.analyze_go(code)

        assert functions[0].lines == 5

    def test_no_functions(self):
        code = "package main\n\nvar x = 1\n"
        metrics, functions = main.analyze_go(code)
        assert metrics.functions == 0
        assert functions == []

    def test_via_analyze_code(self):
        """Go code should route to analyze_go, not analyze_generic."""
        code = "func hello() {\n    return\n}"
        metrics, functions, lang = main.analyze_code(code, "go")

        assert lang == "go"
        assert metrics.functions == 1
        assert len(functions) == 1


class TestAnalyzeRust:
    def test_basic_rust(self):
        code = "\n".join([
            "// A simple program",
            "fn main() {",
            "    println!(\"hello\");",
            "}",
            "",
            "fn add(a: i32, b: i32) -> i32 {",
            "    a + b",
            "}",
        ])
        metrics, functions = main.analyze_rust(code)

        assert metrics.functions == 2
        assert metrics.comment_lines == 1
        names = [f.name for f in functions]
        assert "main" in names
        assert "add" in names

    def test_pub_fn(self):
        code = "\n".join([
            "pub fn serve() {",
            "    listen();",
            "}",
        ])
        _, functions = main.analyze_rust(code)

        assert len(functions) == 1
        assert functions[0].name == "serve"

    def test_async_fn(self):
        code = "\n".join([
            "pub async fn fetch() {",
            "    let data = get().await;",
            "}",
        ])
        _, functions = main.analyze_rust(code)

        assert len(functions) == 1
        assert functions[0].name == "fetch"

    def test_struct_and_impl(self):
        code = "\n".join([
            "struct Point {",
            "    x: f64,",
            "    y: f64,",
            "}",
            "",
            "impl Point {",
            "    fn new(x: f64, y: f64) -> Self {",
            "        Point { x, y }",
            "    }",
            "}",
        ])
        metrics, functions = main.analyze_rust(code)

        assert metrics.classes == 2  # struct + impl
        assert metrics.functions == 1
        assert functions[0].name == "new"

    def test_generic_fn(self):
        code = "\n".join([
            "fn process<T>(item: T) {",
            "    do_work(item);",
            "}",
        ])
        _, functions = main.analyze_rust(code)
        assert len(functions) == 1
        assert functions[0].name == "process"

    def test_via_analyze_code(self):
        """Rust code should route to analyze_rust, not analyze_generic."""
        code = "fn hello() {\n    return;\n}"
        metrics, functions, lang = main.analyze_code(code, "rust")

        assert lang == "rust"
        assert metrics.functions == 1
        assert len(functions) == 1


class TestAnalyzeCode:
    def test_auto_detect_python(self):
        code = "def foo():\n    pass"
        metrics, functions, lang = main.analyze_code(code)
        assert lang == "python"
        assert metrics.functions == 1

    def test_auto_detect_go(self):
        code = "func main() {\n    fmt.Println(\"hi\")\n}"
        metrics, functions, lang = main.analyze_code(code)
        assert lang == "go"
        assert metrics.functions == 1

    def test_auto_detect_rust(self):
        code = "fn main() {\n    println!(\"hi\");\n}"
        metrics, functions, lang = main.analyze_code(code)
        assert lang == "rust"
        assert metrics.functions == 1

    def test_unknown_language_still_counts_lines(self):
        code = "<html>\n<body>\n</body>\n</html>"
        metrics, functions, lang = main.analyze_code(code)
        assert lang == "unknown"
        assert metrics.total_lines == 4
        assert metrics.functions == 0

    def test_explicit_language_overrides_detection(self):
        # Code looks like Python but we say it's Go
        code = "def foo():\n    pass"
        _, _, lang = main.analyze_code(code, "go")
        assert lang == "go"

    def test_typescript_alias(self):
        code = "function foo() {\n  return 1;\n}"
        metrics, _, lang = main.analyze_code(code, "ts")
        assert lang == "ts"
        assert metrics.functions == 1


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

    def test_no_warnings_when_within_limits(self):
        metrics = main.Metrics(
            total_lines=10, code_lines=8, blank_lines=1, comment_lines=1,
            functions=1, classes=0,
        )
        functions = [main.FunctionInfo(name="foo", lines=5, start_line=1)]

        warnings = main.generate_warnings(metrics, functions, max_file_lines=300, max_function_lines=50)
        assert warnings == []

    def test_multiple_function_warnings(self):
        metrics = main.Metrics(
            total_lines=10, code_lines=10, blank_lines=0, comment_lines=0,
            functions=2, classes=0,
        )
        functions = [
            main.FunctionInfo(name="a", lines=100, start_line=1),
            main.FunctionInfo(name="b", lines=100, start_line=1),
        ]

        warnings = main.generate_warnings(metrics, functions, max_file_lines=300, max_function_lines=50)
        assert len(warnings) == 2
        assert any("'a'" in w for w in warnings)
        assert any("'b'" in w for w in warnings)


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


class TestMainEntryPoint:
    """Tests that exercise main() end-to-end via stdin/stdout."""

    def _run_main(self, monkeypatch, capsys, payload: dict) -> dict:
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
        main.main()
        captured = capsys.readouterr()
        return json.loads(captured.out)

    def test_code_input_python(self, monkeypatch, capsys):
        result = self._run_main(monkeypatch, capsys, {
            "code": "def foo():\n    pass",
        })
        assert result["language"] == "python"
        assert result["metrics"]["functions"] == 1

    def test_code_input_with_explicit_language(self, monkeypatch, capsys):
        result = self._run_main(monkeypatch, capsys, {
            "code": "function foo() {\n  return 1;\n}",
            "language": "javascript",
        })
        assert result["language"] == "javascript"
        assert result["metrics"]["functions"] == 1

    def test_code_input_go(self, monkeypatch, capsys):
        result = self._run_main(monkeypatch, capsys, {
            "code": "func main() {\n    fmt.Println(\"hi\")\n}",
        })
        assert result["language"] == "go"
        assert result["metrics"]["functions"] == 1

    def test_code_input_rust(self, monkeypatch, capsys):
        result = self._run_main(monkeypatch, capsys, {
            "code": "fn main() {\n    println!(\"hello\");\n}",
        })
        assert result["language"] == "rust"
        assert result["metrics"]["functions"] == 1

    def test_file_input(self, monkeypatch, capsys, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("def foo():\n    pass\n\ndef bar():\n    pass", encoding="utf-8")

        result = self._run_main(monkeypatch, capsys, {
            "files": [{"path": str(f), "original_name": "sample.py"}],
        })
        assert result["files_analyzed"] == 1
        assert result["aggregate"]["total_functions"] == 2

    def test_directory_input(self, monkeypatch, capsys, tmp_path):
        (tmp_path / "one.py").write_text("def a():\n    pass", encoding="utf-8")
        (tmp_path / "two.py").write_text("def b():\n    pass", encoding="utf-8")

        result = self._run_main(monkeypatch, capsys, {"path": str(tmp_path)})
        assert result["files_analyzed"] == 2
        assert result["aggregate"]["total_functions"] == 2

    def test_missing_input_returns_error(self, monkeypatch, capsys):
        result = self._run_main(monkeypatch, capsys, {})
        assert "error" in result

    def test_invalid_json(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "stdin", io.StringIO("not json"))
        main.main()
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "Invalid JSON" in result["error"]

    def test_summary_field_present(self, monkeypatch, capsys):
        result = self._run_main(monkeypatch, capsys, {
            "code": "def hello():\n    print('hi')\n\ndef world():\n    pass",
        })
        assert "summary" in result
        assert "2 functions" in result["summary"]

    def test_metadata_overrides(self, monkeypatch, capsys):
        # Build a function with 3 lines, set max_function_lines=2 via metadata
        result = self._run_main(monkeypatch, capsys, {
            "code": "def f():\n    a = 1\n    return a",
            "metadata": {"max_function_lines": 2},
        })
        assert len(result["warnings"]) == 1
        assert "f" in result["warnings"][0]

    def test_summary_only_mode(self, monkeypatch, capsys, tmp_path):
        (tmp_path / "a.py").write_text("def x():\n    pass", encoding="utf-8")
        result = self._run_main(monkeypatch, capsys, {
            "path": str(tmp_path),
            "summary": True,
        })
        assert "results" not in result  # summary_only omits per-file results
        assert "aggregate" in result

    def test_complexity_in_output(self, monkeypatch, capsys):
        code = "\n".join([
            "def decide(x):",
            "    if x > 0:",
            "        if x > 10:",
            "            return 'big'",
            "        return 'small'",
            "    return 'negative'",
        ])
        result = self._run_main(monkeypatch, capsys, {"code": code})
        funcs = result["functions"]
        assert len(funcs) == 1
        assert funcs[0]["complexity"] >= 3  # base 1 + 2 ifs

    def test_complexity_warning(self, monkeypatch, capsys):
        # Build a function with many branches
        lines = ["def branchy(x):"]
        for i in range(12):
            lines.append(f"    if x == {i}:")
            lines.append(f"        return {i}")
        lines.append("    return -1")
        code = "\n".join(lines)
        result = self._run_main(monkeypatch, capsys, {
            "code": code,
            "metadata": {"max_complexity": 5},
        })
        assert any("complexity" in w for w in result["warnings"])

    def test_max_complexity_metadata(self, monkeypatch, capsys):
        code = "\n".join([
            "def simple():",
            "    if True:",
            "        pass",
        ])
        # With high threshold → no warning
        result = self._run_main(monkeypatch, capsys, {
            "code": code,
            "metadata": {"max_complexity": 100},
        })
        assert not any("complexity" in w for w in result["warnings"])


class TestComplexity:
    """Test cyclomatic complexity counting for each language."""

    def test_python_simple(self):
        code = "\n".join([
            "def foo():",
            "    return 1",
        ])
        _, functions = main.analyze_python(code)
        assert functions[0].complexity == 1  # no branches

    def test_python_branchy(self):
        code = "\n".join([
            "def process(x):",
            "    if x > 0:",
            "        for i in range(x):",
            "            if i % 2 == 0:",
            "                print(i)",
            "    elif x < 0:",
            "        while x < 0:",
            "            x += 1",
        ])
        _, functions = main.analyze_python(code)
        # 1 base + if + for + if + elif + while = 6
        assert functions[0].complexity == 6

    def test_python_logical_operators(self):
        code = "\n".join([
            "def check(a, b, c):",
            "    if a and b or c:",
            "        return True",
        ])
        _, functions = main.analyze_python(code)
        # 1 base + if + and + or = 4
        assert functions[0].complexity == 4

    def test_js_branches(self):
        code = "\n".join([
            "function handle(req) {",
            "  if (req.method === 'GET') {",
            "    return getHandler(req);",
            "  } else if (req.method === 'POST') {",
            "    return postHandler(req);",
            "  }",
            "  const val = req.ok ? 'yes' : 'no';",
            "  return val || 'default';",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        # 1 base + if + else if + ternary(?) + || = 5
        assert functions[0].complexity == 5

    def test_js_switch_cases(self):
        code = "\n".join([
            "function route(action) {",
            "  switch (action) {",
            "    case 'a': return 1;",
            "    case 'b': return 2;",
            "    case 'c': return 3;",
            "  }",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        # 1 base + 3 case = 4
        assert functions[0].complexity == 4

    def test_go_branches(self):
        code = "\n".join([
            "func process(x int) int {",
            "    if x > 0 {",
            "        return x",
            "    }",
            "    for i := 0; i < 10; i++ {",
            "        if x == i || x == -i {",
            "            return i",
            "        }",
            "    }",
            "    return 0",
            "}",
        ])
        _, functions = main.analyze_go(code)
        # 1 base + if + for + if + || = 5
        assert functions[0].complexity == 5

    def test_rust_branches(self):
        code = "\n".join([
            "fn decide(x: i32) -> &str {",
            '    if x > 0 {',
            '        "positive"',
            '    } else if x < 0 {',
            '        "negative"',
            "    } else {",
            '        "zero"',
            "    }",
            "}",
        ])
        _, functions = main.analyze_rust(code)
        # 1 base + if + else if = 3
        assert functions[0].complexity == 3

    def test_generic_no_complexity(self):
        """Unknown languages should report complexity=1 (default)."""
        code = "some unknown code\nwith branches if you squint"
        metrics, functions, lang = main.analyze_code(code)
        assert lang == "unknown"
        # No functions detected → no complexity to check
        assert functions == []


class TestFileFiltering:
    """Test .gitignore, minified file, and build artifact filtering."""

    def test_gitignore_respected(self, tmp_path):
        # Create .gitignore
        (tmp_path / ".gitignore").write_text("ignored_dir\n*.generated.py\n", encoding="utf-8")
        # Create files
        (tmp_path / "good.py").write_text("x = 1", encoding="utf-8")
        ignored_dir = tmp_path / "ignored_dir"
        ignored_dir.mkdir()
        (ignored_dir / "bad.py").write_text("x = 2", encoding="utf-8")
        (tmp_path / "auto.generated.py").write_text("x = 3", encoding="utf-8")

        files = main.collect_files_from_directory(str(tmp_path))
        names = [f["original_name"] for f in files]

        assert "good.py" in names
        assert "ignored_dir/bad.py" not in names
        assert "auto.generated.py" not in names

    def test_skip_next_static_chunks(self, tmp_path):
        """_next/static/chunks should be skipped (build artifacts)."""
        chunks_dir = tmp_path / "_next" / "static" / "chunks"
        chunks_dir.mkdir(parents=True)
        (chunks_dir / "app.js").write_text("var x=1;", encoding="utf-8")

        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "app.js").write_text("function main() {}", encoding="utf-8")

        files = main.collect_files_from_directory(str(tmp_path))
        names = [f["original_name"] for f in files]

        assert "src/app.js" in names
        # _next is in SKIP_DIRS, so chunks should be excluded
        assert not any("_next" in n for n in names)

    def test_skip_minified_by_name(self, tmp_path):
        """Files like *.min.js should be skipped."""
        (tmp_path / "app.min.js").write_text("var x=1;", encoding="utf-8")
        (tmp_path / "app.js").write_text("var x = 1;", encoding="utf-8")

        files = main.collect_files_from_directory(str(tmp_path))
        names = [f["original_name"] for f in files]

        assert "app.js" in names
        assert "app.min.js" not in names

    def test_skip_minified_by_content(self, tmp_path):
        """Files with avg line length > 500 should be skipped."""
        minified = "var a=1;" * 200  # ~1600 chars on one line
        (tmp_path / "bundle.js").write_text(minified, encoding="utf-8")
        (tmp_path / "normal.js").write_text("function foo() {\n  return 1;\n}", encoding="utf-8")

        files = main.collect_files_from_directory(str(tmp_path))
        names = [f["original_name"] for f in files]

        assert "normal.js" in names
        assert "bundle.js" not in names

    def test_skip_dist_out_build(self, tmp_path):
        for dirname in ("dist", "out", "build"):
            d = tmp_path / dirname
            d.mkdir()
            (d / "compiled.js").write_text("x=1", encoding="utf-8")

        (tmp_path / "src.js").write_text("function f() {}", encoding="utf-8")

        files = main.collect_files_from_directory(str(tmp_path))
        names = [f["original_name"] for f in files]

        assert "src.js" in names
        assert not any("dist" in n or "out" in n or "build" in n for n in names)

    def test_gitignore_with_path_pattern(self, tmp_path):
        """Gitignore patterns with slashes match against full relative path."""
        (tmp_path / ".gitignore").write_text("src/generated\n", encoding="utf-8")
        gen_dir = tmp_path / "src" / "generated"
        gen_dir.mkdir(parents=True)
        (gen_dir / "auto.py").write_text("x = 1", encoding="utf-8")
        src_dir = tmp_path / "src"
        (src_dir / "real.py").write_text("x = 2", encoding="utf-8")

        files = main.collect_files_from_directory(str(tmp_path))
        names = [f["original_name"] for f in files]

        assert "src/real.py" in names
        assert "src/generated/auto.py" not in names

    def test_no_gitignore_still_works(self, tmp_path):
        """If no .gitignore exists, should still work fine."""
        (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")

        files = main.collect_files_from_directory(str(tmp_path))
        assert len(files) == 1
        assert files[0]["original_name"] == "app.py"

    def test_deterministic_file_ordering(self, tmp_path):
        """File ordering should be deterministic (sorted) regardless of OS."""
        for name in ("zebra.py", "alpha.py", "middle.py"):
            (tmp_path / name).write_text("x = 1", encoding="utf-8")

        files = main.collect_files_from_directory(str(tmp_path))
        names = [f["original_name"] for f in files]
        assert names == sorted(names)


class TestBugfixRegressions:
    """Regression tests for specific bugs found in code review."""

    # -- Bug 1: JS ternary regex over-counting ?. / ?? / ?: --

    def test_optional_chaining_not_counted_as_branch(self):
        """a?.b should NOT add a branch point."""
        code = "\n".join([
            "function f() {",
            "  return a?.b?.c;",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        assert functions[0].complexity == 1  # just the base, no branches

    def test_nullish_coalescing_counted_once(self):
        """?? should be counted as one logical operator, not two ?s."""
        code = "\n".join([
            "function f() {",
            "  return a ?? b;",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        assert functions[0].complexity == 2  # base 1 + ?? = 2

    def test_ts_optional_param_not_counted(self):
        """x?: string in TS should NOT add a branch."""
        lines = [
            "  name?: string;",
            "  age?: number;",
            "  email?: string;",
        ]
        count = main._count_complexity(lines, "typescript")
        assert count == 0

    def test_mixed_optional_chaining_and_ternary(self):
        """a?.b ?? c ? 'yes' : 'no' → only ?? and ternary ? count."""
        code = "\n".join([
            "function f() {",
            "  const x = a?.b ?? c ? 'yes' : 'no';",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        # base 1 + ?? + ternary ? = 3
        assert functions[0].complexity == 3

    # -- Bug 2: Braces in strings truncating function bodies --

    def test_brace_in_string_does_not_truncate(self):
        """console.log("}") should NOT end the function body."""
        code = "\n".join([
            'function f() {',
            '  console.log("}");',
            '  return 1;',
            '}',
        ])
        _, functions = main.analyze_javascript(code)
        assert functions[0].lines == 4

    def test_brace_in_single_quote_string(self):
        code = "\n".join([
            "function f() {",
            "  const s = '{}}}}';",
            "  return s;",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        assert functions[0].lines == 4

    def test_brace_in_template_literal(self):
        code = "\n".join([
            "function f() {",
            "  const s = `value: }`;",
            "  return s;",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        assert functions[0].lines == 4

    def test_brace_in_comment_does_not_count(self):
        code = "\n".join([
            "function f() {",
            "  // this } does not close",
            "  return 1;",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        assert functions[0].lines == 4

    def test_brace_in_block_comment(self):
        code = "\n".join([
            "function f() {",
            "  /* } */",
            "  return 1;",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        assert functions[0].lines == 4

    # -- Bug 3: Negative code_lines from block comments with blank lines --

    def test_code_lines_never_negative(self):
        """Block comments with blank lines must not produce negative code_lines."""
        code = "\n".join([
            "/*",
            " * A big comment block",
            "",
            " * with blank lines inside",
            "",
            " * more commentary",
            " */",
        ])
        metrics, _ = main.analyze_javascript(code)
        assert metrics.code_lines >= 0

    def test_block_comment_blank_lines_not_double_counted(self):
        """Blank lines inside block comments shouldn't be counted as comment lines."""
        code = "\n".join([
            "/*",
            "",
            " */",
            "const x = 1;",
        ])
        metrics, _ = main.analyze_javascript(code)
        # total=4, blank=1 (the empty line), comment=2 (/* and */), code=1
        assert metrics.blank_lines == 1
        assert metrics.comment_lines == 2
        assert metrics.code_lines == 1

    def test_go_code_lines_never_negative(self):
        """Same bug can happen in Go which uses the same comment counter."""
        code = "\n".join([
            "package main",
            "",
            "/*",
            "",
            "  Big comment",
            "",
            "*/",
        ])
        metrics, _ = main.analyze_go(code)
        assert metrics.code_lines >= 0

    # -- Bug 4: Keywords in strings inflating complexity --

    def test_python_keyword_in_string_not_counted(self):
        """raise ValueError('if data is empty') should not count 'if'."""
        code = "\n".join([
            "def validate(data):",
            "    if not data:",
            "        raise ValueError('if data is empty')",
            "    return data",
        ])
        _, functions = main.analyze_python(code)
        # base 1 + 1 real if = 2 (not 3)
        assert functions[0].complexity == 2

    def test_js_keyword_in_string_not_counted(self):
        """Keywords inside string literals should not inflate complexity."""
        code = "\n".join([
            "function f() {",
            '  console.log("if for while case");',
            "  return 1;",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        assert functions[0].complexity == 1  # just the base

    def test_python_keyword_in_inline_comment_not_counted(self):
        """Keywords in inline comments should not be counted."""
        code = "\n".join([
            "def process():",
            "    x = 1  # if this fails, retry",
            "    return x",
        ])
        _, functions = main.analyze_python(code)
        assert functions[0].complexity == 1  # just the base

    def test_js_keyword_in_inline_comment_not_counted(self):
        code = "\n".join([
            "function f() {",
            "  const x = 1; // if this fails, catch it",
            "  return x;",
            "}",
        ])
        _, functions = main.analyze_javascript(code)
        assert functions[0].complexity == 1

    def test_go_keyword_in_string_not_counted(self):
        code = "\n".join([
            'func f() {',
            '    fmt.Sprintf("for each %s", x)',
            '}',
        ])
        _, functions = main.analyze_go(code)
        assert functions[0].complexity == 1

    # -- Bug 6/7: Dead code removal --

    def test_python_branch_re_removed(self):
        """_PYTHON_BRANCH_RE should no longer exist."""
        assert not hasattr(main, '_PYTHON_BRANCH_RE')

    def test_rust_arrow_not_in_regex(self):
        """=> should not be in _RUST_BRANCH_RE (it can never match with \\b)."""
        assert '=>' not in main._RUST_BRANCH_RE.pattern
