# Code Stats

Analyzes code quality: line counts, function detection, cyclomatic complexity scoring, and warnings. Respects `.gitignore` and skips build artifacts. Supports Python, JavaScript/TypeScript, Go, and Rust.

## Features

- **Line metrics** — total, code, blank, and comment lines per file
- **Function & class detection** — names, line counts, and start lines
- **Cyclomatic complexity** — per-function complexity score (branches, logical operators, ternaries)
- **Configurable warnings** — file length, function length, and complexity thresholds
- **Smart file filtering** — respects `.gitignore`, skips `node_modules`/`dist`/`_next`/`out`/build artifacts, detects and skips minified files
- **Multiple input modes** — file uploads, directory scanning, or raw code strings

## Supported Languages

| Language | Functions | Classes | Complexity | Comments |
|----------|-----------|---------|------------|----------|
| Python | `def` (top-level + methods) | `class` | `if`/`elif`/`for`/`while`/`except`/`and`/`or` | `#` |
| JavaScript/TypeScript | `function`, arrow functions, method shorthand | `class` | `if`/`else if`/`for`/`while`/`case`/`catch`/`?`/`&&`/`\|\|`/`??` | `//`, `/* */` |
| Go | `func`, methods with receivers | `type ... struct` | `if`/`for`/`case`/`select`/`&&`/`\|\|` | `//`, `/* */` |
| Rust | `fn`, `pub fn`, `async fn` | `struct`, `impl` | `if`/`else if`/`for`/`while`/`loop`/`match`/`=>`/`&&`/`\|\|` | `//`, `/* */` |

## Usage

### CLI (file upload)

```bash
orch run orchagent/code-stats main.py server.go
```

### CLI (with options)

```bash
orch run orchagent/code-stats --input '{"code": "def foo():\n    pass"}'
```

### API (file upload)

```bash
curl -X POST "https://api.orchagent.io/orchagent/code-stats/v3/run" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "files[]=@main.py" \
  -F 'metadata={"max_function_lines": 40, "max_complexity": 8}'
```

### API (JSON code)

```bash
curl -X POST "https://api.orchagent.io/orchagent/code-stats/v3/run" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"code": "def foo():\n    if x:\n        return 1\n    return 2"}'
```

## Output

### Single file / code string

```json
{
  "language": "python",
  "metrics": {
    "total_lines": 23,
    "code_lines": 19,
    "blank_lines": 4,
    "comment_lines": 0,
    "functions": 1,
    "classes": 0
  },
  "functions": [
    {"name": "process_request", "lines": 23, "start_line": 1, "complexity": 11}
  ],
  "warnings": [
    "Function 'process_request' has complexity 11 (exceeds 10)"
  ],
  "summary": "1 function, 23 lines, 1 warning."
}
```

### Multiple files / directory scan

```json
{
  "files_analyzed": 12,
  "results": [
    {
      "filename": "src/server.py",
      "language": "python",
      "metrics": {"total_lines": 245, "code_lines": 198, "blank_lines": 30, "comment_lines": 17, "functions": 8, "classes": 2},
      "functions": [
        {"name": "handle_request", "lines": 65, "start_line": 42, "complexity": 14}
      ],
      "warnings": [
        "Function 'handle_request' is 65 lines (exceeds 50 line limit)",
        "Function 'handle_request' has complexity 14 (exceeds 10)"
      ]
    }
  ],
  "summary": "12 files analyzed. 3 warnings total.",
  "aggregate": {
    "total_lines": 1840,
    "total_functions": 47,
    "total_classes": 8,
    "total_warnings": 3,
    "errors": 0
  }
}
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_file_lines` | 300 | Warn if a file exceeds this many lines |
| `max_function_lines` | 50 | Warn if any function exceeds this many lines |
| `max_complexity` | 10 | Warn if any function's cyclomatic complexity exceeds this |

Pass via `metadata` object when using file uploads, or as top-level keys with JSON code input.

## File Filtering (Directory Scan)

When scanning a directory, the agent automatically skips:

- **`.gitignore` patterns** — parsed and respected
- **Build output** — `dist/`, `build/`, `out/`, `_next/`, `.nuxt/`, `.vercel/`, `.turbo/`, `target/`
- **Dependencies** — `node_modules/`, `vendor/`, `.venv/`, `venv/`, `site-packages/`
- **Caches** — `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `coverage/`
- **Minified files** — `*.min.js`, `*.bundle.js`, `*.chunk.js`, or any file with avg line length > 500

## Local Testing

```bash
echo '{"code": "def foo():\n    if x:\n        pass"}' | python3 main.py
echo '{"path": "."}' | python3 main.py
echo '{"files":[{"path":"main.py","original_name":"main.py"}]}' | python3 main.py
```
