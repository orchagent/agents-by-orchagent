# Code Stats

Analyzes code for quality metrics - line counts, function lengths, complexity warnings.

## Features

- Counts total lines, code lines, blank lines, comment lines
- Detects functions and classes
- Warns when files or functions exceed configurable limits
- Accepts file uploads (single or multiple)
- Supports Python and JavaScript/TypeScript (auto-detected)

## Usage (File Uploads)

This agent is designed to run in OrchAgent's E2B sandbox.

**CLI:**
```bash
orch call orchagent/code-stats --file main.py --metadata '{"max_file_lines": 200, "max_function_lines": 40}'
```

**API (multipart):**
```bash
curl -X POST "https://api.orchagent.io/orchagent/code-stats/v1/run" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "files[]=@main.py" \
  -F "metadata={\"max_file_lines\":200,\"max_function_lines\":40}"
```

**Output (JSON):**
```json
{
  "files_analyzed": 2,
  "results": [
    {
      "filename": "main.py",
      "language": "python",
      "metrics": {
        "total_lines": 120,
        "code_lines": 95,
        "blank_lines": 15,
        "comment_lines": 10,
        "functions": 6,
        "classes": 1
      },
      "functions": [
        {"name": "hello", "lines": 2, "start_line": 1}
      ],
      "warnings": []
    }
  ],
  "summary": "2 files analyzed. 0 warnings total.",
  "aggregate": {
    "total_lines": 120,
    "total_functions": 6,
    "total_classes": 1,
    "total_warnings": 0,
    "errors": 0
  }
}
```

## Usage (JSON Code)

This mode is backward compatible with existing JSON input.

**Input (JSON):**
```json
{
  "code": "def hello():\n    print('hi')\n\ndef world():\n    pass",
  "language": "python",
  "max_file_lines": 300,
  "max_function_lines": 50
}
```

**Output (JSON):**
```json
{
  "language": "python",
  "metrics": {
    "total_lines": 5,
    "code_lines": 4,
    "blank_lines": 1,
    "comment_lines": 0,
    "functions": 2,
    "classes": 0
  },
  "functions": [
    {"name": "hello", "lines": 2, "start_line": 1},
    {"name": "world", "lines": 2, "start_line": 4}
  ],
  "warnings": [],
  "summary": "2 functions, 5 lines."
}
```

## API Call (JSON)

```bash
curl -X POST "https://api.orchagent.io/orchagent/code-stats/v1/run" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"code": "def foo():\n    pass"}'
```

## Local Testing

```bash
echo '{"files":[{"path":"main.py","original_name":"main.py"}]}' | python main.py
echo '{"code": "def foo():\n    pass"}' | python main.py
```

## Supported Languages

| Language | Detection | Functions | Classes |
|----------|-----------|-----------|---------|
| Python | Extension or `def` keyword | Yes | Yes |
| JavaScript/TypeScript | Extension or `function`, `=>` | Yes | Yes |
| Other | Generic | No | No |

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_file_lines` | 300 | Warn if file exceeds this |
| `max_function_lines` | 50 | Warn if any function exceeds this |

When using file uploads, pass configuration via the `metadata` object.
