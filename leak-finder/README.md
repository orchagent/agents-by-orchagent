# Leak Finder

AI-powered agent that scans repositories for exposed secrets and credentials.

## Features

- Scans current files and git history for exposed secrets
- Detects 23+ secret types (AWS, Stripe, GitHub, private keys, etc.)
- LLM-powered false positive reduction using Gemini
- REST API for integration with CI/CD pipelines
- CLI for local scanning

## Installation

```bash
cd agents/leak-finder
pip install -e .
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GEMINI_API_KEY` | No | Gemini API key for LLM-based false positive filtering. If not set, all findings are returned without filtering. |

## CLI Usage

### Scan a local directory

```bash
python -m leak_finder.cli ./path/to/project
```

### Deep scan including git history

```bash
python -m leak_finder.cli ./path/to/project --deep
```

### Mark rotated keys

```bash
python -m leak_finder.cli ./path/to/project --rotated AKIA1234,sk_live_abc
```

### Output as JSON

```bash
python -m leak_finder.cli ./path/to/project --json
```

### Exit codes

- `0`: No critical findings
- `1`: Critical findings detected

## API Usage

### Start the server

```bash
uvicorn leak_finder.main:app --port 8003
```

### Health check

```bash
curl http://localhost:8003/health
```

Response:
```json
{"status": "ok"}
```

### Quick scan (current files only)

```bash
curl -X POST http://localhost:8003/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo"}'
```

With branch:
```bash
curl -X POST http://localhost:8003/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo", "branch": "main"}'
```

Response:
```json
{
  "scan_id": "uuid",
  "mode": "quick",
  "findings": [...],
  "summary": "Found 2 potential secrets: 1 critical, 1 high severity.",
  "offer_deep_scan": true
}
```

### Deep scan (includes git history)

```bash
curl -X POST http://localhost:8003/scan/deep \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo"}'
```

With rotated keys:
```bash
curl -X POST http://localhost:8003/scan/deep \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo", "rotated_keys": ["AKIA1234", "sk_live_abc"]}'
```

Response:
```json
{
  "scan_id": "uuid",
  "mode": "deep",
  "findings": [...],
  "history_findings": [...],
  "summary": "Found 2 secrets in current files (1 critical), 5 in git history (3 critical).",
  "offer_deep_scan": false
}
```

## Detected Secret Types

| Category | Types |
|----------|-------|
| **AWS** | Access Key ID, Secret Access Key |
| **Stripe** | Live Secret Key, Test Secret Key, Live Publishable Key |
| **GitHub** | Personal Access Token, OAuth Token, App Token, Refresh Token |
| **Clerk** | Secret Key (Live), Secret Key (Test) |
| **Supabase** | Service Role Key (JWT) |
| **Private Keys** | RSA, OpenSSH, EC, PGP |
| **Database** | PostgreSQL URI, MySQL URI |
| **Other** | Slack Token, SendGrid API Key, Twilio API Key |
| **Generic** | API Key, Secret/Password |

## Finding Severity Levels

- **critical**: Immediate action required (live API keys, private keys, production credentials)
- **high**: Should be rotated (generic secrets, database credentials)
- **medium**: Review recommended (test keys that shouldn't be in code)
- **low**: Informational (test keys, example values)
- **info**: Rotated or acknowledged findings

## Docker

### Build

```bash
docker build -t leak-finder .
```

### Run

```bash
docker run -p 8003:8000 -e GEMINI_API_KEY=your-key leak-finder
```

## Development

### Install dev dependencies

```bash
pip install -e ".[dev]"
```

### Run tests

```bash
pytest tests/ -v
```
