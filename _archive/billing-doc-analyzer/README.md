# Billing Doc Analyzer

Analyzes billing documents (bills, letters, emails, statements) from service providers.

## Setup

```bash
cd /Users/joe/orchagent/agents/billing-doc-analyzer
pip install -e .
```

## Run

```bash
uvicorn billing_doc_analyzer.main:app --reload --port 8001
```

## API

### Health Check
```
GET /health
```

### Analyze Document
```
POST /analyze
Content-Type: multipart/form-data
Body: { file: <pdf> }
```

**Response:**
```json
{
  "provider_name": "British Gas",
  "provider_slug": "british-gas",
  "document_type": "bill",
  "document_date": "2025-01-15",
  "threat_level": "info",
  "summary": "January gas bill",
  "amount": 85.50,
  "amount_type": "charge",
  "currency": "GBP",
  "due_date": "2025-02-01",
  "line_items": [],
  "letter_type": null,
  "action_required": null,
  "deadline": null,
  "reference": "INV-12345",
  "account_number": "123456789",
  "key_points": ["Usage: 250 kWh", "Fixed rate tariff"],
  "raw_text": "..."
}
```

## Supported Document Types

- **bill** - Invoices, utility bills
- **letter** - Correspondence, reminders, demands
- **email** - Email communications
- **statement** - Account statements
- **other** - Anything else

## Threat Levels

- **info** - Normal documents (default)
- **warning** - Reminders, overdue notices
- **action_required** - Final notices, disconnection warnings
- **legal** - Court docs, solicitor letters

## LLM Backend

Uses **Gemini 2.5 Flash** by default and requires `GEMINI_API_KEY`.

To swap providers:
1. Install: `pip install -e ".[openai]"` or `pip install -e ".[anthropic]"`
2. Create provider in `src/billing_doc_analyzer/llm/`
3. Update `main.py` to use your provider
