# Invoice Scanner

Extracts structured invoice data (supplier, invoice number, line items) using the same prompt and parsing as the current OSO-stock invoice scanner.

## Setup

```bash
cd /Users/joe/orchagent/agents/invoice-scanner
pip install -e .
```

## Run

```bash
uvicorn invoice_scanner.main:app --reload --port 8002
```

## API

### Health Check
```
GET /health
```

### Scan Invoice
```
POST /scan
Content-Type: multipart/form-data
Body: { file: <pdf|jpg|png> }
```

**Response:** JSON in the exact format produced by the OSO-stock invoice scanner prompt.
