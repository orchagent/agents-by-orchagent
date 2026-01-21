import json
import re
from ..models import DocumentAnalysis
from ..llm import LLMProvider
from .pdf import extract_text_from_pdf


ANALYSIS_PROMPT = """Analyze this document and extract structured information. Return ONLY valid JSON, no markdown.

{
  "provider_name": "Company name (e.g., BT, Thames Water, British Gas)",
  "provider_slug": "lowercase-slug (e.g., bt, thames-water, british-gas)",
  "document_type": "bill" | "letter" | "email" | "statement" | "other",
  "document_date": "YYYY-MM-DD",
  "threat_level": "info" | "warning" | "action_required" | "legal",
  "summary": "One sentence summary (max 10 words)",

  "amount": null or number (total/main amount),
  "amount_type": null or "charge" | "credit" | "payment" | "balance",
  "currency": null or "GBP" | "USD" | "EUR",
  "due_date": null or "YYYY-MM-DD",
  "line_items": null or [{"description": "item", "amount": 10.00, "type": "charge" or "credit"}],

  "letter_type": null or "reminder" | "demand" | "confirmation" | "legal" | "notification" | "other",
  "action_required": null or "what they want you to do",
  "deadline": null or "YYYY-MM-DD",

  "reference": null or "reference number",
  "account_number": null or "account number",
  "key_points": ["detailed", "points", "from", "document"],
  "raw_text": "full text content"
}

Threat level guide:
- "info": DEFAULT. Bills, invoices, statements, confirmations, general letters, payment requests
- "warning": Explicit reminder language: "reminder", "overdue", "past due", "second notice"
- "action_required": Threatening language: "final notice", "disconnection warning", "collections", "termination"
- "legal": Debt collectors, solicitor letters, court documents, CCJ notices

Summary examples:
- "February broadband bill"
- "Payment demand for overdue balance"
- "Confirmation of complaint received"
- "Final notice before disconnection" """


async def analyze_document(file_bytes: bytes, llm: LLMProvider) -> DocumentAnalysis:
    """Extract text from PDF and analyze with LLM."""
    text = await extract_text_from_pdf(file_bytes)

    if not text.strip():
        return DocumentAnalysis(
            provider_name="Unknown",
            provider_slug="unknown",
            document_type="other",
            summary="Could not extract text from PDF",
        )

    response = await llm.analyze_text(text, ANALYSIS_PROMPT)

    def extract_json(raw: str) -> str | None:
        if not raw:
            return None
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3].strip()
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            return cleaned[start : end + 1]
        return None

    try:
        data = json.loads(response)
    except Exception:
        extracted = extract_json(response)
        if extracted is None:
            return DocumentAnalysis(
                provider_name="Unknown",
                provider_slug="unknown",
                document_type="other",
                summary="Analysis failed: invalid JSON from LLM",
            )
        try:
            data = json.loads(extracted)
        except Exception as e:
            return DocumentAnalysis(
                provider_name="Unknown",
                provider_slug="unknown",
                document_type="other",
                summary=f"Analysis failed: {str(e)[:100]}",
            )

    if data.get("line_items") is None:
        data["line_items"] = []
    return DocumentAnalysis(**data)
