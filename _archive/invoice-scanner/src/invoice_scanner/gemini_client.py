"""
Gemini AI Client for Invoice Scanning

Uses Google GenAI SDK (google-genai) for document extraction.
"""

from google import genai
from google.genai import types
from typing import Dict, Any
import os
import logging
from pathlib import Path
from .parsing import parse_invoice_response

logger = logging.getLogger(__name__)

# Path to the customizable extraction prompt
PROMPT_FILE = Path(__file__).parent / "extraction_prompt.txt"


class GeminiInvoiceScanner:
    """Wrapper for Gemini API invoice extraction using the new google-genai SDK"""

    MODEL_ID = os.environ.get("GEMINI_MODEL_ID", "gemini-2.0-flash")
    _GENERATION_CONFIG = types.GenerateContentConfig(
        responseMimeType="application/json",
        temperature=0.1,
    )
    _MIME_TYPE_ALIASES = {
        "image/jpg": "image/jpeg",
        "image/pjpeg": "image/jpeg",
    }

    def __init__(self, api_key: str):
        """Initialize the Gemini client with API key"""
        self.client = genai.Client(api_key=api_key)

    def scan_invoice(self, file_bytes: bytes, file_type: str) -> Dict[str, Any]:
        """
        Extract structured data from invoice image or PDF.

        Args:
            file_bytes: Raw file content
            file_type: MIME type (image/jpeg, image/png, application/pdf)

        Returns:
            Dict with extracted invoice data and confidence scores
        """
        prompt = self._build_extraction_prompt()
        normalized_type = self._normalize_mime_type(file_type)

        try:
            logger.info(f"Scanning invoice with Gemini {self.MODEL_ID}")

            response = self.client.models.generate_content(
                model=self.MODEL_ID,
                contents=[
                    types.Part.from_bytes(
                        data=file_bytes,
                        mime_type=normalized_type,
                    ),
                    prompt,
                ],
                config=self._GENERATION_CONFIG,
            )

            logger.info("=" * 60)
            logger.info("GEMINI RAW RESPONSE:")
            logger.info("=" * 60)
            logger.info(response.text)
            logger.info("=" * 60)

            result = self._parse_response(response.text)
            line_items = result.get("lineItems")
            if not isinstance(line_items, list):
                logger.warning("lineItems is not a list; defaulting to empty list")
                line_items = []
                result["lineItems"] = line_items

            logger.info("EXTRACTED LINE ITEMS:")
            for i, item in enumerate(line_items):
                if not isinstance(item, dict):
                    logger.warning("Line item %s is not an object; skipping", i + 1)
                    continue
                name_data = item.get("name", {})
                name = (
                    name_data.get("value", "N/A") if isinstance(name_data, dict) else name_data
                )
                qty_data = item.get("quantity", {})
                qty = (
                    qty_data.get("value", "N/A") if isinstance(qty_data, dict) else qty_data
                )
                logger.info("  Item %s: name='%s', qty=%s", i + 1, name, qty)
            logger.info("=" * 60)

            return result

        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            raise

    def _build_extraction_prompt(self) -> str:
        """
        Load the extraction prompt from external file.

        The prompt can be customized by editing:
        invoice_scanner/extraction_prompt.txt
        """
        try:
            logger.info(f"Looking for prompt file at: {PROMPT_FILE}")
            logger.info(f"File exists: {PROMPT_FILE.exists()}")

            if PROMPT_FILE.exists():
                prompt = PROMPT_FILE.read_text(encoding='utf-8')
                logger.info(f"Loaded extraction prompt from {PROMPT_FILE} ({len(prompt)} chars)")
                logger.info(f"Prompt starts with: {prompt[:200]}...")
                return prompt
            else:
                logger.warning(f"Prompt file not found at {PROMPT_FILE}, using default")
                return self._default_prompt()
        except Exception as e:
            logger.error(f"Error loading prompt file: {e}, using default")
            return self._default_prompt()

    def _default_prompt(self) -> str:
        """Fallback default prompt if file cannot be loaded"""
        return """
Analyze this invoice image/PDF and extract the following information in JSON format.
For each field, also provide a confidence score between 0 and 1 based on how clearly you can read it.

Extract:
1. Supplier/Vendor name (the company sending the invoice)
2. Invoice number
3. Invoice date (in ISO 8601 format: YYYY-MM-DD)
4. Currency (GBP, USD, EUR, etc.)
5. Total amount (the final amount to pay)
6. Shipping/delivery costs (if listed separately, otherwise 0)
7. Line items: For each product/item, extract:
   - Product name/description (clean it up, remove codes if there's a clear name)
   - Quantity (as a number)
   - Unit price
   - Line total

Return ONLY valid JSON in this exact format (no markdown, no explanation):
{
    "supplier": {"value": "Company Name Ltd", "confidence": 0.95},
    "invoiceNumber": {"value": "INV-2024-0892", "confidence": 0.98},
    "invoiceDate": {"value": "2024-12-15", "confidence": 0.90},
    "currency": {"value": "GBP", "confidence": 0.99},
    "totalAmount": {"value": 495.00, "confidence": 0.95},
    "shippingAmount": {"value": 12.50, "confidence": 0.80},
    "lineItems": [
        {
            "name": {"value": "Vitamin B12 1000mcg", "confidence": 0.85},
            "quantity": {"value": 50, "confidence": 0.95},
            "unitCost": {"value": 2.40, "confidence": 0.90},
            "totalCost": {"value": 120.00, "confidence": 0.92}
        }
    ]
}

Important rules:
- If you cannot read or are uncertain about a field, use a low confidence score (below 0.5)
- For quantities, always return integers
- For amounts, return numbers (not strings), use 2 decimal places
- Parse dates carefully - UK invoices use DD/MM/YYYY format, convert to YYYY-MM-DD
- For product names, use the clearest/most descriptive name available
- If there are no shipping costs visible, use 0
- Currency should be the 3-letter code (GBP, USD, EUR)
- "Delivery Charge", "Shipping", "Postage" go in shippingAmount, NOT as line items
"""

    def _parse_response(self, response_text: str) -> Dict[str, Any]:
        """Parse and validate Gemini response."""
        try:
            data = parse_invoice_response(response_text or "")
        except ValueError as exc:
            logger.error("Failed to parse Gemini response: %s", exc)
            logger.error("Response was: %s", (response_text or "")[:500])
            raise

        required_fields = [
            "supplier",
            "invoiceNumber",
            "invoiceDate",
            "currency",
            "totalAmount",
            "lineItems",
        ]
        for field in required_fields:
            if field not in data:
                logger.warning("Missing required field in Gemini response: %s", field)

        return data

    def _normalize_mime_type(self, mime_type: str) -> str:
        if not mime_type:
            return mime_type
        return self._MIME_TYPE_ALIASES.get(mime_type.lower(), mime_type)
