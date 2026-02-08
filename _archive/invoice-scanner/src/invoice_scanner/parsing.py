import json
import re
from typing import Any, Dict

_FENCED_JSON_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)


def _extract_json_payload(text: str) -> str | None:
    if not text:
        return None

    candidate = text.strip()
    if not candidate:
        return None

    fenced_match = _FENCED_JSON_RE.search(candidate)
    if fenced_match:
        candidate = fenced_match.group(1).strip()
        if not candidate:
            return None

    decoder = json.JSONDecoder()
    for match in re.finditer(r"[\[{]", candidate):
        start = match.start()
        snippet = candidate[start:]
        try:
            _, end = decoder.raw_decode(snippet)
            return snippet[:end]
        except json.JSONDecodeError:
            continue

    return None


def parse_invoice_response(response_text: str) -> Dict[str, Any]:
    if not response_text or not response_text.strip():
        raise ValueError("Empty response from Gemini")

    payload = _extract_json_payload(response_text)
    if payload is None:
        raise ValueError("No JSON object found in Gemini response")

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON response from Gemini: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Gemini response JSON must be an object")

    if "lineItems" in data:
        line_items = data.get("lineItems")
        if line_items is None or not isinstance(line_items, list):
            data["lineItems"] = []

    return data
