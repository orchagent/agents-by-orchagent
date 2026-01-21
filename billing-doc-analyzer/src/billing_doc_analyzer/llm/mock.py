import json
from .base import LLMProvider


class MockLLMProvider(LLMProvider):
    """Mock LLM for development and testing."""

    async def analyze_text(self, text: str, prompt: str) -> str:
        """Return a mock analysis based on simple keyword detection."""
        text_lower = text.lower()

        # Simple keyword-based mock analysis
        total = None
        if "$" in text:
            # Try to find a dollar amount
            import re
            amounts = re.findall(r'\$[\d,]+\.?\d*', text)
            if amounts:
                total = float(amounts[0].replace('$', '').replace(',', ''))

        legal_issues = []
        if any(word in text_lower for word in ['late fee', 'penalty', 'termination']):
            legal_issues.append("Potential fee or penalty clause detected")

        return json.dumps({
            "summary": f"Mock analysis of document ({len(text)} chars)",
            "total_amount": total,
            "due_date": None,
            "vendor": "Unknown (mock)",
            "legal_issue_detected": len(legal_issues) > 0,
            "legal_issues": legal_issues
        })
