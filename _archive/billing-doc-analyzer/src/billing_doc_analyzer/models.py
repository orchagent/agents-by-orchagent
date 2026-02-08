from pydantic import BaseModel
from typing import Literal


class LineItem(BaseModel):
    description: str
    amount: float
    type: Literal["charge", "credit"] = "charge"


class DocumentAnalysis(BaseModel):
    """Response from billing document analysis."""
    # Provider info
    provider_name: str
    provider_slug: str  # lowercase, e.g. "british-gas"

    # Document classification
    document_type: Literal["bill", "letter", "email", "statement", "other"]
    document_date: str | None = None  # YYYY-MM-DD
    threat_level: Literal["info", "warning", "action_required", "legal"] = "info"
    summary: str  # One-liner, max 10 words

    # Bill/Invoice specific
    amount: float | None = None
    amount_type: Literal["charge", "credit", "payment", "balance"] | None = None
    currency: str | None = None  # ISO: GBP, USD, EUR
    due_date: str | None = None  # YYYY-MM-DD
    line_items: list[LineItem] = []

    # Letter specific
    letter_type: Literal["reminder", "demand", "confirmation", "legal", "notification", "other"] | None = None
    action_required: str | None = None
    deadline: str | None = None  # YYYY-MM-DD

    # General
    reference: str | None = None
    account_number: str | None = None
    key_points: list[str] = []
    raw_text: str = ""
