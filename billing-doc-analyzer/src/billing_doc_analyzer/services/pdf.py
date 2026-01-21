import pdfplumber
from io import BytesIO


async def extract_text_from_pdf(file_bytes: bytes) -> str:
    """Extract all text from a PDF file."""
    text_parts = []

    with pdfplumber.open(BytesIO(file_bytes)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)

    return "\n\n".join(text_parts)
