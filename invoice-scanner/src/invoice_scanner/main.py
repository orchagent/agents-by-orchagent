import os
from fastapi import FastAPI, UploadFile, HTTPException
from .gemini_client import GeminiInvoiceScanner

ALLOWED_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/jpg",
    "image/png",
}

app = FastAPI(
    title="Invoice Scanner",
    description="Extracts structured invoice data using the same prompt as OSO-stock",
    version="0.1.0",
)

api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    raise RuntimeError("GEMINI_API_KEY environment variable is required")

scanner = GeminiInvoiceScanner(api_key)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/scan")
async def scan(file: UploadFile):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected")

    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: PDF, JPEG, PNG. Got: {file.content_type}",
        )

    contents = await file.read()
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    try:
        return scanner.scan_invoice(contents, file.content_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
