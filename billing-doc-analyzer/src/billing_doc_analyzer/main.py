import os
from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .models import DocumentAnalysis
from .services import analyze_document
from .llm import GeminiProvider

app = FastAPI(
    title="Billing Doc Analyzer",
    description="Analyzes billing documents (bills, letters, emails) from service providers",
    version="0.1.0"
)

# CORS - allow BillSure origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite dev server
        "http://localhost:3000",
        "https://billsure-test.web.app",
        "https://billsure.web.app",
    ],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# Require GEMINI_API_KEY - fail fast if not set
if not os.environ.get("GEMINI_API_KEY"):
    raise RuntimeError("GEMINI_API_KEY environment variable is required")

llm_provider = GeminiProvider(model="gemini-2.5-flash")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/analyze", response_model=DocumentAnalysis)
async def analyze(file: UploadFile) -> DocumentAnalysis:
    """
    Analyze a billing document (PDF) and return structured data.

    - **file**: PDF file to analyze (bill, letter, statement, etc.)
    """
    if not file.filename or not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="File must be a PDF")

    contents = await file.read()

    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    result = await analyze_document(contents, llm_provider)
    return result
