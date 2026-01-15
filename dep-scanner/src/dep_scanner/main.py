"""FastAPI application for dependency scanner."""

import logging
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .models import ScanRequest, ScanResponse, ScanSummary

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Dependency Scanner",
    description="Scans repositories for known vulnerabilities in dependencies",
    version="0.1.0",
)

# CORS - allow common development origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8000",
    ],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    """
    Scan a repository for dependency vulnerabilities.

    - **repo_url**: URL of the git repository to scan
    - **package_managers**: Optional list of package managers to scan
    - **severity_threshold**: Minimum severity to include (low/medium/high/critical)
    """
    try:
        logger.info(f"Scanning repository: {request.repo_url}")

        # TODO: Implement actual scanning logic in future stories
        # For now, return empty findings as a stub

        return ScanResponse(
            scan_id=str(uuid.uuid4()),
            detected_managers=[],
            findings=[],
            summary=ScanSummary(),
        )

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
