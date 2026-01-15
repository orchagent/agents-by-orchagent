"""FastAPI application for security review orchestrator."""

import logging
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .models import (
    ReviewRequest,
    ReviewResponse,
    FindingsCollection,
    ReviewSummary,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Security Review",
    description="Comprehensive security review combining secret scanning, dependency auditing, and code pattern analysis",
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


@app.post("/review", response_model=ReviewResponse)
async def review(request: ReviewRequest) -> ReviewResponse:
    """
    Perform a comprehensive security review of a repository.

    - **repo_url**: URL of the git repository to review
    - **scan_mode**: What to scan (full, secrets-only, deps-only, patterns-only)
    """
    try:
        logger.info(f"Reviewing repository: {request.repo_url} (mode: {request.scan_mode})")

        # Stub implementation - returns empty results
        # Actual implementation in SR-003+ will call leak-finder, dep-scanner,
        # and run internal pattern scanners

        return ReviewResponse(
            scan_id=str(uuid.uuid4()),
            findings=FindingsCollection(),
            summary=ReviewSummary(),
            recommendations=[],
        )

    except Exception as e:
        logger.error(f"Review failed: {e}")
        raise HTTPException(status_code=500, detail=f"Review failed: {str(e)}")
