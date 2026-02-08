#!/usr/bin/env python3
"""
Sandbox entrypoint for invoice-scanner.

Reads file path from input.json, scans invoice, outputs JSON to stdout.
"""

import json
import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from invoice_scanner.gemini_client import GeminiInvoiceScanner

ALLOWED_TYPES = {
    "application/pdf": "application/pdf",
    "image/jpeg": "image/jpeg",
    "image/jpg": "image/jpeg",
    "image/png": "image/png",
}


def main():
    # Read input from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(1)

    # Get files from input
    files = input_data.get("files", [])
    if not files:
        print(json.dumps({"error": "No files provided. Expected 'files' array in input."}))
        sys.exit(1)

    file_info = files[0]
    file_path = Path(file_info["path"])
    content_type = file_info.get("content_type", "application/octet-stream")

    # Validate file exists
    if not file_path.exists():
        print(json.dumps({"error": f"File not found: {file_path}"}))
        sys.exit(1)

    # Validate content type
    if content_type not in ALLOWED_TYPES:
        print(json.dumps({
            "error": f"Invalid file type. Allowed: PDF, JPEG, PNG. Got: {content_type}"
        }))
        sys.exit(1)

    # Get API key from environment
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print(json.dumps({"error": "GEMINI_API_KEY environment variable is required"}))
        sys.exit(1)

    # Read file and scan
    try:
        file_bytes = file_path.read_bytes()
        if len(file_bytes) == 0:
            print(json.dumps({"error": "Empty file"}))
            sys.exit(1)

        scanner = GeminiInvoiceScanner(api_key)
        result = scanner.scan_invoice(file_bytes, ALLOWED_TYPES[content_type])
        print(json.dumps(result))

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
