#!/usr/bin/env python3
"""Sandbox entrypoint for billing-doc-analyzer."""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from billing_doc_analyzer.services import analyze_document
from billing_doc_analyzer.llm import GeminiProvider


def main():
    # Read JSON from stdin
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(1)

    # Get file from manifest
    files = input_data.get("files", [])
    if not files:
        print(json.dumps({"error": "No files provided"}))
        sys.exit(1)

    file_info = files[0]
    file_path = Path(file_info["path"])
    content_type = file_info.get("content_type", "application/octet-stream")
    original_name = file_info.get("original_name", "")

    # Validate
    if not file_path.exists():
        print(json.dumps({"error": f"File not found: {file_path}"}))
        sys.exit(1)

    # Process
    try:
        file_bytes = file_path.read_bytes()
        if not file_bytes:
            print(json.dumps({"error": "Empty file"}))
            sys.exit(1)

        looks_like_pdf = file_bytes[:1024].lstrip().startswith(b"%PDF")
        if (
            content_type != "application/pdf"
            and not looks_like_pdf
            and not original_name.lower().endswith(".pdf")
        ):
            print(json.dumps({"error": f"Expected PDF, got: {content_type}"}))
            sys.exit(1)

        llm = GeminiProvider()  # Reads GEMINI_API_KEY from env
        result = asyncio.run(analyze_document(file_bytes, llm))
        print(json.dumps(result.model_dump()))

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
