"""LLM-based analysis to validate findings and reduce false positives."""

import json
import os
from pathlib import Path

import google.generativeai as genai

from .models import Finding


# Load the analysis prompt
PROMPTS_DIR = Path(__file__).parent / "prompts"


def get_analysis_prompt() -> str:
    """Load the analysis prompt from file."""
    prompt_file = PROMPTS_DIR / "analysis.txt"
    if prompt_file.exists():
        return prompt_file.read_text()
    # Fallback prompt if file doesn't exist
    return """You are a security expert analyzing potential secret/credential findings.
For each finding, determine if it's a true positive or false positive.

Respond with a JSON array of objects, each with:
- "index": the finding index (0-based)
- "is_secret": true if this is a real secret, false if it's a false positive
- "confidence": your confidence score from 0.0 to 1.0
- "reason": brief explanation of your decision

Common false positives:
- Example/placeholder values in documentation
- Test fixtures with fake credentials
- Environment variable references (not actual values)
- Hash values that aren't secrets
- Public keys (only private keys are secrets)
"""


async def validate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Use Gemini to validate findings and filter out false positives.

    Args:
        findings: List of findings to validate

    Returns:
        Filtered list of findings with confidence scores
    """
    if not findings:
        return []

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        # Return findings unchanged if no API key
        return findings

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        generation_config = genai.GenerationConfig(
            response_mime_type="application/json",
            temperature=0.1,
        )

        # Build the prompt with findings
        prompt = get_analysis_prompt()
        findings_text = "\n".join([
            f"{i}. Type: {f.type}, File: {f.file}, Line: {f.line}, Preview: {f.preview}"
            for i, f in enumerate(findings)
        ])
        full_prompt = f"{prompt}\n\nFindings to analyze:\n{findings_text}"

        # Call Gemini
        response = await model.generate_content_async(
            full_prompt,
            generation_config=generation_config
        )

        # Parse response
        try:
            validations = json.loads(response.text)
        except json.JSONDecodeError:
            # If parsing fails, return original findings
            return findings

        # Filter findings based on LLM validation
        validated_findings = []
        for validation in validations:
            idx = validation.get("index", -1)
            is_secret = validation.get("is_secret", True)
            confidence = validation.get("confidence", 1.0)

            if 0 <= idx < len(findings) and is_secret and confidence >= 0.5:
                finding = findings[idx]
                # Add confidence to recommendation
                finding.recommendation = f"[Confidence: {confidence:.0%}] {finding.recommendation}"
                validated_findings.append(finding)

        return validated_findings

    except Exception:
        # On any error, return original findings
        return findings


def validate_findings_sync(findings: list[Finding]) -> list[Finding]:
    """
    Synchronous wrapper for validate_findings.

    Args:
        findings: List of findings to validate

    Returns:
        Filtered list of findings
    """
    import asyncio
    return asyncio.run(validate_findings(findings))
