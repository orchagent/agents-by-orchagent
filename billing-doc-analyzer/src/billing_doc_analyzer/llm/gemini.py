import os
from google import genai
from google.genai import types
from .base import LLMProvider


class GeminiProvider(LLMProvider):
    """Google Gemini LLM provider."""

    def __init__(self, model: str = "gemini-2.5-flash"):
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable not set")
        self.client = genai.Client(api_key=api_key)
        self.model_name = model
        self.generation_config = types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1,
        )

    async def analyze_text(self, text: str, prompt: str) -> str:
        """Send text to Gemini with a prompt, return the response."""
        full_prompt = f"{prompt}\n\nDocument text:\n{text}"
        response = await self.client.aio.models.generate_content(
            model=self.model_name,
            contents=full_prompt,
            config=self.generation_config,
        )
        return response.text
