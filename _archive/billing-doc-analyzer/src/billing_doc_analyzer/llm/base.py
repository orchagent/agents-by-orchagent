from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def analyze_text(self, text: str, prompt: str) -> str:
        """Send text to LLM with a prompt, return the response."""
        pass
