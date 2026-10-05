"""Groq provider (OpenAI-compatible)."""
import logging

from ai.providers.openai_compat import OpenAICompatProvider

logger = logging.getLogger(__name__)


class GroqProvider(OpenAICompatProvider):
    name = "groq"

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        super().__init__(api_key, model)

    def _create_client(self):
        from groq import Groq
        logger.info("Groq client ready (%s)", self.model)
        return Groq(api_key=self.api_key)