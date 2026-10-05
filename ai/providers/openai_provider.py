"""OpenAI / ChatGPT provider."""
import logging

from ai.providers.openai_compat import OpenAICompatProvider

logger = logging.getLogger(__name__)


class OpenAIProvider(OpenAICompatProvider):
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        super().__init__(api_key, model)

    def _create_client(self):
        from openai import OpenAI
        logger.info("OpenAI client ready (%s)", self.model)
        return OpenAI(api_key=self.api_key)