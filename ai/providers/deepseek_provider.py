"""DeepSeek provider (OpenAI SDK, different base_url)."""
import logging

from ai.providers.openai_compat import OpenAICompatProvider

logger = logging.getLogger(__name__)


class DeepSeekProvider(OpenAICompatProvider):
    name = "deepseek"

    def __init__(self, api_key: str,
                 model: str = "deepseek-chat",
                 base_url: str = "https://api.deepseek.com"):
        self.base_url = base_url
        super().__init__(api_key, model)

    def _create_client(self):
        from openai import OpenAI
        logger.info("DeepSeek client ready (%s @ %s)", self.model, self.base_url)
        return OpenAI(api_key=self.api_key, base_url=self.base_url)