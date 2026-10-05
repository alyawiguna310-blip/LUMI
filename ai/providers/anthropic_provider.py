"""
Anthropic Claude provider.

Anthropic's tool-use format differs from OpenAI:
  - tools use `input_schema` instead of `parameters`
  - assistant tool calls appear as `tool_use` content blocks (with `input` dict)
  - tool results appear as `tool_result` blocks inside a user message
  - `max_tokens` is required
"""
import json
import logging

from ai.provider import ChatMessage, ChatResponse, ToolCall, LLMProvider
from ai.tool_schema import to_anthropic_tools

logger = logging.getLogger(__name__)


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-latest"):
        self.api_key = api_key
        self.model = model
        self._client = None
        if api_key:
            try:
                from anthropic import Anthropic
                self._client = Anthropic(api_key=api_key)
                logger.info("Anthropic client ready (%s)", model)
            except Exception:
                logger.exception("Failed to create Anthropic client")
                self._client = None

    def is_available(self) -> bool:
        return self._client is not None

    def supports_tools(self) -> bool:
        return self._client is not None

    # ---------- message translation ----------

    def _build_request(self, messages: list[ChatMessage]):
        system_text = ""
        anth_messages: list[dict] = []

        for m in messages:
            if m.role == "system":
                system_text = (system_text + "\n\n" + m.content) if system_text else m.content

            elif m.role == "user":
                anth_messages.append({
                    "role": "user",
                    "content": m.content or "",
                })

            elif m.role == "assistant":
                content_blocks = []
                if m.content:
                    content_blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    content_blocks.append({
                        "type": "tool_use",
                        "id": tc.id or f"toolu_{len(content_blocks)}",
                        "name": tc.name,
                        "input": tc.arguments or {},
                    })
                if not content_blocks:
                    content_blocks = [{"type": "text", "text": ""}]
                anth_messages.append({"role": "assistant", "content": content_blocks})

            elif m.role == "tool":
                # Anthropic expects tool_result blocks inside a user message
                anth_messages.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": m.tool_call_id or "toolu_0",
                        "content": json.dumps(m.tool_result or {}, default=str),
                    }],
                })

        return system_text, anth_messages

    # ---------- chat ----------

    def chat(self, messages: list[ChatMessage], max_tokens: int = 300) -> ChatResponse:
        if self._client is None:
            raise RuntimeError("Anthropic client not initialized")

        system_text, anth_messages = self._build_request(messages)

        kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": anth_messages,
        }
        if system_text:
            kwargs["system"] = system_text
        if self.supports_tools():
            kwargs["tools"] = to_anthropic_tools()

        response = self._client.messages.create(**kwargs)

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []

        for block in getattr(response, "content", []) or []:
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(getattr(block, "text", "") or "")
            elif btype == "tool_use":
                tool_calls.append(ToolCall(
                    name=getattr(block, "name", "") or "",
                    arguments=dict(getattr(block, "input", {}) or {}),
                    id=getattr(block, "id", "") or "",
                ))

        return ChatResponse(
            text="".join(text_parts).strip(),
            tool_calls=tool_calls,
            raw=response,
        )