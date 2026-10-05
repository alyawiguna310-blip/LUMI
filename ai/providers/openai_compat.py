"""
Base class for providers whose SDK mirrors OpenAI's chat.completions API:
  - OpenAI
  - Groq
  - DeepSeek (via openai SDK with base_url)
  - HuggingFace InferenceClient
"""
import json
import logging
from typing import Any

from ai.provider import ChatMessage, ChatResponse, ToolCall, LLMProvider
from ai.tool_schema import to_openai_tools

logger = logging.getLogger(__name__)


def _strip_none(d: dict) -> dict:
    """Remove keys whose value is None. Groq's schema validator rejects null."""
    if not isinstance(d, dict):
        return d or {}
    return {k: v for k, v in d.items() if v is not None}


class OpenAICompatProvider(LLMProvider):
    supports_tools_flag: bool = True

    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
        self._client = None
        if api_key:
            try:
                self._client = self._create_client()
            except Exception:
                logger.exception("%s: failed to create client", self.name)
                self._client = None

    def _create_client(self):
        raise NotImplementedError

    def is_available(self) -> bool:
        return self._client is not None

    def supports_tools(self) -> bool:
        return self.supports_tools_flag and self._client is not None

    # ---------- request building ----------

    def _build_messages(self, messages: list[ChatMessage]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m.role == "system":
                out.append({"role": "system", "content": m.content or ""})

            elif m.role == "user":
                out.append({"role": "user", "content": m.content or ""})

            elif m.role == "assistant":
                msg: dict[str, Any] = {
                    "role": "assistant",
                    "content": m.content or "",
                }
                if m.tool_calls:
                    tool_calls_payload = []
                    for i, tc in enumerate(m.tool_calls):
                        args = _strip_none(tc.arguments or {})
                        tool_calls_payload.append({
                            "id": tc.id or f"call_{i}",
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(args),
                            },
                        })
                    msg["tool_calls"] = tool_calls_payload
                out.append(msg)

            elif m.role == "tool":
                out.append({
                    "role": "tool",
                    "tool_call_id": m.tool_call_id or "call_0",
                    "content": json.dumps(m.tool_result or {}, default=str),
                })

            else:
                logger.warning("%s: unknown role %r; skipping", self.name, m.role)
        return out

    # ---------- response parsing ----------

    def _parse_response(self, completion) -> ChatResponse:
        text = ""
        tool_calls: list[ToolCall] = []

        try:
            choice = completion.choices[0]
            msg = choice.message

            text = (getattr(msg, "content", None) or "").strip()

            raw_tcs = getattr(msg, "tool_calls", None) or []
            for tc in raw_tcs:
                fn = getattr(tc, "function", None)
                if fn is None:
                    continue
                name = getattr(fn, "name", "") or ""
                raw_args = getattr(fn, "arguments", "") or "{}"
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                except Exception:
                    logger.warning("%s: bad tool_call arguments %r", self.name, raw_args)
                    args = {}
                # Strip nulls from incoming args too, so our own parse
                # and any replay never see nulls
                args = _strip_none(args)
                tool_calls.append(ToolCall(
                    name=name,
                    arguments=args,
                    id=getattr(tc, "id", "") or "",
                ))
        except (AttributeError, IndexError):
            logger.exception("%s: malformed completion", self.name)

        return ChatResponse(text=text, tool_calls=tool_calls, raw=completion)

    # ---------- chat ----------

    def chat(self, messages: list[ChatMessage], max_tokens: int = 300) -> ChatResponse:
        if self._client is None:
            raise RuntimeError(f"{self.name}: client not initialized")

        payload = self._build_messages(messages)

        kwargs = {
            "model": self.model,
            "messages": payload,
            "max_tokens": max_tokens,
            "temperature": 0.85,
            "top_p": 0.95,
        }
        if self.supports_tools():
            kwargs["tools"] = to_openai_tools()
            kwargs["tool_choice"] = "auto"

        try:
            completion = self._client.chat.completions.create(**kwargs)
        except TypeError:
            # Older SDK — drop tool_choice and retry
            kwargs.pop("tool_choice", None)
            completion = self._client.chat.completions.create(**kwargs)

        return self._parse_response(completion)