"""Hugging Face InferenceClient provider (OpenAI-compatible chat)."""
import json
import logging
from typing import Any

from ai.provider import ChatMessage, ChatResponse, ToolCall, LLMProvider
from ai.tool_schema import to_openai_tools

logger = logging.getLogger(__name__)


class HuggingFaceProvider(LLMProvider):
    name = "huggingface"

    def __init__(self, token: str, model: str):
        self.token = token
        self.model = model
        self._client = None
        if token:
            try:
                from huggingface_hub import InferenceClient
                self._client = InferenceClient(token=token)
                logger.info("HuggingFace client ready (%s)", model)
            except Exception:
                logger.exception("Failed to create HF client")
                self._client = None

    def is_available(self) -> bool:
        return self._client is not None

    def supports_tools(self) -> bool:
        return self._client is not None

    # ---------- message translation ----------

    def _build_messages(self, messages: list[ChatMessage]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m.role in ("system", "user"):
                out.append({"role": m.role, "content": m.content or ""})
            elif m.role == "assistant":
                msg: dict[str, Any] = {"role": "assistant", "content": m.content or ""}
                if m.tool_calls:
                    msg["tool_calls"] = [
                        {
                            "id": tc.id or f"call_{i}",
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(tc.arguments or {}),
                            },
                        }
                        for i, tc in enumerate(m.tool_calls)
                    ]
                out.append(msg)
            elif m.role == "tool":
                out.append({
                    "role": "tool",
                    "tool_call_id": m.tool_call_id or "call_0",
                    "content": json.dumps(m.tool_result or {}, default=str),
                })
        return out

    # ---------- chat ----------

    def chat(self, messages: list[ChatMessage], max_tokens: int = 300) -> ChatResponse:
        if self._client is None:
            raise RuntimeError("HuggingFace client not initialized")

        payload = self._build_messages(messages)

        try:
            completion = self._client.chat_completion(
                messages=payload,
                model=self.model,
                max_tokens=max_tokens,
                temperature=0.85,
                top_p=0.95,
                tools=to_openai_tools(),
                tool_choice="auto",
            )
        except TypeError:
            # Older client without tool support — retry without tools
            completion = self._client.chat_completion(
                messages=payload,
                model=self.model,
                max_tokens=max_tokens,
                temperature=0.85,
                top_p=0.95,
            )

        text = ""
        tool_calls: list[ToolCall] = []
        try:
            msg = completion.choices[0].message
            text = (getattr(msg, "content", None) or "").strip()
            for tc in (getattr(msg, "tool_calls", None) or []):
                fn = getattr(tc, "function", None)
                if fn is None:
                    continue
                name = getattr(fn, "name", "") or ""
                raw_args = getattr(fn, "arguments", "") or "{}"
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                except Exception:
                    args = {}
                tool_calls.append(ToolCall(
                    name=name, arguments=args,
                    id=getattr(tc, "id", "") or "",
                ))
        except Exception:
            logger.exception("HF response parse failed")

        return ChatResponse(text=text, tool_calls=tool_calls, raw=completion)