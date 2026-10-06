"""Google Gemini provider using the official google-genai SDK. Tool-capable."""
import logging
import time

from google import genai
from google.genai import types

from ai.provider import ChatMessage, ChatResponse, LLMProvider
from ai.tool_schema import to_gemini_tool, extract_tool_calls

logger = logging.getLogger(__name__)


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self, api_key: str, model: str, enable_tools: bool = True):
        self.api_key = api_key
        self.model = model
        self._client: genai.Client | None = None
        self._tools = None

        if not api_key:
            logger.warning("GeminiProvider: no API key provided; disabled.")
            return

        try:
            self._client = genai.Client(api_key=api_key)
        except Exception:
            logger.exception("Failed to create Gemini client")
            self._client = None
            return

        if enable_tools:
            try:
                self._tools = to_gemini_tool()
                logger.info("Gemini tool calling enabled.")
            except Exception:
                logger.exception("Failed to build Gemini tool declarations")
                self._tools = None

    def is_available(self) -> bool:
        return self._client is not None

    def supports_tools(self) -> bool:
        return self._tools is not None

    # ---------- chat ----------

    def chat(self, messages: list[ChatMessage], max_tokens: int = 300) -> ChatResponse:
        if self._client is None:
            raise RuntimeError("Gemini client is not initialized.")

        system_instruction: str | None = None
        contents: list[types.Content] = []

        for m in messages:
            if m.role == "system":
                system_instruction = (system_instruction + "\n\n" + m.content) if system_instruction else m.content

            elif m.role == "user":
                contents.append(types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=m.content)],
                ))

            elif m.role == "assistant":
                if m.raw_parts and m.source_provider == "gemini":
                    contents.append(types.Content(role="model", parts=list(m.raw_parts)))
                    continue
                parts = []
                if m.content:
                    parts.append(types.Part.from_text(text=m.content))
                for tc in m.tool_calls:
                    parts.append(types.Part.from_function_call(
                        name=tc.name, args=tc.arguments,
                    ))
                if not parts:
                    parts = [types.Part.from_text(text="")]
                contents.append(types.Content(role="model", parts=parts))

            elif m.role == "tool":
                # Keep the function-call ID even on google-genai versions where
                # Part.from_function_response() does not accept an id argument.
                function_response = types.FunctionResponse(
                    name=m.tool_name,
                    response=m.tool_result,
                    id=m.tool_call_id or None,
                )
                contents.append(types.Content(
                    role="tool",
                    parts=[types.Part(function_response=function_response)],
                ))
            else:
                logger.warning("Unknown role %r; skipping.", m.role)

        # Gemini 3.x uses thinking_level, not the legacy thinking_budget.
        # Gemini 3.x also recommends leaving temperature/top_p at their defaults.
        # Gemini 2.5 still uses thinking_budget, so keep compatibility for it.
        kwargs = dict(
            max_output_tokens=max_tokens,
            system_instruction=system_instruction,
        )

        model_lower = self.model.lower()
        try:
            if model_lower.startswith("gemini-3"):
                kwargs["thinking_config"] = types.ThinkingConfig(
                    thinking_level="minimal"
                )
            elif model_lower.startswith("gemini-2.5"):
                kwargs["thinking_config"] = types.ThinkingConfig(
                    thinking_budget=0
                )
            else:
                # Older/other Gemini models may still accept the classic
                # sampling controls.
                kwargs["temperature"] = 0.85
                kwargs["top_p"] = 0.95
        except Exception:
            logger.warning(
                "Could not configure Gemini thinking for model %s; "
                "using model defaults.",
                self.model,
            )
        if self._tools is not None:
            kwargs["tools"] = [self._tools]

        try:
            gen_config = types.GenerateContentConfig(**kwargs)
        except TypeError:
            kwargs.pop("thinking_config", None)
            gen_config = types.GenerateContentConfig(**kwargs)

        delays = [0.0, 0.5, 1.5, 3.0]
        last_error: Exception | None = None

        for attempt, delay in enumerate(delays, start=1):
            if delay > 0:
                logger.warning("Gemini busy; retrying in %.1fs (%d/%d)...",
                               delay, attempt, len(delays))
                time.sleep(delay)
            try:
                response = self._client.models.generate_content(
                    model=self.model, contents=contents, config=gen_config,
                )
            except Exception as e:
                last_error = e
                msg = str(e)
                retryable = ("503" in msg) or ("UNAVAILABLE" in msg) or ("overloaded" in msg.lower())
                if retryable:
                    continue
                raise RuntimeError(f"Gemini request failed: {e}") from e

            tool_calls = extract_tool_calls(response)
            text = self._extract_text(response)
            raw_parts = self._extract_raw_parts(response)

            return ChatResponse(
                text=text or "",
                tool_calls=tool_calls,
                raw_parts=raw_parts,
                raw=response,
                source_provider=self.name,
            )

        raise RuntimeError("Gemini is overloaded right now. Try again in a few seconds.") from last_error

    # ---------- helpers ----------

    @staticmethod
    def _extract_text(response) -> str:
        try:
            t = (getattr(response, "text", "") or "").strip()
            if t:
                return t
        except Exception:
            pass
        try:
            parts_text = []
            for cand in getattr(response, "candidates", []) or []:
                content = getattr(cand, "content", None)
                if content is None:
                    continue
                for part in getattr(content, "parts", []) or []:
                    if getattr(part, "thought", False):
                        continue
                    if getattr(part, "function_call", None) is not None:
                        continue
                    pt = getattr(part, "text", None)
                    if pt:
                        parts_text.append(pt)
            return "".join(parts_text).strip()
        except Exception:
            logger.exception("Failed to extract text from Gemini response")
            return ""

    @staticmethod
    def _extract_raw_parts(response) -> list:
        try:
            cands = getattr(response, "candidates", None) or []
            if not cands:
                return []
            content = getattr(cands[0], "content", None)
            if content is None:
                return []
            return list(getattr(content, "parts", None) or [])
        except Exception:
            logger.exception("Failed to extract raw parts")
            return []