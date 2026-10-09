"""Assistant orchestrator: user text -> LLM (tool-capable) -> response -> TTS."""
import hashlib
import json
import logging
import threading

from ai.provider import ChatMessage, LLMProvider
from ai.prompts import LUMI_SYSTEM_PROMPT
from config import config
from core.events import EventBus
from core.memory import ConversationMemory
from core.state import LumiState, StateManager

logger = logging.getLogger(__name__)


class Assistant:
    def __init__(
        self,
        provider: LLMProvider,
        memory: ConversationMemory,
        state_manager: StateManager,
        event_bus: EventBus,
        tts=None,
        tts_voice: str | None = None,
        tool_router=None,
    ):
        self.provider = provider
        self.memory = memory
        self.state_manager = state_manager
        self.event_bus = event_bus
        self.tts = tts
        self.tts_voice = tts_voice
        self.tool_router = tool_router
        self._busy = threading.Lock()

    # ---------- Public ----------

    def send(self, user_text: str) -> None:
        user_text = (user_text or "").strip()
        if not user_text:
            return
        if not self._busy.acquire(blocking=False):
            self.event_bus.emit("assistant_error",
                                message="Hold on, I'm still thinking.")
            return
        threading.Thread(target=self._worker, args=(user_text,), daemon=True).start()

    def reset(self) -> None:
        self.memory.clear()

    def stop_speaking(self) -> None:
        if self.tts is not None:
            self.tts.stop()

    # ---------- Worker ----------

    @staticmethod
    def _tool_call_key(name: str, arguments: dict) -> str:
        """Stable per-turn fingerprint used only to stop exact repeated calls."""
        payload = json.dumps(
            {"name": name, "arguments": arguments},
            sort_keys=True, separators=(",", ":"), default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _result_status(result) -> str:
        if not isinstance(result, dict):
            return "unknown"
        if result.get("status"):
            return str(result["status"])
        if result.get("ok") is True:
            return "ok"
        if result.get("ok") is False:
            return "denied" if result.get("denied") else "error"
        return "unknown"

    def _worker(self, user_text: str) -> None:
        try:
            if not self.provider.is_available():
                raise RuntimeError(
                    "I can't reach my brain right now. "
                    "Check your configured AI provider credentials."
                )

            self.state_manager.transition(LumiState.THINKING)
            self.memory.add(ChatMessage(role="user", content=user_text))

            # Working set for THIS turn (does not persist across turns).
            turn_messages: list[ChatMessage] = [
                ChatMessage(role="system", content=LUMI_SYSTEM_PROMPT)
            ]
            turn_messages.extend(self.memory.get_all())

            final_text: str | None = None
            seen_tool_calls: set[str] = set()
            max_tool_rounds = config.MAX_TOOL_ROUNDS

            # Allow one additional model request after the last permitted tool
            # round, so the model can interpret the final tool result.
            for round_index in range(max_tool_rounds + 1):
                response = self.provider.chat(
                    turn_messages, max_tokens=config.MAX_RESPONSE_TOKENS
                )
                provider_name = (
                    getattr(response, "source_provider", "")
                    or getattr(self.provider, "name", "unknown")
                )

                if not response.tool_calls:
                    final_text = response.text or "..."
                    logger.info(
                        "Assistant turn completed: provider=%s rounds=%d reason=final_answer",
                        provider_name, round_index,
                    )
                    break

                # If the model still asks for tools after the permitted number
                # of tool rounds, stop without executing an extra operation.
                if round_index >= max_tool_rounds:
                    logger.warning(
                        "Assistant tool loop stopped: provider=%s rounds=%d reason=round_limit",
                        provider_name, max_tool_rounds,
                    )
                    final_text = (
                        response.text.strip()
                        if response.text and response.text.strip()
                        else "I reached the tool-call limit before I could finish. "
                             "No additional tool calls were executed."
                    )
                    break

                if self.tool_router is None:
                    logger.error(
                        "Assistant tool loop stopped: provider=%s reason=no_tool_router",
                        provider_name,
                    )
                    final_text = (
                        response.text.strip()
                        if response.text and response.text.strip()
                        else "I wanted to use a tool, but tools aren't configured."
                    )
                    break

                # Ensure every call has a stable ID shared by the assistant
                # tool-call message and its corresponding result message.
                for call_index, tc in enumerate(response.tool_calls):
                    if not tc.id:
                        tc.id = f"lumi_{round_index}_{call_index}"

                turn_messages.append(ChatMessage(
                    role="assistant",
                    content=response.text or "",
                    tool_calls=response.tool_calls,
                    source_provider=provider_name,
                    raw_parts=response.raw_parts,
                ))

                for tc in response.tool_calls:
                    call_key = self._tool_call_key(tc.name, tc.arguments or {})
                    if call_key in seen_tool_calls:
                        result = {
                            "ok": False,
                            "status": "repeated_call_blocked",
                            "error": (
                                "This exact tool call already ran during this turn. "
                                "Use the previous result or choose a different operation."
                            ),
                        }
                        logger.warning(
                            "Tool round=%d provider=%s name=%s status=repeated_call_blocked",
                            round_index + 1, provider_name, tc.name,
                        )
                    else:
                        seen_tool_calls.add(call_key)
                        logger.info(
                            "Tool round=%d provider=%s name=%s status=executing",
                            round_index + 1, provider_name, tc.name,
                        )
                        self.event_bus.emit(
                            "tool_call_requested",
                            name=tc.name, arguments=tc.arguments,
                        )
                        try:
                            # All execution continues through the existing
                            # security-aware router; no approval is bypassed.
                            result = self.tool_router.route(tc.name, tc.arguments)
                        except Exception as exc:
                            logger.exception(
                                "Tool round=%d provider=%s name=%s status=exception",
                                round_index + 1, provider_name, tc.name,
                            )
                            result = {
                                "ok": False,
                                "status": "error",
                                "error": f"{type(exc).__name__}: {exc}",
                            }

                    status = self._result_status(result)
                    logger.info(
                        "Tool round=%d provider=%s name=%s status=%s",
                        round_index + 1, provider_name, tc.name, status,
                    )
                    self.event_bus.emit(
                        "tool_call_completed", name=tc.name, result=result,
                    )
                    turn_messages.append(ChatMessage(
                        role="tool",
                        tool_call_id=tc.id,
                        tool_name=tc.name,
                        tool_result=result if isinstance(result, dict) else {
                            "ok": False,
                            "status": "error",
                            "error": str(result),
                        },
                    ))
            else:
                # Defensive fallback; the loop should terminate in a branch
                # above, but never return the old generic tool-loop error.
                logger.warning("Assistant tool loop stopped: reason=loop_fallback")
                final_text = "I couldn't safely finish that request within the tool-call limit."

            if not final_text:
                final_text = "..."

            # Persist only the final exchange in long-term memory.
            self.memory.add(ChatMessage(role="assistant", content=final_text))

            self.state_manager.transition(LumiState.SPEAKING)
            self.event_bus.emit("assistant_response", text=final_text)

            if self.tts is not None:
                try:
                    self.tts.speak(final_text, voice=self.tts_voice,
                                   speed=config.SPEECH_SPEED)
                except Exception:
                    logger.exception("TTS failed; continuing without voice.")

            self.state_manager.transition(LumiState.IDLE)

        except Exception as e:
            logger.exception("Assistant worker failed")
            try:
                if self.state_manager.state != LumiState.ERROR:
                    self.state_manager.transition(LumiState.ERROR)
            except Exception:
                pass
            self.event_bus.emit("assistant_error", message=str(e))
            try:
                self.state_manager.transition(LumiState.IDLE)
            except Exception:
                pass
        finally:
            self._busy.release()
