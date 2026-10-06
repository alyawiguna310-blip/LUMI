"""Assistant orchestrator: user text -> LLM (tool-capable) -> response -> TTS."""
import logging
import threading

from ai.provider import ChatMessage, LLMProvider
from ai.prompts import LUMI_SYSTEM_PROMPT
from config import config
from core.events import EventBus
from core.memory import ConversationMemory
from core.state import LumiState, StateManager

logger = logging.getLogger(__name__)

MAX_TOOL_ROUNDS = 5


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

    def _worker(self, user_text: str) -> None:
        try:
            if not self.provider.is_available():
                raise RuntimeError(
                    "I can't reach my brain right now. "
                    "Check GEMINI_API_KEY or HF_TOKEN."
                )

            self.state_manager.transition(LumiState.THINKING)
            self.memory.add(ChatMessage(role="user", content=user_text))

            # Working set for THIS turn (does not persist across turns)
            turn_messages: list[ChatMessage] = [
                ChatMessage(role="system", content=LUMI_SYSTEM_PROMPT)
            ]
            turn_messages.extend(self.memory.get_all())

            final_text: str | None = None

            for round_num in range(MAX_TOOL_ROUNDS):
                response = self.provider.chat(
                    turn_messages, max_tokens=config.MAX_RESPONSE_TOKENS
                )

                if not response.tool_calls:
                    final_text = response.text or "..."
                    break

                if self.tool_router is None:
                    logger.error("Tool calls requested but no router configured.")
                    final_text = "...I wanted to use a tool but I'm not set up for that."
                    break

                # Append the assistant's tool-call message
                turn_messages.append(ChatMessage(
                    role="assistant",
                    content=response.text or "",
                    tool_calls=response.tool_calls,
                    source_provider=response.source_provider,
                    raw_parts=response.raw_parts,
                ))

                # Execute each tool through the router
                for tc in response.tool_calls:
                    logger.info("Tool call: %s(%r)", tc.name, tc.arguments)
                    self.event_bus.emit("tool_call_requested",
                                        name=tc.name, arguments=tc.arguments)
                    result = self.tool_router.route(tc.name, tc.arguments)
                    logger.info("Tool result: %s", result)
                    self.event_bus.emit("tool_call_completed",
                                        name=tc.name, result=result)
                    turn_messages.append(ChatMessage(
                        role="tool",
                        tool_call_id=tc.id,
                        tool_name=tc.name,
                        tool_result=result,
                    ))
            else:
                logger.warning("Tool loop exhausted (%d rounds).", MAX_TOOL_ROUNDS)
                final_text = "...I got stuck trying to use a tool. Try rephrasing?"

            if not final_text:
                final_text = "..."

            # Persist only the final exchange in long-term memory
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