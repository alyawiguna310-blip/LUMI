"""Lumi entry point — multi-provider, security gate, tool calling, terminal, admin, install."""
import sys
import threading
import logging

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication

# --- AI / LLM ---
from ai.provider_manager import ProviderManager
from ai.providers.gemini_provider import GeminiProvider
from ai.providers.hf_provider import HuggingFaceProvider
from ai.providers.groq_provider import GroqProvider
from ai.providers.openai_provider import OpenAIProvider
from ai.providers.anthropic_provider import AnthropicProvider
from ai.providers.deepseek_provider import DeepSeekProvider
from ai.translator import Translator

# --- Core ---
from config import config
from core.assistant import Assistant
from core.events import bus
from core.memory import ConversationMemory
from core.state import LumiState, StateManager
from core.tool_router import ToolRouter

# --- Security ---
import security
from security.confirmation import ConfirmationManager
from security.gate import SecurityGate
from security.permissions import PermissionLevel, PermissionPolicy
from tools import filesystem as fs_tools
from tools import terminal as term_tools
from tools import applications as app_tools

# --- Storage ---
from storage.logs import setup_logging

# --- UI ---
from ui.confirmation_dialog import QtConfirmationBridge
from ui.minimal_window import MinimalWindow
from ui.tray import TrayIcon

# --- Voice ---
from voice.hotkey import PushToTalkHotkey
from voice.mic_controller import MicController
from voice.recorder import Recorder
from voice.whisper_stt import WhisperSTT

logger = logging.getLogger(__name__)


class _WakeSignals(QObject):
    wake_detected = pyqtSignal()


# ---------------------------------------------------------------- providers


def build_llm_provider() -> ProviderManager:
    """
    Fallback chain, tool-capable providers first.
    Gemini → Groq → OpenAI → Anthropic → DeepSeek → HuggingFace
    """
    providers: list[tuple[str, object]] = []

    def _add(name: str, key: str, factory):
        if key:
            try:
                instance = factory()
                providers.append((name, instance))
                logger.info("Registered provider: %s", name)
            except Exception:
                logger.exception("Failed to build provider %s", name)
        else:
            logger.info("Provider %s skipped (no API key)", name)

    _add("gemini", config.GEMINI_API_KEY, lambda: GeminiProvider(
        config.GEMINI_API_KEY, config.GEMINI_MODEL, enable_tools=True))
    _add("groq", config.GROQ_API_KEY, lambda: GroqProvider(
        config.GROQ_API_KEY, config.GROQ_MODEL))
    _add("openai", config.OPENAI_API_KEY, lambda: OpenAIProvider(
        config.OPENAI_API_KEY, config.OPENAI_MODEL))
    _add("anthropic", config.ANTHROPIC_API_KEY, lambda: AnthropicProvider(
        config.ANTHROPIC_API_KEY, config.ANTHROPIC_MODEL))
    _add("deepseek", config.DEEPSEEK_API_KEY, lambda: DeepSeekProvider(
        config.DEEPSEEK_API_KEY, config.DEEPSEEK_MODEL,
        base_url=config.DEEPSEEK_BASE_URL))
    _add("huggingface", config.HF_TOKEN, lambda: HuggingFaceProvider(
        config.HF_TOKEN, config.HF_MODEL))

    if not providers:
        logger.error("No AI providers configured — Lumi cannot chat.")

    return ProviderManager(providers)


def build_tts():
    if not config.TTS_ENABLED:
        logger.info("TTS disabled in config.")
        return None
    if config.TTS_ENGINE == "gemini":
        from voice.gemini_tts import GeminiTTS
        tts = GeminiTTS(
            config.GEMINI_API_KEY,
            config.GEMINI_TTS_MODEL,
            config.GEMINI_TTS_VOICE,
        )
        logger.info("TTS engine: Gemini (%s, voice=%s)",
                    config.GEMINI_TTS_MODEL, config.GEMINI_TTS_VOICE)
        return tts
    from voice.kokoro_tts import KokoroTTS
    tts = KokoroTTS(
        config.MODELS_DIR / "kokoro-v1.0.onnx",
        config.MODELS_DIR / "voices-v1.0.bin",
    )
    logger.info("TTS engine: Kokoro (voice=%s)", config.VOICE)
    return tts


def build_stt():
    if not config.STT_ENABLED:
        logger.info("STT disabled in config.")
        return None
    stt = WhisperSTT(
        model_name=config.STT_MODEL,
        device=config.STT_DEVICE,
        compute_type=config.STT_COMPUTE,
        language=config.STT_LANGUAGE,
    )
    logger.info("STT engine ready (model=%s, lang=%s).",
                config.STT_MODEL, config.STT_LANGUAGE)
    return stt


def build_translator():
    if not config.TRANSLATE_ENABLED:
        logger.info("Translator disabled in config.")
        return None
    translator = Translator(
        api_key=config.GEMINI_API_KEY,
        model=config.TRANSLATE_MODEL,
    )
    logger.info("Translator ready (%s).", config.TRANSLATE_MODEL)
    return translator


def build_wake_detector(whisper_stt):
    if not config.WAKE_ENABLED or whisper_stt is None:
        return None

    oww_model = config.MODELS_DIR / "lumi.onnx"
    if oww_model.exists():
        try:
            from voice.wake_oww import OpenWakeWordDetector
            logger.info("Using openWakeWord model: %s", oww_model)
            return OpenWakeWordDetector(
                model_path=oww_model,
                input_device=config.STT_INPUT_DEVICE,
                threshold=0.70,
            )
        except Exception:
            logger.exception("openWakeWord failed; trying trained model")

    trained_model = config.MODELS_DIR / "wake_model.pkl"
    if trained_model.exists():
        try:
            from voice.wake_trained import TrainedWakeDetector
            logger.info("Using trained wake model: %s", trained_model)
            return TrainedWakeDetector(
                model_path=trained_model,
                input_device=config.STT_INPUT_DEVICE,
                positive_threshold=0.75,
                required_consecutive=2,
            )
        except Exception:
            logger.exception("Trained model failed; falling back to Whisper")

    from voice.wake_whisper import WhisperWakeDetector
    logger.info("Using Whisper wake detector.")
    return WhisperWakeDetector(
        whisper_stt=whisper_stt,
        wake_words=config.WAKE_WORDS,
        input_device=config.STT_INPUT_DEVICE,
    )


# ---------------------------------------------------------------- main


def main():
    setup_logging()
    logger.info("Lumi starting (multi-provider + security + tools)...")

    for err in config.validate():
        logger.warning("Config: %s", err)

    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            logger.warning(
                "Lumi is running as ADMINISTRATOR. "
                "Terminal commands will be refused. "
                "Restart normally (double-click, not 'Run as admin')."
            )
    except Exception:
        pass

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    # ---------- Core ----------
    state_manager = StateManager(initial=LumiState.SLEEPING)
    memory = ConversationMemory(max_messages=config.MAX_CONTEXT_MESSAGES)

    # ---------- Providers / engines ----------
    provider = build_llm_provider()
    tts = build_tts()
    stt = build_stt()
    translator = build_translator()

    tts_voice = (
        config.GEMINI_TTS_VOICE if config.TTS_ENGINE == "gemini"
        else config.VOICE
    )

    # ---------- Minimal window (deferred assistant reference) ----------
    mic_ref: dict = {}
    assistant_ref: dict = {}
    force_ref: dict = {}

    def on_mic_clicked():
        ctl = mic_ref.get("ctl")
        if ctl is not None:
            ctl.toggle()

    def on_user_input(text: str):
        """Handle special commands (typed only) or forward to assistant."""
        low = text.strip().lower()

        # ---- /force intercept (typed input ONLY — never voice, never LLM) ----
        if low == "/force" or low.startswith("/force "):
            mgr = force_ref.get("mgr")
            if mgr is None:
                window.set_user_text("force: manager not ready")
                return
            parts = text.strip().split(maxsplit=1)
            arg = parts[1].strip().lower() if len(parts) > 1 else ""

            if arg == "off":
                was = mgr.disable_force()
                window.set_user_text(
                    "force OFF" if was else "force was already off"
                )
                return

            if arg == "status":
                if mgr.is_force_active():
                    window.set_user_text(
                        f"force ON — {mgr.force_remaining()}s left"
                    )
                else:
                    window.set_user_text("force OFF")
                return

            seconds = 300
            if arg.isdigit():
                seconds = int(arg)
            actual = mgr.enable_force(seconds=seconds, reason="user /force")
            window.set_user_text(
                f"FORCE ON for {actual}s — delete/rename/move/admin/install "
                f"still ask"
            )
            return

        # ---- normal path ----
        a = assistant_ref.get("assistant")
        if a is not None:
            a.send(text)

    window = MinimalWindow(
        state_manager=state_manager,
        event_bus=bus,
        on_user_input=on_user_input,
        on_mic_clicked=on_mic_clicked,
    )

    # ---------- Security gate ----------
    conf_bridge = QtConfirmationBridge(
        parent=window,
        timeout_seconds=config.CONFIRMATION_TIMEOUT,
    )
    confirmation_mgr = ConfirmationManager(
        timeout_seconds=config.CONFIRMATION_TIMEOUT
    )
    confirmation_mgr.set_handler(conf_bridge.request)
    force_ref["mgr"] = confirmation_mgr

    gate = SecurityGate(
        protected_folder=config.PROTECTED_FOLDER,
        sandbox_root=config.SANDBOX_ROOT,
        sandbox_enabled=config.SANDBOX_ENABLED,
        policy=PermissionPolicy(
            auto_approve_max=PermissionLevel(
                config.PERMISSION_AUTO_APPROVE_MAX
            ),
        ),
        confirmation=confirmation_mgr,
    )
    security.set_gate(gate)

    # Register all tool families
    fs_tools.register(gate)
    term_tools.register(gate)
    app_tools.register(gate)

    logger.info(
        "Security initialized. Protected folder: %s, sandbox: %s (%s), "
        "auto-approve up to level %d",
        config.PROTECTED_FOLDER,
        "on" if config.SANDBOX_ENABLED else "off",
        config.SANDBOX_ROOT if config.SANDBOX_ENABLED else "-",
        config.PERMISSION_AUTO_APPROVE_MAX,
    )
    logger.info(
        "Admin terminal: %s",
        "ENABLED" if getattr(config, "ADMIN_TERMINAL_ENABLED", False)
        else "disabled",
    )

    # ---------- Tool router ----------
    tool_router = ToolRouter(gate)
    logger.info("Tool router ready with %d tools.",
                len(tool_router._executors))

    # ---------- Assistant ----------
    assistant = Assistant(
        provider=provider,
        memory=memory,
        state_manager=state_manager,
        event_bus=bus,
        tts=tts,
        tts_voice=tts_voice,
        tool_router=tool_router,
    )
    assistant_ref["assistant"] = assistant
    bus.subscribe("assistant_reset", lambda: assistant.reset())

    # ---------- Mic controller ----------
    mic_ctl = None
    if stt is not None:
        recorder = Recorder(
            sample_rate=config.STT_SAMPLE_RATE,
            max_seconds=config.STT_MAX_SECONDS,
            device=config.STT_INPUT_DEVICE,
        )
        mic_ctl = MicController(
            recorder,
            stt,
            assistant,
            state_manager,
            window,
            translator=translator,
        )
        mic_ref["ctl"] = mic_ctl

        hotkey = PushToTalkHotkey(
            hotkey_spec=config.STT_HOTKEY,
            on_press=mic_ctl.start_recording,
            on_release=mic_ctl.stop_and_transcribe,
        )
        hotkey.start()

    # ---------- Wake detector ----------
    wake_detector = build_wake_detector(stt)
    wake_signals = None

    if wake_detector is not None:
        wake_signals = _WakeSignals()

        def _handle_wake():
            logger.info("Waking up...")
            if wake_detector is not None:
                wake_detector.stop()
            if state_manager.state == LumiState.SLEEPING:
                state_manager.transition(LumiState.IDLE)
            if config.WAKE_AUTO_RECORD and mic_ctl is not None:
                mic_ctl.wake_and_record(
                    silence_seconds=config.WAKE_SILENCE_SECONDS,
                    max_seconds=config.WAKE_MAX_SECONDS,
                )

        wake_signals.wake_detected.connect(_handle_wake)
        wake_detector.set_callback(
            lambda: wake_signals.wake_detected.emit()
        )

    # ---------- State observer ----------
    def _on_state(old, new):
        if new == LumiState.STOPPING:
            if wake_detector is not None:
                wake_detector.stop()
            app.quit()
            return

        if wake_detector is None:
            return

        if new == LumiState.SLEEPING and not wake_detector.is_running:
            def _delayed_start():
                import time
                time.sleep(0.35)
                if state_manager.state == LumiState.SLEEPING:
                    wake_detector.start()
            threading.Thread(target=_delayed_start, daemon=True).start()
        elif new != LumiState.SLEEPING and wake_detector.is_running:
            wake_detector.stop()

    state_manager.add_observer(_on_state)

    if wake_detector is not None:
        def _start_initial():
            import time
            time.sleep(0.4)
            wake_detector.start()
        threading.Thread(target=_start_initial, daemon=True).start()

    # ---------- Tray ----------
    tray = TrayIcon(state_manager)
    threading.Thread(target=tray.run, daemon=True).start()

    logger.info('Lumi initialized. State = SLEEPING. Say "Lumi" to wake her.')
    sys.exit(app.exec())


if __name__ == "__main__":
    main()