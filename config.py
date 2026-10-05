"""Centralized configuration loader."""
import os
from pathlib import Path
from dotenv import load_dotenv

_env_path = Path(__file__).resolve().parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=_env_path)
else:
    load_dotenv()

_input_device_raw = os.getenv("LUMI_INPUT_DEVICE", "").strip()
_input_device: int | None = int(_input_device_raw) if _input_device_raw else None


class Config:
    # --- Gemini ---
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")

    # --- Hugging Face ---
    HF_TOKEN: str = os.getenv("HF_TOKEN", "")
    HF_MODEL: str = os.getenv("HF_MODEL", "Qwen/Qwen2.5-72B-Instruct")

    # --- Groq ---
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    # --- OpenAI / ChatGPT ---
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # --- Anthropic / Claude ---
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL",
                                     "claude-3-5-sonnet-latest")

    # --- DeepSeek ---
    DEEPSEEK_API_KEY: str = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_MODEL: str = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    DEEPSEEK_BASE_URL: str = os.getenv("DEEPSEEK_BASE_URL",
                                       "https://api.deepseek.com")

    # --- Security ---
    PROTECTED_FOLDER: str = os.getenv("LUMI_PROTECTED_FOLDER", r"D:\Secure")
    PERMISSION_AUTO_APPROVE_MAX: int = int(
        os.getenv("LUMI_PERMISSION_AUTO_APPROVE_MAX", "1"))
    CONFIRMATION_TIMEOUT: int = int(
        os.getenv("LUMI_CONFIRMATION_TIMEOUT", "60"))
    SANDBOX_ENABLED: bool = (
        os.getenv("LUMI_SANDBOX_ENABLED", "false").lower() == "true")
    SANDBOX_ROOT: str = os.getenv("LUMI_SANDBOX_ROOT", "F:\\")

    # --- Admin terminal (Phase 3 privileged helper) ---
    ADMIN_TERMINAL_ENABLED: bool = (
        os.getenv("LUMI_ADMIN_TERMINAL_ENABLED", "false").lower() == "true")

    # Bounded timeouts for the privileged helper exchange. Every timeout
    # path results in a terminal outcome; none triggers an automatic retry.
    HELPER_CONNECT_TIMEOUT_SECONDS: int = int(
        os.getenv("LUMI_HELPER_CONNECT_TIMEOUT_SECONDS", "120"))
    HELPER_RESPONSE_TIMEOUT_SECONDS: int = int(
        os.getenv("LUMI_HELPER_RESPONSE_TIMEOUT_SECONDS", "3600"))
    HELPER_MAX_REQUEST_BYTES: int = int(
        os.getenv("LUMI_HELPER_MAX_REQUEST_BYTES", "262144"))
    HELPER_MAX_RESPONSE_BYTES: int = int(
        os.getenv("LUMI_HELPER_MAX_RESPONSE_BYTES", "4194304"))

    # --- Logging / startup ---
    LOG_LEVEL: str = os.getenv("LUMI_LOG_LEVEL", "INFO").upper()
    START_MINIMIZED: bool = (
        os.getenv("LUMI_START_MINIMIZED", "true").lower() == "true")

    # --- Conversation ---
    MAX_CONTEXT_MESSAGES: int = int(os.getenv("LUMI_MAX_CONTEXT_MESSAGES", "20"))
    MAX_RESPONSE_TOKENS: int = int(os.getenv("LUMI_MAX_RESPONSE_TOKENS", "800"))

    # --- TTS ---
    TTS_ENABLED: bool = os.getenv("LUMI_TTS_ENABLED", "true").lower() == "true"
    TTS_ENGINE: str = os.getenv("LUMI_TTS_ENGINE", "kokoro").lower()
    VOICE: str = os.getenv("LUMI_VOICE", "af_bella")
    SPEECH_SPEED: float = float(os.getenv("LUMI_SPEECH_SPEED", "1.0"))
    MODELS_DIR: Path = Path(__file__).resolve().parent / "models"
    GEMINI_TTS_MODEL: str = os.getenv(
        "LUMI_GEMINI_TTS_MODEL", "gemini-3.5-flash-tts")
    GEMINI_TTS_VOICE: str = os.getenv("LUMI_GEMINI_VOICE", "Kore")

    # --- Translator ---
    TRANSLATE_ENABLED: bool = (
        os.getenv("LUMI_TRANSLATE_ENABLED", "true").lower() == "true")
    TRANSLATE_MODEL: str = os.getenv(
        "LUMI_TRANSLATE_MODEL", "gemini-flash-lite-latest")

    # --- STT ---
    STT_ENABLED: bool = os.getenv("LUMI_STT_ENABLED", "true").lower() == "true"
    STT_MODEL: str = os.getenv("LUMI_STT_MODEL", "small")
    STT_LANGUAGE: str = os.getenv("LUMI_STT_LANG", "auto")
    STT_DEVICE: str = os.getenv("LUMI_STT_DEVICE", "cpu")
    STT_COMPUTE: str = os.getenv("LUMI_STT_COMPUTE", "int8")
    STT_MAX_SECONDS: int = int(os.getenv("LUMI_STT_MAX_SECONDS", "30"))
    STT_HOTKEY: str = os.getenv("LUMI_STT_HOTKEY", "<ctrl>+<alt>+l")
    STT_SAMPLE_RATE: int = 16000
    STT_INPUT_DEVICE: int | None = _input_device

    # --- Wake word ---
    WAKE_ENABLED: bool = os.getenv("LUMI_WAKE_ENABLED", "true").lower() == "true"
    WAKE_WORDS: list[str] = [
        w.strip().lower()
        for w in os.getenv("LUMI_WAKE_WORDS",
                           "lumi,loomi,loomy,lumy,lumie,loomie").split(",")
        if w.strip()
    ]
    WAKE_AUTO_RECORD: bool = (
        os.getenv("LUMI_WAKE_AUTO_RECORD", "true").lower() == "true")
    WAKE_SILENCE_SECONDS: float = float(
        os.getenv("LUMI_WAKE_SILENCE_SECONDS", "1.2"))
    WAKE_MAX_SECONDS: float = float(
        os.getenv("LUMI_WAKE_MAX_SECONDS", "15"))

    @classmethod
    def validate(cls) -> list[str]:
        errors: list[str] = []
        any_provider = any([
            cls.GEMINI_API_KEY, cls.HF_TOKEN, cls.GROQ_API_KEY,
            cls.OPENAI_API_KEY, cls.ANTHROPIC_API_KEY, cls.DEEPSEEK_API_KEY,
        ])
        if not any_provider:
            errors.append("No AI provider API keys configured.")
        if not Path(cls.PROTECTED_FOLDER).is_absolute():
            errors.append(
                f"PROTECTED_FOLDER must be absolute: {cls.PROTECTED_FOLDER}")
        if cls.SANDBOX_ENABLED:
            if not cls.SANDBOX_ROOT:
                errors.append("SANDBOX_ENABLED=true but SANDBOX_ROOT empty.")
            elif not Path(cls.SANDBOX_ROOT).is_absolute():
                errors.append(
                    f"SANDBOX_ROOT must be absolute: {cls.SANDBOX_ROOT}")
        if cls.TTS_ENABLED and cls.TTS_ENGINE == "kokoro":
            onnx = cls.MODELS_DIR / "kokoro-v1.0.onnx"
            voices = cls.MODELS_DIR / "voices-v1.0.bin"
            if not onnx.exists():
                errors.append(f"Kokoro model missing: {onnx}")
            if not voices.exists():
                errors.append(f"Kokoro voices missing: {voices}")
        return errors


config = Config()