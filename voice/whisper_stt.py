"""Local speech-to-text using faster-whisper. Multilingual."""
import logging
import threading

import numpy as np

logger = logging.getLogger(__name__)


class WhisperSTT:
    def __init__(self, model_name: str = "small", device: str = "cpu",
                 compute_type: str = "int8", language: str = "auto"):
        self.model_name = model_name
        self.device = device
        self.compute_type = compute_type
        # "auto" → None (Whisper auto-detects); otherwise use the code.
        self.language = None if (language or "").lower() == "auto" else language
        self._model = None
        self._lock = threading.Lock()

    def _ensure_loaded(self):
        if self._model is not None:
            return
        with self._lock:
            if self._model is not None:
                return
            logger.info(
                "Loading Whisper model %s (%s/%s, language=%s)...",
                self.model_name, self.device, self.compute_type,
                self.language or "auto",
            )
            from faster_whisper import WhisperModel
            self._model = WhisperModel(
                self.model_name,
                device=self.device,
                compute_type=self.compute_type,
            )
            logger.info("Whisper model loaded.")

    def transcribe(self, audio: np.ndarray, sample_rate: int = 16000,
                   language: str | None = None,
                   use_vad: bool = True,
                   initial_prompt: str | None = None,
                   no_speech_threshold: float = 0.6,
                   compression_ratio_threshold: float = 2.4) -> str:
        if audio is None or len(audio) == 0:
            return ""

        self._ensure_loaded()

        if audio.dtype != np.float32:
            audio = audio.astype(np.float32)
        if audio.ndim > 1:
            audio = audio.mean(axis=1)

        peak = float(np.max(np.abs(audio))) if len(audio) else 0.0
        if peak > 0:
            target = 0.9
            gain = min(target / peak, 8.0)
            if gain > 1.05:
                audio = np.clip(audio * gain, -1.0, 1.0).astype(np.float32)

        if sample_rate != 16000:
            ratio = 16000.0 / sample_rate
            new_len = max(1, int(len(audio) * ratio))
            indices = np.linspace(0, len(audio) - 1, new_len)
            audio = np.interp(indices, np.arange(len(audio)), audio).astype(np.float32)

        # --- FIX: normalize "auto" to None ---
        # faster-whisper accepts either None (auto-detect) or a real
        # language code like "id" or "en". It does NOT accept "auto".
        if isinstance(language, str) and language.lower() == "auto":
            language = None
        lang = language if language is not None else self.language

        try:
            segments, info = self._model.transcribe(
                audio,
                language=lang,
                beam_size=5,
                best_of=5,
                temperature=0.0,
                condition_on_previous_text=False,
                vad_filter=use_vad,
                vad_parameters=dict(
                    threshold=0.35,
                    min_speech_duration_ms=100,
                    min_silence_duration_ms=800,
                    speech_pad_ms=500,
                ),
                no_speech_threshold=no_speech_threshold,
                log_prob_threshold=-1.5,
                compression_ratio_threshold=compression_ratio_threshold,
                initial_prompt=initial_prompt,
            )
            text = " ".join(s.text.strip() for s in segments).strip()
            detected_lang = getattr(info, "language", "?")
            prob = getattr(info, "language_probability", 0.0)
            logger.info(
                "STT result: %r (lang=%s, prob=%.2f, duration=%.2fs)",
                text, detected_lang, prob, getattr(info, "duration", 0.0),
            )
            return text
        except Exception:
            logger.exception("Whisper transcription failed")
            return ""