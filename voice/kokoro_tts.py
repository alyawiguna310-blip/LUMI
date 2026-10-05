"""
Kokoro TTS engine using kokoro-onnx.

- Lazy-loads the ONNX model on first speak() call.
- Chunks long text at sentence boundaries so Kokoro never truncates.
- Pads each chunk with trailing silence so the Windows audio driver
  has time to flush the last buffer (prevents dropped syllables).
- Uses sd.play(blocking=False) + sd.wait() with a kept reference to the
  audio array so Python never frees it mid-playback.
- stop() is a no-op unless playback is actually active.
"""
import logging
import re
import threading
from pathlib import Path

import numpy as np
import sounddevice as sd

logger = logging.getLogger(__name__)


class KokoroTTS:
    def __init__(self, model_path: Path, voices_path: Path):
        self.model_path = Path(model_path)
        self.voices_path = Path(voices_path)
        self._kokoro = None
        self._lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._current_audio = None

    # ---------- Loading ----------

    def _ensure_loaded(self):
        if self._kokoro is not None:
            return
        with self._lock:
            if self._kokoro is not None:
                return
            if not self.model_path.exists():
                raise FileNotFoundError(
                    f"Kokoro model not found: {self.model_path}"
                )
            if not self.voices_path.exists():
                raise FileNotFoundError(
                    f"Kokoro voices file not found: {self.voices_path}"
                )
            logger.info("Loading Kokoro model (first time may take 10-20s)...")
            from kokoro_onnx import Kokoro

            self._kokoro = Kokoro(str(self.model_path), str(self.voices_path))
            logger.info("Kokoro model loaded.")

    # ---------- Text chunking ----------

    @staticmethod
    def _chunk_text(text: str, max_chars: int = 280) -> list[str]:
        """Split text into sentence-bounded chunks under max_chars."""
        text = text.strip()
        if not text:
            return []
        if len(text) <= max_chars:
            return [text]

        sentences = re.split(r"(?<=[.!?])\s+", text)
        chunks: list[str] = []
        current = ""

        for s in sentences:
            s = s.strip()
            if not s:
                continue

            while len(s) > max_chars:
                cut = s.rfind(" ", 0, max_chars)
                if cut == -1:
                    cut = max_chars
                chunks.append(s[:cut].strip())
                s = s[cut:].strip()

            if not current:
                current = s
            elif len(current) + 1 + len(s) <= max_chars:
                current = current + " " + s
            else:
                chunks.append(current)
                current = s

        if current:
            chunks.append(current)

        return chunks

    # ---------- Speaking ----------

    def speak(
        self,
        text: str,
        voice: str = "af_bella",
        speed: float = 1.0,
        lang: str = "en-us",
    ) -> None:
        """Synthesize text and play it. Blocks until playback finishes."""
        text = (text or "").strip()
        if not text:
            return

        self._stop_requested.clear()

        try:
            self._ensure_loaded()
        except Exception:
            logger.exception("Kokoro failed to load; skipping speech.")
            return

        chunks = self._chunk_text(text)
        logger.info("TTS: %d chunk(s) for %d chars", len(chunks), len(text))

        for i, chunk in enumerate(chunks):
            if self._stop_requested.is_set():
                logger.info(
                    "TTS stop requested; aborting after chunk %d/%d",
                    i, len(chunks),
                )
                break

            try:
                samples, sample_rate = self._kokoro.create(
                    text=chunk,
                    voice=voice,
                    speed=speed,
                    lang=lang,
                )
            except Exception:
                logger.exception("Kokoro synthesis failed on chunk %d", i)
                continue

            if samples is None or len(samples) == 0:
                logger.warning("Kokoro returned empty audio for chunk %d", i)
                continue

            if samples.dtype != np.float32:
                samples = samples.astype(np.float32)

            # ~150 ms trailing silence so the audio driver can flush the
            # final buffer before the stream closes. Without this, the last
            # syllable sometimes gets dropped on Windows.
            tail = np.zeros(int(sample_rate * 0.15), dtype=np.float32)
            padded = np.concatenate([samples, tail]).astype(np.float32)

            try:
                # Keep a live reference for the duration of playback —
                # otherwise Python may free the array while the stream reads it.
                self._current_audio = padded
                sd.play(self._current_audio, samplerate=sample_rate, blocking=False)
                sd.wait()
            except Exception:
                logger.exception("Audio playback failed for chunk %d", i)
            finally:
                self._current_audio = None

    def stop(self) -> None:
        """Request playback to stop at the next chunk boundary."""
        self._stop_requested.set()
        # Only forcibly stop the device if playback is actually happening.
        try:
            if self._current_audio is not None:
                sd.stop()
        except Exception:
            pass