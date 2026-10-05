"""
Wake-word detector using faster-whisper with hallucination guards.

Runs continuously while Lumi is sleeping:
  1. RMS gate: ignore quiet audio (noise, breathing)
  2. VAD: collect utterances separated by silence
  3. Whisper transcribes with NO initial_prompt (which caused hallucination)
  4. Multi-layer filter rejects phantom phrases before matching
  5. Fuzzy match against wake-word list
"""
import difflib
import logging
import threading
import time
from collections import Counter, deque

import numpy as np
import sounddevice as sd

logger = logging.getLogger(__name__)


# Whisper hallucinates these on silence/noise. Reject outright.
_HALLUCINATIONS = {
    "thank you", "thanks for watching", "thank you for watching",
    "thank you.", "thanks for watching.", "subscribe",
    "please subscribe", "amara.org", "subs by", "subtitle",
    "transcription by", "translated by", "terima kasih",
    "terima kasih kerana menonton", "terima kasih telah menonton",
    "sampai jumpa", "bye", "bye bye", "you", "yeah", "hmm", "mm",
    "uh", "um", "okay", "ok", "oh", "ah", "eh", "ha", "haha",
    "please", "music", "♪", "...", "..", ".", "!",
}


def _normalize(s: str) -> str:
    return "".join(c for c in s.lower() if c.isalnum())


def _similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


class WhisperWakeDetector:
    def __init__(self, whisper_stt, wake_words,
                 sample_rate: int = 16000,
                 input_device: int | None = None,
                 rms_threshold: float = 0.015,
                 peak_threshold: float = 0.05,
                 silence_ms: int = 700,
                 min_speech_ms: int = 400,
                 max_utterance_sec: float = 2.0,
                 cooldown_seconds: float = 3.0,
                 fuzzy_threshold: float = 0.78,
                 debug: bool = True):
        self.stt = whisper_stt
        self.wake_words = [w.lower() for w in wake_words]
        self.sample_rate = sample_rate
        self.input_device = input_device
        self.rms_threshold = rms_threshold
        self.peak_threshold = peak_threshold
        self.silence_ms = silence_ms
        self.min_speech_ms = min_speech_ms
        self.max_utterance_samples = int(max_utterance_sec * sample_rate)
        self.cooldown_seconds = cooldown_seconds
        self.fuzzy_threshold = fuzzy_threshold
        self.debug = debug

        self._stream = None
        self._thread = None
        self._running = False
        self._stop_requested = threading.Event()
        self._thread_done = threading.Event()
        self._lock = threading.Lock()
        self._on_wake = None
        self._last_wake_time = 0.0
        self._chunks = deque()
        self._chunks_lock = threading.Lock()

    def set_callback(self, callback):
        self._on_wake = callback

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._stop_requested.clear()
            self._thread_done.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0):
        self._stop_requested.set()
        self._thread_done.wait(timeout=timeout)
        with self._lock:
            self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    # ---------- Audio plumbing ----------

    def _audio_callback(self, indata, frames, time_info, status):
        mono = indata[:, 0].copy() if indata.ndim > 1 else indata.copy()
        with self._chunks_lock:
            self._chunks.append(mono)

    def _drain(self) -> np.ndarray:
        with self._chunks_lock:
            chunks = list(self._chunks)
            self._chunks.clear()
        if not chunks:
            return np.zeros(0, dtype=np.float32)
        return np.concatenate(chunks).astype(np.float32)

    # ---------- Main loop ----------

    def _run(self):
        try:
            self._stream = sd.InputStream(
                samplerate=self.sample_rate,
                channels=1,
                dtype="float32",
                blocksize=1600,
                callback=self._audio_callback,
                device=self.input_device,
            )
            self._stream.start()
        except Exception:
            logger.exception("Failed to open mic for Whisper wake listener")
            self._thread_done.set()
            return

        logger.info(
            "Whisper wake active (device=%s, rms>=%.3f, peak>=%.3f, silence=%dms)",
            self.input_device, self.rms_threshold,
            self.peak_threshold, self.silence_ms,
        )

        utt_buffer: list[np.ndarray] = []
        utt_samples = 0
        speech_active = False
        silence_start = None

        try:
            while not self._stop_requested.is_set():
                time.sleep(0.05)
                chunk = self._drain()
                if len(chunk) == 0:
                    continue

                rms = float(np.sqrt(np.mean(chunk ** 2)))
                peak = float(np.max(np.abs(chunk)))
                speaking = (rms >= self.rms_threshold) and (peak >= self.peak_threshold)

                if speaking:
                    if not speech_active:
                        speech_active = True
                    silence_start = None
                    utt_buffer.append(chunk)
                    utt_samples += len(chunk)
                else:
                    if speech_active:
                        utt_buffer.append(chunk)
                        utt_samples += len(chunk)
                        if silence_start is None:
                            silence_start = time.time()
                        elif (time.time() - silence_start) * 1000 >= self.silence_ms:
                            audio = np.concatenate(utt_buffer).astype(np.float32)
                            utt_buffer = []
                            utt_samples = 0
                            speech_active = False
                            silence_start = None
                            self._process(audio)

                if utt_samples > self.max_utterance_samples:
                    utt_buffer = []
                    utt_samples = 0
                    speech_active = False
                    silence_start = None
        finally:
            try:
                if self._stream is not None:
                    self._stream.stop()
                    self._stream.close()
            except Exception:
                pass
            self._stream = None
            self._thread_done.set()
            logger.info("Whisper wake listener stopped.")

    # ---------- Utterance processing ----------

    def _process(self, audio: np.ndarray):
        duration = len(audio) / self.sample_rate
        if duration < (self.min_speech_ms / 1000):
            return
        if duration > self.max_utterance_samples / self.sample_rate:
            return

        clip_peak = float(np.max(np.abs(audio))) if len(audio) else 0.0
        if clip_peak < self.peak_threshold:
            return

        now = time.time()
        if now - self._last_wake_time < self.cooldown_seconds:
            return

        if self.debug:
            logger.info("Wake: transcribing %.2fs utterance...", duration)

        try:
            text = self.stt.transcribe(
                audio,
                language="en",
                use_vad=False,
                initial_prompt=None,     # critical: no prompt bias
                no_speech_threshold=0.4,
                compression_ratio_threshold=1.8,
            )
        except Exception:
            logger.exception("Whisper wake transcribe failed")
            return

        if not text:
            return

        text_clean = text.lower().strip().strip(".,!?\"' ")
        if self.debug:
            logger.info("Wake heard: %r", text_clean)

        # --- Hallucination guards ---

        # 1. Empty or too long
        words = text_clean.split()
        if not words or len(words) > 3:
            if self.debug and words:
                logger.info("Wake: %d words - rejecting", len(words))
            return

        # 2. Repetitive (e.g. "lumi lumi lumi")
        if len(words) > 1:
            counts = Counter(words)
            if any(c >= 2 for c in counts.values()):
                if self.debug:
                    logger.info("Wake: repeated word - hallucination")
                return

        # 3. Known hallucination phrases
        stripped = " ".join(words)
        if stripped in _HALLUCINATIONS:
            if self.debug:
                logger.info("Wake: hallucination phrase - rejecting")
            return

        # 4. Match
        if self._matches(text_clean):
            self._last_wake_time = now
            logger.info("Wake word detected via Whisper: %r", text_clean)
            if self._on_wake:
                try:
                    self._on_wake()
                except Exception:
                    logger.exception("Wake callback failed")

    def _matches(self, text: str) -> bool:
        norm = _normalize(text)
        if not norm:
            return False

        for word in self.wake_words:
            n = _normalize(word)
            if not n:
                continue
            # Exact substring (word must be reasonably short)
            if n in norm and len(norm) <= len(n) + 3:
                return True
            # Whole-string similarity
            if _similarity(n, norm) >= self.fuzzy_threshold:
                return True
            # Sliding-window similarity
            wlen = len(n)
            if len(norm) > wlen:
                for i in range(len(norm) - wlen + 1):
                    if _similarity(n, norm[i:i + wlen]) >= self.fuzzy_threshold:
                        return True
        return False