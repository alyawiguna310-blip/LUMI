"""Microphone recorder using sounddevice. Non-blocking start/stop."""
import logging
import threading
import time

import numpy as np
import sounddevice as sd

logger = logging.getLogger(__name__)


class Recorder:
    def __init__(self, sample_rate: int = 16000, max_seconds: int = 30,
                 device: int | None = None):
        self.sample_rate = sample_rate
        self.max_seconds = max_seconds
        self.device = device

        self._frames: list[np.ndarray] = []
        self._stream = None
        self._recording = False
        self._lock = threading.Lock()

        # Silence tracking
        self._last_speech_time = 0.0
        self._has_speech = False
        self._speech_threshold = 0.01   # RMS

    @property
    def is_recording(self) -> bool:
        return self._recording

    @property
    def last_speech_time(self) -> float:
        return self._last_speech_time

    @property
    def has_speech(self) -> bool:
        return self._has_speech

    def silence_duration(self) -> float:
        if not self._has_speech:
            return 0.0
        return time.time() - self._last_speech_time

    def _callback(self, indata, frames, time_info, status):
        if status:
            logger.debug("Recorder status: %s", status)
        if not self._recording:
            return
        self._frames.append(indata.copy())

        # Silence tracking
        rms = float(np.sqrt(np.mean(indata ** 2)))
        if rms > self._speech_threshold:
            self._has_speech = True
            self._last_speech_time = time.time()

    def _device_name(self) -> str:
        try:
            if self.device is not None:
                return sd.query_devices(self.device, "input")["name"]
            return sd.query_devices(kind="input")["name"]
        except Exception:
            return "unknown"

    def start(self):
        with self._lock:
            if self._recording:
                return
            self._frames = []
            self._has_speech = False
            self._last_speech_time = 0.0
            try:
                self._stream = sd.InputStream(
                    samplerate=self.sample_rate,
                    channels=1,
                    dtype="float32",
                    callback=self._callback,
                    device=self.device,
                )
                self._stream.start()
                self._recording = True
                logger.info("Mic recording started (device: %s).", self._device_name())
            except Exception:
                logger.exception("Failed to start mic stream (device=%r)", self.device)
                self._recording = False
                self._stream = None

    def stop(self) -> np.ndarray | None:
        with self._lock:
            if not self._recording:
                return None
            self._recording = False
            try:
                if self._stream is not None:
                    self._stream.stop()
                    self._stream.close()
            except Exception:
                logger.exception("Failed to stop mic stream")
            finally:
                self._stream = None

        if not self._frames:
            logger.warning("Recorder: no frames captured.")
            return None

        audio = np.concatenate(self._frames, axis=0).flatten().astype(np.float32)
        self._frames = []

        duration = len(audio) / self.sample_rate
        rms = float(np.sqrt(np.mean(audio ** 2))) if len(audio) else 0.0
        peak = float(np.max(np.abs(audio))) if len(audio) else 0.0
        logger.info(
            "Mic recording stopped (%.2fs, %d samples, rms=%.4f, peak=%.4f, speech=%s)",
            duration, len(audio), rms, peak, self._has_speech,
        )

        if peak < 0.001:
            logger.warning("Mic captured NO audio (peak=0.0000).")
        elif peak < 0.01:
            logger.warning("Mic level is VERY low (peak=%.4f).", peak)
        elif peak > 0.99:
            logger.warning("Mic is clipping (peak=%.4f).", peak)

        if duration < 0.3:
            logger.info("Recording too short; ignoring.")
            return None
        if duration > self.max_seconds:
            logger.warning("Recording exceeded max length; trimming.")
            audio = audio[: self.max_seconds * self.sample_rate]

        return audio

    def cancel(self):
        with self._lock:
            self._recording = False
            try:
                if self._stream is not None:
                    self._stream.stop()
                    self._stream.close()
            except Exception:
                pass
            self._stream = None
            self._frames = []