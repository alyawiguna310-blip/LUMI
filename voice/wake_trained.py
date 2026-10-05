"""
Lightweight wake-word detector using a trained classifier.
~1% CPU while running. No Whisper loaded.
"""
import logging
import pickle
import threading
import time
from pathlib import Path

import numpy as np
import sounddevice as sd

from voice.features import extract_features

logger = logging.getLogger(__name__)


class TrainedWakeDetector:
    def __init__(self, model_path: Path,
                 sample_rate: int = 16000,
                 input_device: int | None = None,
                 window_seconds: float = 1.2,
                 hop_seconds: float = 0.25,
                 positive_threshold: float = 0.75,
                 required_consecutive: int = 2,
                 # Gate thresholds — reject noise before classifier runs.
                 min_rms: float = 0.008,
                 min_peak: float = 0.06,
                 max_gain: float = 10.0,
                 cooldown_seconds: float = 3.0,
                 debug: bool = True):
        self.model_path = Path(model_path)
        self.sample_rate = sample_rate
        self.input_device = input_device
        self.window_samples = int(window_seconds * sample_rate)
        self.hop_samples = int(hop_seconds * sample_rate)
        self.positive_threshold = positive_threshold
        self.required_consecutive = required_consecutive
        self.min_rms = min_rms
        self.min_peak = min_peak
        self.max_gain = max_gain
        self.cooldown_seconds = cooldown_seconds
        self.debug = debug

        self._clf = None
        self._stream = None
        self._thread = None
        self._running = False
        self._stop_requested = threading.Event()
        self._thread_done = threading.Event()
        self._lock = threading.Lock()
        self._on_wake = None
        self._last_wake_time = 0.0
        self._consecutive_hits = 0

    # ---------- Public API ----------

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

    def stop(self, timeout: float = 2.0):
        self._stop_requested.set()
        self._thread_done.wait(timeout=timeout)
        with self._lock:
            self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    # ---------- Setup ----------

    def _load_model(self):
        if self._clf is not None:
            return
        if not self.model_path.exists():
            raise FileNotFoundError(f"Wake model not found: {self.model_path}")
        logger.info("Loading trained wake model from %s", self.model_path)
        with open(self.model_path, "rb") as f:
            data = pickle.load(f)
        self._clf = data["model"]
        logger.info("Wake model loaded.")

    # ---------- Main loop ----------

    def _run(self):
        try:
            self._load_model()
        except Exception:
            logger.exception("Failed to load wake model")
            self._thread_done.set()
            return

        try:
            self._stream = sd.InputStream(
                samplerate=self.sample_rate,
                channels=1,
                dtype="float32",
                blocksize=1600,
                device=self.input_device,
            )
            self._stream.start()
        except Exception:
            logger.exception("Failed to open mic for wake detector")
            self._thread_done.set()
            return

        logger.info(
            "Trained wake detector active (device=%s, p>=%.2f, hits=%d, "
            "peak>=%.3f, rms>=%.4f)",
            self.input_device, self.positive_threshold,
            self.required_consecutive, self.min_peak, self.min_rms,
        )

        buffer = np.zeros(self.window_samples, dtype=np.float32)
        samples_since_check = 0

        try:
            while not self._stop_requested.is_set():
                data, overflowed = self._stream.read(1600)
                chunk = data[:, 0] if data.ndim > 1 else data

                n = len(chunk)
                if n >= len(buffer):
                    buffer[:] = chunk[-len(buffer):]
                else:
                    buffer[:-n] = buffer[n:]
                    buffer[-n:] = chunk

                samples_since_check += n
                if samples_since_check < self.hop_samples:
                    continue
                samples_since_check = 0

                self._check(buffer)
        finally:
            try:
                if self._stream is not None:
                    self._stream.stop()
                    self._stream.close()
            except Exception:
                pass
            self._stream = None
            self._thread_done.set()
            logger.info("Trained wake detector stopped.")

    # ---------- Detection ----------

    def _check(self, buffer: np.ndarray):
        rms = float(np.sqrt(np.mean(buffer ** 2)))
        peak = float(np.max(np.abs(buffer))) if len(buffer) else 0.0

        # --- Hard gates: reject noise BEFORE running the classifier. ---
        # Real speech reliably has peak > 0.06 and rms > 0.008.
        # Ambient noise (fans, keyboard, breathing) rarely exceeds both.
        if rms < self.min_rms or peak < self.min_peak:
            self._consecutive_hits = 0
            return

        # Normalize amplitude for the classifier (features.py also
        # normalizes internally — this keeps the two in sync).
        gain = min(0.5 / max(peak, 0.001), self.max_gain)
        normalized = np.clip(buffer * gain, -1.0, 1.0).astype(np.float32)

        try:
            feats = extract_features(normalized, sr=self.sample_rate).reshape(1, -1)
            proba = self._clf.predict_proba(feats)[0]
            positive = float(proba[1]) if len(proba) > 1 else float(proba[0])
        except Exception:
            logger.exception("Wake classifier failed")
            return

        if self.debug:
            logger.info(
                "Wake check: p=%.2f (rms=%.4f, peak=%.4f, gain=%.1fx)",
                positive, rms, peak, gain,
            )

        if positive >= self.positive_threshold:
            self._consecutive_hits += 1
            if self._consecutive_hits >= self.required_consecutive:
                self._fire()
        else:
            self._consecutive_hits = 0

    def _fire(self):
        now = time.time()
        if now - self._last_wake_time < self.cooldown_seconds:
            return
        self._last_wake_time = now
        self._consecutive_hits = 0
        logger.info("Wake word detected (trained model).")
        if self._on_wake:
            try:
                self._on_wake()
            except Exception:
                logger.exception("Wake callback failed")