"""
Wake-word detector using openWakeWord with a custom-trained 'lumi' model.
~2% CPU while running. Works offline.
"""
import logging
import threading
import time
from pathlib import Path

import numpy as np
import sounddevice as sd

logger = logging.getLogger(__name__)


class OpenWakeWordDetector:
    def __init__(self, model_path: Path,
                 sample_rate: int = 16000,
                 input_device: int | None = None,
                 threshold: float = 0.55,
                 cooldown_seconds: float = 2.5,
                 debug: bool = True):
        self.model_path = Path(model_path)
        self.sample_rate = sample_rate
        self.input_device = input_device
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        self.debug = debug

        self._model = None
        self._stream = None
        self._thread = None
        self._running = False
        self._stop_requested = threading.Event()
        self._thread_done = threading.Event()
        self._lock = threading.Lock()
        self._on_wake = None
        self._last_wake_time = 0.0

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

    def _load_model(self):
        if self._model is not None:
            return
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"openWakeWord model not found: {self.model_path}"
            )
        from openwakeword.model import Model
        import inspect
        logger.info("Loading openWakeWord model: %s", self.model_path)
        if "wakeword_model_paths" in inspect.signature(Model.__init__).parameters:
            self._model = Model(wakeword_model_paths=[str(self.model_path)])
        else:
            self._model = Model(
                wakeword_models=[str(self.model_path)],
                inference_framework="onnx",
            )
        logger.info("openWakeWord model loaded.")

    def _run(self):
        try:
            self._load_model()
        except Exception:
            logger.exception("Failed to load openWakeWord model")
            self._thread_done.set()
            return

        chunk = 1280   # 80 ms @ 16 kHz

        try:
            self._stream = sd.RawInputStream(
                samplerate=self.sample_rate,
                channels=1,
                dtype="int16",
                blocksize=chunk,
                device=self.input_device,
            )
            self._stream.start()
        except Exception:
            logger.exception("Failed to open mic for openWakeWord")
            self._thread_done.set()
            return

        logger.info(
            "openWakeWord active (device=%s, threshold=%.2f, model=%s)",
            self.input_device, self.threshold, self.model_path.name,
        )

        try:
            while not self._stop_requested.is_set():
                data, overflowed = self._stream.read(chunk)
                pcm = np.frombuffer(bytes(data), dtype=np.int16)
                try:
                    scores = self._model.predict(pcm)
                except Exception:
                    logger.exception("openWakeWord predict failed")
                    continue

                best_score = max(scores.values()) if scores else 0.0

                if self.debug and best_score > 0.2:
                    logger.info("OWW score: %.3f", best_score)

                if best_score >= self.threshold:
                    now = time.time()
                    if now - self._last_wake_time < self.cooldown_seconds:
                        continue
                    self._last_wake_time = now
                    logger.info("Wake word detected (openWakeWord, score=%.3f)",
                                best_score)
                    if self._on_wake:
                        try:
                            self._on_wake()
                        except Exception:
                            logger.exception("Wake callback failed")
        finally:
            try:
                if self._stream is not None:
                    self._stream.stop()
                    self._stream.close()
            except Exception:
                pass
            self._stream = None
            self._thread_done.set()
            logger.info("openWakeWord stopped.")

    def set_sensitivity(self, threshold: float):
        self.threshold = max(0.0, min(1.0, threshold))