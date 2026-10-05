"""Coordinates: recorder + STT + translator + assistant + window + state."""
import logging
import threading
import time

from core.state import LumiState, StateManager

logger = logging.getLogger(__name__)


# Whisper hallucinates these on quiet/noisy audio, or when it hears
# YouTube/media outros. Reject before sending to the LLM.
_HALLUCINATIONS = {
    # YouTube/media boilerplate
    "thank you for watching",
    "thanks for watching",
    "please subscribe",
    "hit that like button",
    "like and subscribe",
    "please like and subscribe",
    "subscribe and hit",
    "amara.org",
    "subs by",
    "subtitle",
    "transcription by",
    "translated by",
    "music",
    "♪",
    # Indonesian media outros
    "terima kasih kerana menonton",
    "terima kasih telah menonton",
    "terima kasih sudah menonton",
    "sampai jumpa",
    # Filler-only
    "bye", "bye bye",
    "you", "yeah", "hmm", "mm", "uh", "um",
    "okay", "ok", "oh", "ah", "eh", "ha", "haha",
    "please", "...", "..", ".",
}

# If any of these phrases appear anywhere in the transcript,
# reject the whole utterance as a media hallucination.
_HALLUCINATION_SUBSTRINGS = (
    "thank you for watching",
    "thanks for watching",
    "please subscribe",
    "hit that like button",
    "like and subscribe",
    "amara.org",
    "terima kasih kerana menonton",
    "terima kasih telah menonton",
)


class MicController:
    def __init__(self, recorder, stt, assistant, state_manager: StateManager,
                 window, translator=None):
        self.recorder = recorder
        self.stt = stt
        self.translator = translator
        self.assistant = assistant
        self.state_manager = state_manager
        self.window = window
        self._lock = threading.Lock()
        self._transcribing = False
        self._auto_stop_thread: threading.Thread | None = None

    # ---------- Public ----------

    def toggle(self):
        if self.recorder.is_recording:
            self.stop_and_transcribe()
        else:
            self.start_recording()

    def start_recording(self):
        with self._lock:
            if self._transcribing:
                logger.info("Still transcribing; ignoring start.")
                return
            if self.recorder.is_recording:
                return
            if self.state_manager.state not in (LumiState.IDLE, LumiState.LISTENING):
                logger.info("Not IDLE (%s); ignoring mic start.",
                            self.state_manager.state.name)
                return
            if self.state_manager.state == LumiState.IDLE:
                self.state_manager.transition(LumiState.LISTENING)
            self.window.set_mic_recording(True)
            self.recorder.start()

    def wake_and_record(self, silence_seconds: float = 1.2, max_seconds: float = 12.0):
        time.sleep(0.15)
        self.start_recording()
        if not self.recorder.is_recording:
            return
        self._auto_stop_thread = threading.Thread(
            target=self._auto_stop_worker,
            args=(silence_seconds, max_seconds),
            daemon=True,
        )
        self._auto_stop_thread.start()

    def stop_and_transcribe(self):
        with self._lock:
            if not self.recorder.is_recording:
                return
            audio = self.recorder.stop()
            self.window.set_mic_recording(False)
            try:
                if self.state_manager.state == LumiState.LISTENING:
                    self.state_manager.transition(LumiState.IDLE)
            except Exception:
                pass

        if audio is None:
            logger.info("No audio captured; nothing to transcribe.")
            return

        self._transcribing = True
        threading.Thread(
            target=self._transcribe_worker, args=(audio,), daemon=True
        ).start()

    def cancel(self):
        with self._lock:
            self.recorder.cancel()
            self.window.set_mic_recording(False)
            try:
                if self.state_manager.state == LumiState.LISTENING:
                    self.state_manager.transition(LumiState.IDLE)
            except Exception:
                pass

    # ---------- Auto-stop ----------

    def _auto_stop_worker(self, silence_seconds: float, max_seconds: float):
        start = time.time()
        while time.time() - start < 3.0:
            if not self.recorder.is_recording:
                return
            if self.recorder.has_speech:
                break
            time.sleep(0.05)

        while time.time() - start < max_seconds:
            if not self.recorder.is_recording:
                return
            if self.recorder.has_speech and \
               self.recorder.silence_duration() >= silence_seconds:
                logger.info("Auto-stop: %.2fs of silence detected.", silence_seconds)
                self.stop_and_transcribe()
                return
            time.sleep(0.05)

        if self.recorder.is_recording:
            logger.info("Auto-stop: max recording time reached.")
            self.stop_and_transcribe()

    # ---------- Hallucination filter ----------

    @staticmethod
    def _is_hallucination(text: str) -> tuple[bool, str]:
        """
        Return (True, reason) if the transcript is a known hallucination
        pattern (e.g. YouTube outro playing through the speakers).
        """
        low = text.lower().strip().strip(".,!? \"'")

        if not low:
            return True, "empty"

        # Exact match
        if low in _HALLUCINATIONS:
            return True, "exact match in blocklist"

        # Substring — catches Whisper adding extra words around the outro
        for phrase in _HALLUCINATION_SUBSTRINGS:
            if phrase in low:
                return True, f"contains media phrase: {phrase!r}"

        # Very short filler — reject anything under 3 chars
        if len(low) < 3:
            return True, "too short"

        return False, ""

    # ---------- Transcribe → translate → send ----------

    def _transcribe_worker(self, audio):
        try:
            text = self.stt.transcribe(
                audio,
                language="auto",
                use_vad=False,
                no_speech_threshold=0.6,
                compression_ratio_threshold=2.4,
                initial_prompt=(
                    "Percakapan santai. Bahasa Indonesia atau Inggris. "
                    "Contoh: halo apa kabar, aku ga tahu, 1 tambah 1 berapa, "
                    "hey can you help me, what time is it."
                ),
            )
            logger.info("Transcribed: %r", text)

            if not text or len(text.strip()) < 2:
                self.window.set_user_text("(couldn't hear that — try again)")
                return

            # --- Hallucination filter ---
            bad, reason = self._is_hallucination(text)
            if bad:
                logger.warning("Rejected transcript (%s): %r", reason, text)
                self.window.set_user_text("(couldn't hear that — try again)")
                return

            # Show the raw transcript first
            self.window.set_user_text(text)

            # Normalize to English
            english = text
            if self.translator is not None:
                english = self.translator.normalize(text)
                if english and english != text:
                    logger.info("Normalized for LLM: %r", english)

            if not english or len(english.strip()) < 2:
                return

            self.assistant.send(english)
        except Exception:
            logger.exception("Transcription worker failed")
        finally:
            self._transcribing = False