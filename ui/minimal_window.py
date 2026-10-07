"""Minimal, frameless, animated caption-style window with mic button and live activity."""
from PyQt6.QtCore import (
    Qt, QObject, pyqtSignal, QPropertyAnimation, QEasingCurve, QTimer,
)
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QLabel,
    QGraphicsOpacityEffect,
    QApplication,
    QFileDialog,
)

from ai.attachments import validate_image
from core.events import EventBus
from core.state import LumiState, StateManager
from ui import themes
from ui.caption_label import CaptionLabel
from ui.lumi_character import LumiCharacter
from ui.settings_window import SettingsWindow


_CHROME_HEIGHT = 100   # bumped from 80 to fit the activity line


class AttachmentInput(str):
    def __new__(cls, text, attachment_path=""):
        obj = str.__new__(cls, text)
        obj.attachment_path = attachment_path
        return obj


class _UiSignals(QObject):
    state_changed = pyqtSignal(object, object)
    response_ready = pyqtSignal(str)
    error_ready = pyqtSignal(str)
    user_text_ready = pyqtSignal(str)
    mic_state_changed = pyqtSignal(bool)
    activity_started = pyqtSignal(str)
    activity_finished = pyqtSignal()
    open_settings = pyqtSignal()


class MinimalWindow(QWidget):
    def __init__(
        self,
        state_manager: StateManager,
        event_bus: EventBus,
        on_user_input,
        on_mic_clicked,
    ):
        super().__init__()
        self.state_manager = state_manager
        self.event_bus = event_bus
        self._on_user_input = on_user_input
        self._on_mic_clicked = on_mic_clicked
        self._pending_attachment = ""
        self._drag_active = False

        self.setAcceptDrops(True)

        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedWidth(themes.WINDOW_WIDTH)
        self.setFixedHeight(themes.WINDOW_HEIGHT)
        self.setWindowOpacity(0.0)

        # Activity-hide timer
        self._activity_timer = QTimer(self)
        self._activity_timer.setSingleShot(True)
        self._activity_timer.timeout.connect(self._hide_activity)

        self._build_ui()
        self._apply_style()
        self._wire_signals()
        self._setup_fade()
        self.hide()

    # ---------- Fade ----------

    def _setup_fade(self):
        self._fade = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade.setDuration(230)
        self._fade.setEasingCurve(QEasingCurve.Type.InOutQuad)

    def _fade_in(self):
        self._fade.stop()
        self.setWindowOpacity(0.0)
        self.show()
        self.raise_()
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.start()

    def _fade_out(self):
        if not self.isVisible():
            return
        self._fade.stop()
        self._fade.setStartValue(self.windowOpacity())
        self._fade.setEndValue(0.0)
        try:
            self._fade.finished.disconnect()
        except Exception:
            pass
        self._fade.finished.connect(self._after_fade_out)
        self._fade.start()

    def _after_fade_out(self):
        try:
            self._fade.finished.disconnect(self._after_fade_out)
        except Exception:
            pass
        self.hide()

    # ---------- Signals ----------

    def _wire_signals(self):
        self._signals = _UiSignals()
        self._signals.state_changed.connect(self._on_state_change)
        self._signals.response_ready.connect(self._on_response)
        self._signals.error_ready.connect(self._on_error)
        self._signals.user_text_ready.connect(self._on_user_text)
        self._signals.mic_state_changed.connect(self._on_mic_state)
        self._signals.activity_started.connect(self._on_activity_started)
        self._signals.activity_finished.connect(self._on_activity_finished)
        self._signals.open_settings.connect(self._show_settings)

        self.state_manager.add_observer(
            lambda old, new: self._signals.state_changed.emit(old, new)
        )
        self.event_bus.subscribe(
            "assistant_response",
            lambda text: self._signals.response_ready.emit(text),
        )
        self.event_bus.subscribe(
            "assistant_error",
            lambda message: self._signals.error_ready.emit(message),
        )
        self.event_bus.subscribe(
            "open_settings",
            lambda: self._signals.open_settings.emit(),
        )
        # Live activity — any tool call
        self.event_bus.subscribe(
            "tool_call_requested",
            lambda name, arguments: self._signals.activity_started.emit(name),
        )
        self.event_bus.subscribe(
            "tool_call_completed",
            lambda name, result: self._signals.activity_finished.emit(),
        )
        # Terminal kill switch state changes
        self.event_bus.subscribe(
            "terminal.state_changed",
            lambda enabled, paused: self._signals.activity_started.emit(
                "terminal DISABLED" if not enabled
                else ("tools PAUSED" if paused else "")
            ),
        )

    # ---------- Control panel ----------

    def _show_settings(self):
        if not hasattr(self, "_settings_window") or self._settings_window is None:
            self._settings_window = SettingsWindow(
                state_manager=self.state_manager,
                parent=self,
            )
        self._settings_window.show_panel()

    # ---------- UI ----------

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 14, 18, 12)
        outer.setSpacing(6)

        # Activity line (small, top)
        self.activity_label = QLabel("", self)
        self.activity_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.activity_label.setFixedHeight(16)
        outer.addWidget(self.activity_label)

        # Character + caption
        top = QHBoxLayout()
        top.setSpacing(10)
        self.character = LumiCharacter(self)
        top.addWidget(self.character, alignment=Qt.AlignmentFlag.AlignTop)
        self.label = CaptionLabel(self)
        top.addWidget(self.label, stretch=1)
        outer.addLayout(top, stretch=1)

        # Input + mic
        bottom = QHBoxLayout()
        bottom.setSpacing(6)

        self.input = QLineEdit(self)
        self.input.setPlaceholderText("type or speak...")
        self.input.returnPressed.connect(self._on_submit)
        bottom.addWidget(self.input, stretch=1)

        self.attach_btn = QPushButton("📎", self)
        self.attach_btn.setFixedSize(28, 28)
        self.attach_btn.clicked.connect(self._on_attach_click)
        self.attach_btn.setToolTip("Attach an image")
        bottom.addWidget(self.attach_btn)

        self.mic_btn = QPushButton("◉", self)
        self.mic_btn.setFixedSize(28, 28)
        self.mic_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mic_btn.setToolTip("Click to record (or hold Ctrl+Alt+L)")
        self.mic_btn.clicked.connect(self._on_mic_click)
        bottom.addWidget(self.mic_btn)

        outer.addLayout(bottom)

        self._input_effect = QGraphicsOpacityEffect(self.input)
        self._input_effect.setOpacity(1.0)
        self.input.setGraphicsEffect(self._input_effect)

    def _apply_style(self):
        font = QFont(themes.FONT_FAMILY, themes.FONT_SIZE)

        self.activity_label.setFont(QFont(themes.FONT_FAMILY, 8))
        self.activity_label.setStyleSheet(
            "color: #6c63ff; background: transparent;"
        )

        self.input.setFont(font)
        self.input.setStyleSheet(
            f"""
            QLineEdit {{
                background: {themes.INPUT_BG};
                color: #ffffff;
                border: 1px solid {themes.INPUT_BORDER};
                border-radius: 10px;
                padding: 6px 10px;
            }}
            QLineEdit:focus {{
                border: 1px solid {themes.ACCENT};
            }}
            """
        )

        self.mic_btn.setStyleSheet(
            """
            QPushButton {
                background: rgba(0, 0, 0, 120);
                color: #ffffff;
                border: 1px solid rgba(160, 160, 160, 90);
                border-radius: 14px;
                font-size: 14px;
                padding: 0;
            }
            QPushButton:hover { border: 1px solid #6c63ff; }
            QPushButton[recording="true"] {
                background: #cc3344;
                border: 1px solid #ff5566;
            }
            """
        )

    # ---------- Activity line ----------

    def _on_activity_started(self, name: str):
        if not name:
            return
        self.activity_label.setText(f"◦ running: {name}")
        self._activity_timer.stop()

    def _on_activity_finished(self):
        # Keep the last message visible for 2s so the user sees it
        self._activity_timer.start(2000)

    def _hide_activity(self):
        self.activity_label.setText("")

    # ---------- Auto-resize ----------

    def _resize_to_content(self):
        margins = self.layout().contentsMargins()
        char_w = self.character.width() if hasattr(self, "character") else 64
        top_layout_spacing = 10
        label_w = (
            self.width()
            - margins.left() - margins.right()
            - char_w - top_layout_spacing
        )
        label_w = max(80, label_w)

        content_h = self.label.preferred_height(width=label_w)
        desired = content_h + _CHROME_HEIGHT

        screen = QApplication.primaryScreen()
        if screen is not None:
            max_h = int(screen.availableGeometry().height() *
                        themes.WINDOW_MAX_HEIGHT_FRACTION)
        else:
            max_h = 900

        new_h = max(themes.WINDOW_HEIGHT, min(desired, max_h))
        if self.height() != new_h:
            self.setFixedHeight(new_h)

    # ---------- Emotion detection ----------

    @staticmethod
    def _detect_emotion(text: str) -> str:
        if not text:
            return "neutral"
        low = text.lower()
        if any(w in low for w in ("hmph", "ugh", "whatever", "annoyed", "seriously")):
            return "annoyed"
        if text.startswith("...") or text.startswith(".."):
            return "annoyed"
        if "?" in text and any(
            low.startswith(w) for w in ("what", "huh", "why", "how")
        ):
            return "confused"
        if "!" in text:
            return "happy"
        return "neutral"

    # ---------- State ----------

    def _on_state_change(self, old: LumiState, new: LumiState):
        if new == LumiState.SLEEPING:
            self.character.set_emotion("sleepy")
            self.character.set_speaking(False)
            self._fade_out()
        elif new in (LumiState.IDLE, LumiState.LISTENING):
            self.character.set_emotion(
                "confused" if new == LumiState.LISTENING else "neutral"
            )
            self.character.set_speaking(False)
            self.input.show()
            self.mic_btn.show()
            self._fade_in()
            self.input.setFocus()
        elif new == LumiState.THINKING:
            self.character.set_emotion("thinking")
            self.input.hide()
            self.mic_btn.hide()
            self.label.setText("...")
            self._resize_to_content()
        elif new == LumiState.SPEAKING:
            self.character.set_speaking(True)
            self.input.hide()
            self.mic_btn.hide()
        elif new == LumiState.ERROR:
            self.character.set_emotion("confused")
            self.character.set_speaking(False)
            self.input.hide()
            self.mic_btn.hide()
            if not self.isVisible():
                self._fade_in()

    # ---------- Response / error ----------

    def _on_response(self, text: str):
        emotion = self._detect_emotion(text)
        if emotion != "neutral":
            self.character.set_emotion(emotion)
        self.label.animateText(text, cps=60)
        self._resize_to_content()

    def _on_error(self, message: str):
        self.character.set_emotion("confused")
        self.label.setText(message)
        self._resize_to_content()
        if not self.isVisible():
            self._fade_in()

    def _on_user_text(self, text: str):
        self.label.setText(f"you: {text}")
        self.character.set_emotion("neutral")
        self._resize_to_content()

    def _on_mic_state(self, recording: bool):
        self.mic_btn.setProperty("recording", "true" if recording else "false")
        self.mic_btn.style().unpolish(self.mic_btn)
        self.mic_btn.style().polish(self.mic_btn)
        self.mic_btn.setText("■" if recording else "◉")

    def set_user_text(self, text: str):
        self._signals.user_text_ready.emit(text)

    def set_mic_recording(self, recording: bool):
        self._signals.mic_state_changed.emit(recording)

    # ---------- Input ----------

    def _on_submit(self):
        text = self.input.text().strip()
        if not text:
            return
        self.input.clear()
        attachment_path = getattr(self, "_pending_attachment", "")
        self._pending_attachment = ""
        self.input.setPlaceholderText("type or speak...")
        low = text.lower()
        if low in ("sleep", "lumi, sleep", "go to sleep"):
            self.state_manager.transition(LumiState.SLEEPING)
            return
        if low in ("clear", "reset", "forget"):
            self.event_bus.emit("assistant_reset")
            self.label.setText("...fine. Forgotten.")
            self._resize_to_content()
            return
        self.label.setText(f"you: {text}")
        self.character.set_emotion("neutral")
        self._resize_to_content()
        self._on_user_input(AttachmentInput(text, attachment_path))

    def _set_attachment(self, path: str):
        ok, _mime, error = validate_image(path)
        if not ok:
            self.label.setText(f"attachment rejected: {error}")
            self._resize_to_content()
            return False
        self._pending_attachment = path
        self.input.setPlaceholderText("Image attached — type your question...")
        self.label.setText("attachment ready — type your question")
        self._resize_to_content()
        return True

    def _on_attach_click(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Attach an image",
            "",
            "Images (*.png *.jpg *.jpeg *.webp *.heic *.heif)",
        )
        if path:
            self._set_attachment(path)

    # ---------- Drag and drop ----------

    def dragEnterEvent(self, event):
        mime = event.mimeData()
        if mime.hasUrls() and any(
            url.isLocalFile() for url in mime.urls()
        ):
            event.acceptProposedAction()
            self._drag_active = True
            self.label.setText("drop an image on Lumi...")
            self._resize_to_content()
            return
        event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self._drag_active = False
        if not self._pending_attachment:
            self.label.setText("")
        event.accept()

    def dropEvent(self, event):
        self._drag_active = False
        paths = [
            url.toLocalFile()
            for url in event.mimeData().urls()
            if url.isLocalFile()
        ]
        if not paths:
            event.ignore()
            return

        # The current vision pipeline accepts one image per message.
        image_path = next(
            (path for path in paths if validate_image(path)[0]),
            "",
        )
        if not image_path:
            self.label.setText("drop rejected — use a supported image")
            self._resize_to_content()
            event.ignore()
            return

        self._set_attachment(image_path)
        event.acceptProposedAction()

    # ---------- Mouse ----------

    def _on_mic_click(self):
        if self._on_mic_clicked is not None:
            self._on_mic_clicked()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            handle = self.windowHandle()
            if handle is not None:
                handle.startSystemMove()
            event.accept()
