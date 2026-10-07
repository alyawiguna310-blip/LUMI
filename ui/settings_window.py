"""Qt control panel for Lumi's desktop settings.

This is a UI-only control surface. Protected paths and restricted commands
are displayed read-only; no security boundary is changed by this window.
"""
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget, QLabel,
    QComboBox, QSlider, QPushButton, QGroupBox, QListWidget, QListWidgetItem,
    QCheckBox,
)

from config import config
from core.events import bus
from core.state import LumiState, StateManager
from tools.terminal_guard import guard


VOICE_PRESETS = (
    ("Bella", "af_bella"),
    ("Sarah", "af_sarah"),
    ("Mommy", "bf_emma"),
    ("Adam", "am_adam"),
    ("Michael", "am_michael"),
)

SPEED_PRESETS = (0.85, 1.00, 1.15, 1.30)

PROTECTED_ITEMS = (
    r"D:\Lumi\security",
    r"D:\Lumi\main.py",
    r"D:\Lumi\config.py",
    r"D:\Lumi\.env",
    r"D:\Lumi\core\tool_router.py",
    r"D:\Lumi\tools\admin_tasks.py",
    r"D:\Lumi\tools\terminal_guard.py",
    r"D:\Lumi\storage\audit.py",
)

RESTRICTED_COMMAND_RULES = (
    "Unknown executables: denied by the terminal allowlist.",
    "File-modifying commands: require confirmation.",
    "Python/Node inline code: requires confirmation.",
    "pip/npm/cargo/go package installs: require confirmation.",
    "ADB/fastboot: require confirmation.",
    "Admin terminal: separate security gate + UAC helper.",
    "Dangerous root/system patterns: denied outright.",
    "Protected paths: denied by security path checks.",
)


class SettingsWindow(QDialog):
    request_wake = pyqtSignal()
    request_sleep = pyqtSignal()

    def __init__(self, state_manager: StateManager, parent=None):
        super().__init__(parent)
        self.state_manager = state_manager
        self.setWindowTitle("Lumi Control Panel")
        self.setMinimumSize(540, 520)
        self.setModal(False)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
        self._build_ui()
        self._refresh_security()

    def _build_ui(self):
        root = QVBoxLayout(self)
        title = QLabel("Lumi Control Panel")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")
        root.addWidget(title)

        tabs = QTabWidget()
        root.addWidget(tabs)

        voice_tab = QWidget()
        voice = QVBoxLayout(voice_tab)

        box = QGroupBox("Voice")
        form = QVBoxLayout(box)
        self.voice_combo = QComboBox()
        for name, value in VOICE_PRESETS:
            self.voice_combo.addItem(name, value)
        current_voice = getattr(config, "VOICE", "af_bella")
        idx = self.voice_combo.findData(current_voice)
        if idx >= 0:
            self.voice_combo.setCurrentIndex(idx)
        self.voice_combo.currentIndexChanged.connect(self._voice_changed)
        form.addWidget(QLabel("Voice"))
        form.addWidget(self.voice_combo)

        speed_row = QHBoxLayout()
        speed_row.addWidget(QLabel("Speech speed"))
        self.speed_slider = QSlider(Qt.Orientation.Horizontal)
        self.speed_slider.setRange(85, 130)
        self.speed_slider.setValue(round(float(getattr(config, "SPEECH_SPEED", 1.0)) * 100))
        self.speed_value = QLabel(f"{self.speed_slider.value() / 100:.2f}x")
        self.speed_slider.valueChanged.connect(self._speed_changed)
        speed_row.addWidget(self.speed_slider, 1)
        speed_row.addWidget(self.speed_value)
        form.addLayout(speed_row)

        voice.addWidget(box)

        wake_box = QGroupBox("Wake word")
        wake_layout = QVBoxLayout(wake_box)
        status = QLabel(
            "Enabled — say “Lumi” while sleeping."
            if config.WAKE_ENABLED
            else "Disabled in configuration."
        )
        wake_layout.addWidget(status)
        buttons = QHBoxLayout()
        wake_btn = QPushButton("Wake Lumi")
        sleep_btn = QPushButton("Sleep Lumi")
        wake_btn.clicked.connect(lambda: self.state_manager.transition(LumiState.IDLE))
        sleep_btn.clicked.connect(lambda: self.state_manager.transition(LumiState.SLEEPING))
        buttons.addWidget(wake_btn)
        buttons.addWidget(sleep_btn)
        wake_layout.addLayout(buttons)
        voice.addWidget(wake_box)

        voice.addStretch()
        tabs.addTab(voice_tab, "Voice & Wake")

        sec_tab = QWidget()
        sec = QVBoxLayout(sec_tab)

        state_box = QGroupBox("Command controls")
        state_layout = QVBoxLayout(state_box)
        self.terminal_check = QCheckBox()
        self.terminal_check.setChecked(guard.enabled)
        self.terminal_check.stateChanged.connect(self._terminal_changed)
        self.tools_check = QCheckBox()
        self.tools_check.setChecked(not guard.paused)
        self.tools_check.stateChanged.connect(self._tools_changed)
        state_layout.addWidget(self.terminal_check)
        state_layout.addWidget(self.tools_check)
        sec.addWidget(state_box)

        protected_box = QGroupBox("Protected files — read only")
        protected_layout = QVBoxLayout(protected_box)
        protected_list = QListWidget()
        for path in PROTECTED_ITEMS:
            QListWidgetItem(path, protected_list)
        protected_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        protected_layout.addWidget(protected_list)
        sec.addWidget(protected_box)

        restricted_box = QGroupBox("Restricted commands — read only")
        restricted_layout = QVBoxLayout(restricted_box)
        restricted_list = QListWidget()
        for rule in RESTRICTED_COMMAND_RULES:
            QListWidgetItem(rule, restricted_list)
        restricted_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        restricted_layout.addWidget(restricted_list)
        sec.addWidget(restricted_box)

        tabs.addTab(sec_tab, "Security")

        close_row = QHBoxLayout()
        close_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.hide)
        close_row.addWidget(close_btn)
        root.addLayout(close_row)

        self.setStyleSheet("""
            QDialog { background: #15151c; color: #f4f4f5; }
            QGroupBox {
                border: 1px solid #333342;
                border-radius: 10px;
                margin-top: 10px;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
            }
            QComboBox, QListWidget {
                background: #20202a;
                color: #f4f4f5;
                border: 1px solid #3a3a4a;
                border-radius: 7px;
                padding: 5px;
            }
            QPushButton {
                background: #2b2940;
                color: #ffffff;
                border: 1px solid #4a4668;
                border-radius: 7px;
                padding: 7px 12px;
            }
            QPushButton:hover { background: #383451; }
            QCheckBox { spacing: 8px; }
        """)

    def _voice_changed(self, index):
        voice = self.voice_combo.itemData(index)
        if voice:
            bus.emit("tts.voice_changed", voice=voice)

    def _speed_changed(self, value):
        speed = value / 100.0
        self.speed_value.setText(f"{speed:.2f}x")
        bus.emit("tts.speed_changed", speed=speed)

    def _terminal_changed(self, state):
        enabled = state == int(Qt.CheckState.Checked)
        if enabled != guard.enabled:
            guard.toggle_enabled()

    def _tools_changed(self, state):
        active = state == int(Qt.CheckState.Checked)
        paused = not active
        if paused != guard.paused:
            guard.toggle_paused()

    def _refresh_security(self):
        self.terminal_check.setChecked(guard.enabled)
        self.tools_check.setChecked(not guard.paused)

    def show_panel(self):
        self._refresh_security()
        self.show()
        self.raise_()
        self.activateWindow()
