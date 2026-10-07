"""
System tray icon and control panels for Lumi.

The tray is a control surface only. Security restrictions are displayed,
not weakened: protected files and command restrictions are informational,
while the existing terminal kill switch remains available.
"""
import logging
import os
import subprocess
import sys

from PIL import Image, ImageDraw
import pystray
from pystray import Menu, MenuItem

from config import config
from core.events import bus
from core.state import LumiState, StateManager
from storage import terminal_log
from tools.terminal_guard import guard

logger = logging.getLogger(__name__)


VOICE_PRESETS = (
    ("Bella", "af_bella"),
    ("Sarah", "af_sarah"),
    ("Mommy", "bf_emma"),
    ("Adam", "am_adam"),
    ("Michael", "am_michael"),
)

SPEED_PRESETS = (
    ("0.85x", 0.85),
    ("1.00x", 1.00),
    ("1.15x", 1.15),
    ("1.30x", 1.30),
)

PROTECTED_ITEMS = (
    "D:\\Lumi\\security",
    "D:\\Lumi\\main.py",
    "D:\\Lumi\\config.py",
    "D:\\Lumi\\.env",
    "D:\\Lumi\\core\\tool_router.py",
    "D:\\Lumi\\tools\\admin_tasks.py",
    "D:\\Lumi\\tools\\terminal_guard.py",
    "D:\\Lumi\\storage\\audit.py",
)

RESTRICTED_COMMAND_RULES = (
    "Unknown executables: denied by the terminal allowlist.",
    "File-modifying commands: require confirmation.",
    "Python/Node inline code: requires confirmation.",
    "pip/npm/cargo/go package installs: require confirmation.",
    "ADB/fastboot: require confirmation.",
    "Admin terminal: requires its separate security gate + UAC helper.",
    "Dangerous root/system patterns: denied outright.",
    "Protected paths: denied by the security path checks.",
)


def _make_icon_image() -> Image.Image:
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((8, 8, size - 8, size - 8), fill=(108, 99, 255, 255))
    return img


class TrayIcon:
    def __init__(self, state_manager: StateManager):
        self.state_manager = state_manager
        self._icon: pystray.Icon | None = None
        self._current_voice = getattr(config, "VOICE", "af_bella")
        self._current_speed = float(getattr(config, "SPEECH_SPEED", 1.0))

    # ---- state ----

    def _on_wake(self, icon, item):
        logger.info("Tray: Wake requested")
        self.state_manager.transition(LumiState.IDLE)

    def _on_sleep(self, icon, item):
        logger.info("Tray: Sleep requested")
        self.state_manager.transition(LumiState.SLEEPING)

    def _on_open(self, icon, item):
        logger.info("Tray: Open requested")
        self.state_manager.transition(LumiState.IDLE)

    # ---- voice ----

    def _set_voice(self, voice: str):
        self._current_voice = voice
        logger.info("Tray: TTS voice -> %s", voice)
        bus.emit("tts.voice_changed", voice=voice)
        if self._icon:
            self._icon.update_menu()

    def _set_speed(self, speed: float):
        self._current_speed = float(speed)
        logger.info("Tray: TTS speed -> %.2fx", speed)
        bus.emit("tts.speed_changed", speed=speed)
        if self._icon:
            self._icon.update_menu()

    # ---- terminal toggles ----

    def _on_toggle_terminal(self, icon, item):
        guard.toggle_enabled()
        terminal_log.log_state_change(guard.enabled, guard.paused)
        logger.warning("Tray: Terminal -> %s",
                       "ENABLED" if guard.enabled else "DISABLED")

    def _on_toggle_tools(self, icon, item):
        guard.toggle_paused()
        terminal_log.log_state_change(guard.enabled, guard.paused)
        logger.warning("Tray: Tools -> %s",
                       "PAUSED" if guard.paused else "ACTIVE")

    def _on_open_terminal_log(self, icon, item):
        path = terminal_log.get_log_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.touch()
            if sys.platform == "win32":
                os.startfile(str(path))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(path)])
            logger.info("Tray: opened %s", path)
        except Exception:
            logger.exception("Failed to open terminal log")

    # ---- informational security panels ----

    def _open_protected_files(self, icon, item):
        logger.info("Tray: Protected Files panel requested")
        for path in PROTECTED_ITEMS:
            logger.info("Protected: %s", path)

    def _open_restricted_commands(self, icon, item):
        logger.info("Tray: Restricted Commands panel requested")
        for rule in RESTRICTED_COMMAND_RULES:
            logger.info("Restriction: %s", rule)

    # ---- misc ----

    def _on_exit(self, icon, item):
        logger.info("Tray: Exit requested")
        self.state_manager.transition(LumiState.STOPPING)
        if self._icon:
            self._icon.stop()

    # ---- dynamic labels ----

    @staticmethod
    def _label_terminal(item):
        return f"Terminal: {'Enabled' if guard.enabled else 'Disabled'}"

    @staticmethod
    def _label_tools(item):
        return f"Tools: {'Paused' if guard.paused else 'Active'}"

    @staticmethod
    def _label_status(item):
        return "Lumi: Listening for wake word" if config.WAKE_ENABLED else "Lumi: Wake word disabled"

    def _voice_menu(self):
        items = []
        for name, voice in VOICE_PRESETS:
            items.append(MenuItem(
                lambda item, n=name, v=voice: f"{'✓ ' if self._current_voice == v else ''}{n}",
                lambda icon, item, v=voice: self._set_voice(v),
            ))
        items.append(Menu.SEPARATOR)
        items.append(MenuItem("Speech speed", Menu(*[
            MenuItem(
                lambda item, n=name, s=speed: f"{'✓ ' if abs(self._current_speed - s) < 0.001 else ''}{n}",
                lambda icon, item, s=speed: self._set_speed(s),
            )
            for name, speed in SPEED_PRESETS
        ])))
        return Menu(*items)

    def _security_menu(self):
        protected = Menu(*[MenuItem(path, None, enabled=False) for path in PROTECTED_ITEMS])
        restrictions = Menu(*[MenuItem(rule, None, enabled=False) for rule in RESTRICTED_COMMAND_RULES])
        return Menu(
            MenuItem(self._label_terminal, self._on_toggle_terminal),
            MenuItem(self._label_tools, self._on_toggle_tools),
            MenuItem("Protected files", protected),
            MenuItem("Restricted commands", restrictions),
            MenuItem("Open terminal log", self._on_terminal_log_wrapper),
        )

    def run(self):
        menu = Menu(
            MenuItem(self._label_status, None, enabled=False),
            Menu.SEPARATOR,
            MenuItem("Wake", self._on_wake),
            MenuItem("Sleep", self._on_sleep),
            MenuItem("Open Lumi", self._on_open),
            MenuItem("Voice", self._voice_menu()),
            MenuItem("Security", self._security_menu()),
            Menu.SEPARATOR,
            MenuItem("Exit", self._on_exit),
        )
        self._icon = pystray.Icon(
            "Lumi", _make_icon_image(), "Lumi — Desktop Companion", menu,
        )
        self._icon.run()

    def _on_terminal_log_wrapper(self, icon, item):
        self._on_open_terminal_log(icon, item)
