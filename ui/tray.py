"""
System tray icon and menu for Lumi.
"""
import logging
import os
import subprocess
import sys
from PIL import Image, ImageDraw
import pystray
from pystray import Menu, MenuItem

from core.state import LumiState, StateManager
from storage import terminal_log
from tools.terminal_guard import guard

logger = logging.getLogger(__name__)


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

    def run(self):
        menu = Menu(
            MenuItem("Wake", self._on_wake),
            MenuItem("Sleep", self._on_sleep),
            MenuItem("Open", self._on_open),
            Menu.SEPARATOR,
            MenuItem(self._label_terminal, self._on_toggle_terminal),
            MenuItem(self._label_tools, self._on_toggle_tools),
            MenuItem("Open terminal log", self._on_terminal_log_wrapper),
            Menu.SEPARATOR,
            MenuItem("Exit", self._on_exit),
        )
        self._icon = pystray.Icon(
            "Lumi", _make_icon_image(),
            "Lumi — Desktop Companion", menu,
        )
        self._icon.run()

    # pystray's dynamic-label mechanism sends a MenuItem as the callback
    # argument sometimes; wrap to be safe.
    def _on_terminal_log_wrapper(self, icon, item):
        self._on_open_terminal_log(icon, item)