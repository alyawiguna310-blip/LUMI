"""
Live monitoring + kill switch for terminal commands.

Global singleton used by:
  - tools/terminal.py    (checks enabled / paused / rate)
  - ui/tray.py           (menu items toggle state)
  - ui/minimal_window.py (receives events via event bus)
"""
import logging
import threading
import time
from collections import deque

from core.events import bus

logger = logging.getLogger(__name__)


class TerminalGuard:
    def __init__(self,
                 max_commands_per_minute: int = 30,
                 burst_limit_10s: int = 8):
        self._lock = threading.Lock()
        self._enabled = True
        self._paused = False
        self._history: deque[float] = deque(maxlen=200)
        self._max_per_min = max_commands_per_minute
        self._burst_limit = burst_limit_10s

    # ---------- state ----------

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    @property
    def paused(self) -> bool:
        with self._lock:
            return self._paused

    def set_enabled(self, value: bool):
        with self._lock:
            self._enabled = bool(value)
        logger.warning("Terminal %s", "ENABLED" if self._enabled else "DISABLED")
        bus.emit("terminal.state_changed",
                 enabled=self._enabled, paused=self._paused)

    def toggle_enabled(self):
        self.set_enabled(not self.enabled)

    def set_paused(self, value: bool):
        with self._lock:
            self._paused = bool(value)
        logger.warning("Tools %s", "PAUSED" if self._paused else "ACTIVE")
        bus.emit("terminal.state_changed",
                 enabled=self._enabled, paused=self._paused)

    def toggle_paused(self):
        self.set_paused(not self.paused)

    # ---------- rate check ----------

    def check_rate(self) -> tuple[bool, str]:
        """Return (ok, reason). Non-consuming check."""
        now = time.time()
        with self._lock:
            # keep only last 60s
            while self._history and now - self._history[0] > 60:
                self._history.popleft()
            recent = list(self._history)

        last_10s = [t for t in recent if now - t <= 10]
        if len(last_10s) >= self._burst_limit:
            return False, (
                f"burst detected: {len(last_10s)} commands in the last "
                f"10 seconds"
            )
        if len(recent) >= self._max_per_min:
            return False, (
                f"rate limit reached: {len(recent)} commands in the last "
                f"60 seconds"
            )
        return True, ""

    def record_command(self):
        with self._lock:
            self._history.append(time.time())


# Singleton — importable by any module
guard = TerminalGuard()