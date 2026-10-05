"""Global push-to-talk hotkey using pynput."""
import logging

from pynput import keyboard

logger = logging.getLogger(__name__)


def parse_hotkey(spec: str) -> list[set]:
    """
    Parse '<ctrl>+<alt>+l' into a list of key-groups.
    Each group is a set of equivalent keys (e.g. {ctrl_l, ctrl_r}).
    A hotkey is "active" when every group has at least one key held.
    """
    groups: list[set] = []
    for token in spec.split("+"):
        token = token.strip().lower()
        if not token:
            continue
        if token.startswith("<") and token.endswith(">"):
            name = token[1:-1]
            mapping = {
                "ctrl": {keyboard.Key.ctrl_l, keyboard.Key.ctrl_r},
                "alt": {keyboard.Key.alt_l, keyboard.Key.alt_r, keyboard.Key.alt_gr},
                "shift": {keyboard.Key.shift_l, keyboard.Key.shift_r},
                "cmd": {keyboard.Key.cmd_l, keyboard.Key.cmd_r},
                "win": {keyboard.Key.cmd_l, keyboard.Key.cmd_r},
            }
            if name in mapping:
                groups.append(mapping[name])
                continue
            logger.warning("Unknown hotkey token: <%s>", name)
            continue
        # Single character key
        groups.append({keyboard.KeyCode.from_char(token)})
    return groups


class PushToTalkHotkey:
    """
    Listens for a hotkey combination globally.
    Calls on_press when the combo becomes held, and on_release when it stops.
    """

    def __init__(self, hotkey_spec: str, on_press, on_release):
        self._groups = parse_hotkey(hotkey_spec)
        self.hotkey_spec = hotkey_spec
        self.on_press = on_press
        self.on_release = on_release
        self._held: set = set()
        self._active = False
        self._listener = None

    def _is_active(self) -> bool:
        return all(any(k in self._held for k in group) for group in self._groups)

    def start(self):
        self._listener = keyboard.Listener(
            on_press=self._handle_press,
            on_release=self._handle_release,
        )
        self._listener.daemon = True
        self._listener.start()
        logger.info("Push-to-talk hotkey active: %s", self.hotkey_spec)

    def _handle_press(self, key):
        self._held.add(key)
        if not self._active and self._is_active():
            self._active = True
            try:
                self.on_press()
            except Exception:
                logger.exception("Hotkey on_press failed")

    def _handle_release(self, key):
        self._held.discard(key)
        if self._active and not self._is_active():
            self._active = False
            try:
                self.on_release()
            except Exception:
                logger.exception("Hotkey on_release failed")

    def stop(self):
        if self._listener is not None:
            self._listener.stop()
            self._listener = None