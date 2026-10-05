"""
Qt bridge for security confirmations.

Shows a modal dialog with a smart target line:
  - 'path' argument    -> show the path
  - 'command' argument -> show the joined command line
  - else               -> show key=value pairs from arguments
"""
import threading
import logging

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QMessageBox

from security.confirmation import (
    ConfirmationRequest, ConfirmationResponse,
)

logger = logging.getLogger(__name__)


def _format_target(args: dict) -> str:
    if not args:
        return "?"

    if "path" in args:
        return str(args["path"])
    if "target" in args:
        return str(args["target"])

    if "command" in args:
        cmd = args["command"]
        if isinstance(cmd, list):
            cmd_str = " ".join(str(c) for c in cmd)
        else:
            cmd_str = str(cmd)
        cwd = args.get("cwd")
        if cwd:
            return f"{cmd_str}   (cwd={cwd})"
        return cmd_str

    if "task" in args:
        return str(args["task"])

    # Fallback
    parts = []
    for k, v in args.items():
        s = str(v)
        if len(s) > 60:
            s = s[:57] + "..."
        parts.append(f"{k}={s}")
    return "  ".join(parts) or "?"


class QtConfirmationBridge(QObject):
    _signal = pyqtSignal(object)

    def __init__(self, parent=None, timeout_seconds: int = 60):
        super().__init__(parent)
        self.timeout = timeout_seconds
        self._parent = parent
        self._result: ConfirmationResponse | None = None
        self._event = threading.Event()
        self._signal.connect(self._show_dialog)

    def request(self, req: ConfirmationRequest) -> ConfirmationResponse:
        self._result = None
        self._event.clear()
        self._signal.emit(req)
        if not self._event.wait(timeout=self.timeout):
            logger.warning("Confirmation timed out for %s", req.tool_name)
            return ConfirmationResponse(approved=False, note="timeout")
        return self._result or ConfirmationResponse(
            approved=False, note="no result"
        )

    def _show_dialog(self, req: ConfirmationRequest):
        try:
            target = _format_target(req.arguments)
            msg = QMessageBox(self._parent)
            msg.setWindowTitle("Lumi — Confirmation Required")
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setText(
                f"Lumi wants to perform a sensitive operation.\n\n"
                f"Operation: {req.tool_name}\n"
                f"Level: {req.level_name}\n"
                f"Target: {target}\n"
                f"Reason: {req.reason}"
            )
            msg.setStandardButtons(
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            msg.setDefaultButton(QMessageBox.StandardButton.No)
            result = msg.exec()
            approved = result == QMessageBox.StandardButton.Yes
            self._result = ConfirmationResponse(approved=approved)
        except Exception as e:
            logger.exception("Confirmation dialog failed")
            self._result = ConfirmationResponse(
                approved=False, note=f"dialog error: {e}"
            )
        finally:
            self._event.set()