"""Small Windows-only completion notifications for Lumi.

Notifications are informational only. They never authorize, approve, or
execute tools and are emitted only after a successful code fix or a
multi-tool task batch.
"""
import logging
import sys

logger = logging.getLogger(__name__)

MULTI_TASK_THRESHOLD = 3


class NotificationManager:
    """Show Windows notifications without creating another tray icon."""

    def __init__(self):
        self.enabled = sys.platform == "win32"

    def notify(self, title: str, message: str) -> None:
        if not self.enabled:
            return

        try:
            from PyQt6.QtGui import QIcon
            from PyQt6.QtWidgets import QApplication, QSystemTrayIcon

            if QApplication.instance() is None:
                return

            icon = QIcon()
            tray = QSystemTrayIcon(icon)
            tray.setToolTip("Lumi")
            tray.show()
            tray.showMessage(
                title,
                message,
                QSystemTrayIcon.MessageIcon.Information,
                5000,
            )
            # Keep the object alive long enough for Windows to receive the
            # notification. It is intentionally not used for authorization.
            self._last_tray = tray
        except Exception:
            logger.exception("Windows notification failed")
