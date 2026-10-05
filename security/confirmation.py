"""
Confirmation flow for potentially disruptive actions.

Default: fail-closed (no handler → deny).

/force mode: temporarily auto-approves MOST confirmation requests for a
short, bounded window. Hard-denies (protected paths, elevated commands,
drive-root rules) are enforced BEFORE this layer.

NEVER_FORCE tools (delete, rename, move, admin, software install) still
show the confirmation dialog even when /force is active.

Additionally, requests may be marked forceable=False by the SecurityGate
when the confirmation was triggered by anything other than the tool's
base permission level (system-looking path, path-rule confirm, or a
tool-declared confirm_if). Such requests are never auto-approved by
/force.
"""
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from core.events import bus

logger = logging.getLogger(__name__)


FORCE_MIN_SECONDS = 5
FORCE_MAX_SECONDS = 3600
FORCE_DEFAULT_SECONDS = 300

# Tools that /force can NEVER auto-approve. These always ask the user.
NEVER_FORCE: set[str] = {
    "filesystem.delete",
    "filesystem.rename",
    "filesystem.move",
    "terminal.run_admin",
    "applications.install",
}


@dataclass
class ConfirmationRequest:
    tool_name: str
    arguments: dict
    level_name: str
    reason: str
    extra: dict = field(default_factory=dict)
    # If False, /force will NOT auto-approve this request. It will fall
    # through to the real handler. Set by the SecurityGate when the
    # confirmation was triggered by something other than the tool's base
    # permission level (system-looking path, path rule "confirm", or a
    # tool-declared confirm_if). See SECURITY.md section "Force mode".
    forceable: bool = True


@dataclass
class ConfirmationResponse:
    approved: bool
    note: str = ""


class ConfirmationManager:
    def __init__(self, timeout_seconds: int = 60):
        self.timeout = timeout_seconds
        self._handler: Optional[
            Callable[[ConfirmationRequest], ConfirmationResponse]
        ] = None
        self._lock = threading.Lock()

        self._force_until: float = 0.0
        self._force_reason: str = ""

    # ---------------------------------------------------------- handler

    def set_handler(
        self,
        handler: Callable[[ConfirmationRequest], ConfirmationResponse],
    ):
        with self._lock:
            self._handler = handler

    # ---------------------------------------------------------- force mode

    def enable_force(self, seconds: int = FORCE_DEFAULT_SECONDS,
                     reason: str = "user") -> int:
        seconds = max(FORCE_MIN_SECONDS, min(FORCE_MAX_SECONDS, int(seconds)))
        with self._lock:
            self._force_until = time.time() + seconds
            self._force_reason = reason
        logger.warning(
            "[FORCE] auto-approve ENABLED for %ds (reason=%s)", seconds, reason
        )
        bus.emit("force.state_changed", active=True, remaining=seconds)
        return seconds

    def disable_force(self) -> bool:
        with self._lock:
            was = self._force_until > time.time()
            self._force_until = 0.0
            self._force_reason = ""
        if was:
            logger.warning("[FORCE] auto-approve DISABLED")
        bus.emit("force.state_changed", active=False, remaining=0)
        return was

    def is_force_active(self) -> bool:
        with self._lock:
            return self._force_until > time.time()

    def force_remaining(self) -> int:
        with self._lock:
            return max(0, int(self._force_until - time.time()))

    # ---------------------------------------------------------- request

    def request(self, req: ConfirmationRequest) -> ConfirmationResponse:
        # --- Force mode short-circuit ---
        # /force may only auto-approve requests that the gate explicitly
        # marked forceable AND that are not in NEVER_FORCE. Everything
        # else falls through to the real handler, even when /force is on.
        if self.is_force_active():
            if not req.forceable:
                logger.info(
                    "[FORCE] %s is marked non-forceable - requiring manual "
                    "confirmation",
                    req.tool_name,
                )
                # fall through to the real handler
            elif req.tool_name in NEVER_FORCE:
                logger.warning(
                    "[FORCE] %s is in NEVER_FORCE - still requiring manual "
                    "confirmation",
                    req.tool_name,
                )
                # fall through to the real handler
            else:
                remaining = self.force_remaining()
                logger.warning(
                    "[FORCE] auto-approved %s (reason=%r, %ds left)",
                    req.tool_name, req.reason[:80], remaining,
                )
                return ConfirmationResponse(
                    approved=True,
                    note=f"forced ({remaining}s left)",
                )

        with self._lock:
            handler = self._handler

        if handler is None:
            logger.warning(
                "No confirmation handler installed - denying %s (fail-closed)",
                req.tool_name,
            )
            return ConfirmationResponse(approved=False, note="no handler")

        try:
            return handler(req)
        except Exception as e:
            logger.exception("Confirmation handler raised")
            return ConfirmationResponse(
                approved=False, note=f"handler error: {e}"
            )