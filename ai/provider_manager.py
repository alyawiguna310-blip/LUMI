"""
ProviderManager — the fallback authority.

Tries providers in order, tracks health, applies cooldowns, and reports
the first non-retryable error (e.g. our own bug) instead of masking it.
"""
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from ai.provider import (
    ChatMessage, ChatResponse, LLMProvider, ProviderHealth,
)
from ai.providers.base import ErrorKind, classify_error, cooldown_seconds

logger = logging.getLogger(__name__)


@dataclass
class ProviderEntry:
    name: str
    provider: LLMProvider
    health: ProviderHealth = ProviderHealth.HEALTHY
    cooldown_until: float = 0.0
    last_error: str = ""
    last_error_kind: Optional[ErrorKind] = None
    call_count: int = 0
    fail_count: int = 0

    def is_callable(self) -> bool:
        if self.health in (ProviderHealth.DISABLED, ProviderHealth.AUTH_FAILED):
            return False
        if self.health == ProviderHealth.HEALTHY:
            return True
        # COOLDOWN / QUOTA → check the timer
        return time.time() >= self.cooldown_until

    def mark_success(self):
        self.call_count += 1
        if self.health != ProviderHealth.HEALTHY:
            logger.info("Provider %s recovered (was %s)", self.name, self.health.value)
        self.health = ProviderHealth.HEALTHY
        self.cooldown_until = 0.0
        self.last_error = ""
        self.last_error_kind = None

    def mark_failure(self, kind: ErrorKind, err_msg: str):
        self.fail_count += 1
        self.last_error = err_msg[:300]
        self.last_error_kind = kind

        if kind == ErrorKind.AUTH:
            self.health = ProviderHealth.AUTH_FAILED
            self.cooldown_until = float("inf")
            logger.error("Provider %s: AUTH FAILED — disabled until restart",
                         self.name)
        elif kind == ErrorKind.QUOTA:
            self.health = ProviderHealth.QUOTA_EXHAUSTED
            self.cooldown_until = time.time() + cooldown_seconds(kind)
            logger.warning("Provider %s: QUOTA — cooling down for %ds",
                           self.name, cooldown_seconds(kind))
        else:
            self.health = ProviderHealth.COOLDOWN
            self.cooldown_until = time.time() + cooldown_seconds(kind)
            logger.warning("Provider %s: %s — cooling down for %ds",
                           self.name, kind.value, cooldown_seconds(kind))


class ProviderManager(LLMProvider):
    """
    Callable as an LLMProvider. Falls back across entries in order.
    """

    name = "manager"

    def __init__(self, providers: list[tuple[str, LLMProvider]]):
        self.entries: list[ProviderEntry] = []
        self._lock = threading.Lock()

        for name, p in providers:
            if p is None:
                continue
            if not p.is_available():
                logger.warning("Provider %s skipped (not available at init)", name)
                continue
            self.entries.append(ProviderEntry(name=name, provider=p))

        if not self.entries:
            logger.error("ProviderManager: no providers available!")
        else:
            names = ", ".join(e.name for e in self.entries)
            logger.info("ProviderManager chain: %s", names)

    def is_available(self) -> bool:
        return any(e.is_callable() for e in self.entries)

    def supports_tools(self) -> bool:
        return any(e.provider.supports_tools() for e in self.entries)

    # ---------- status reporting ----------

    def status_report(self) -> list[dict]:
        now = time.time()
        out = []
        for e in self.entries:
            remaining = max(0, int(e.cooldown_until - now)) if e.cooldown_until else 0
            out.append({
                "name": e.name,
                "health": e.health.value,
                "calls": e.call_count,
                "fails": e.fail_count,
                "cooldown_s": remaining,
                "last_error": e.last_error,
            })
        return out

    # ---------- chat with fallback ----------

    def chat(self, messages: list[ChatMessage], max_tokens: int = 300) -> ChatResponse:
        if not self.entries:
            raise RuntimeError("No providers configured")

        errors: list[str] = []
        any_transient_failure = False

        for entry in self.entries:
            if not entry.is_callable():
                logger.debug("Skipping %s (health=%s)", entry.name, entry.health.value)
                continue

            try:
                logger.debug("Trying provider %s", entry.name)
                result = entry.provider.chat(messages, max_tokens=max_tokens)
                entry.mark_success()
                logger.info("Provider %s succeeded", entry.name)
                return result

            except Exception as e:
                kind = classify_error(e)
                err_msg = str(e) or type(e).__name__
                logger.warning("Provider %s failed (%s): %s",
                               entry.name, kind.value, err_msg[:200])
                errors.append(f"{entry.name}: {err_msg[:160]}")

                # A provider-side 4xx/INVALID_ARGUMENT is scoped to that
                # provider/model/request adapter. It must not prevent the
                # configured fallback chain from trying the same conversation.
                # Local programming errors that are not classified as INVALID
                # still follow the normal error path and remain visible.
                entry.mark_failure(kind, err_msg)
                any_transient_failure = True
                continue

        # All providers failed (or skipped)
        if any_transient_failure:
            raise RuntimeError(
                "All providers unavailable. Last errors: " + " | ".join(errors)
            )
        raise RuntimeError(
            "No providers callable right now. Status: " +
            ", ".join(f"{e.name}={e.health.value}" for e in self.entries)
        )