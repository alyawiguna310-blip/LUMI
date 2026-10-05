"""
Lightweight event bus for decoupling components.
"""
import logging
from typing import Callable, Any

logger = logging.getLogger(__name__)


class EventBus:
    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = {}

    def subscribe(self, event: str, callback: Callable) -> None:
        self._subscribers.setdefault(event, []).append(callback)

    def emit(self, event: str, **kwargs: Any) -> None:
        for cb in self._subscribers.get(event, []):
            try:
                cb(**kwargs)
            except Exception:
                logger.exception("Event handler for %s raised", event)


bus = EventBus()