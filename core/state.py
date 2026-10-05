"""
Centralized state machine for Lumi.
No other module may directly set the state; they must go through StateManager.
"""
from enum import Enum, auto
from typing import Callable, Optional
import logging

logger = logging.getLogger(__name__)


class LumiState(Enum):
    SLEEPING = auto()
    IDLE = auto()
    LISTENING = auto()
    THINKING = auto()
    SPEAKING = auto()
    WORKING = auto()
    WAITING_FOR_CONFIRMATION = auto()
    INVESTIGATING = auto()
    ERROR = auto()
    STOPPING = auto()


# Valid transitions: from_state -> set(to_state)
_VALID_TRANSITIONS: dict[LumiState, set[LumiState]] = {
    LumiState.SLEEPING: {LumiState.IDLE},
    LumiState.IDLE: {
        LumiState.LISTENING,
        LumiState.SLEEPING,
        LumiState.THINKING,
        LumiState.ERROR,
    },
    LumiState.LISTENING: {
        LumiState.THINKING,
        LumiState.IDLE,
        LumiState.SLEEPING,
        LumiState.ERROR,
    },
    LumiState.THINKING: {
        LumiState.SPEAKING,
        LumiState.WORKING,
        LumiState.INVESTIGATING,
        LumiState.WAITING_FOR_CONFIRMATION,
        LumiState.IDLE,
        LumiState.ERROR,
    },
    LumiState.SPEAKING: {LumiState.IDLE, LumiState.LISTENING, LumiState.ERROR},
    LumiState.WORKING: {
        LumiState.IDLE,
        LumiState.SPEAKING,
        LumiState.WAITING_FOR_CONFIRMATION,
        LumiState.ERROR,
    },
    LumiState.WAITING_FOR_CONFIRMATION: {
        LumiState.WORKING,
        LumiState.IDLE,
        LumiState.SLEEPING,
        LumiState.ERROR,
    },
    LumiState.INVESTIGATING: {LumiState.SPEAKING, LumiState.IDLE, LumiState.ERROR},
    LumiState.ERROR: {LumiState.IDLE, LumiState.SLEEPING},
    LumiState.STOPPING: set(),  # terminal
}


class StateManager:
    """Central authority for Lumi's state. Notifies observers on change."""

    def __init__(self, initial: LumiState = LumiState.SLEEPING):
        self._state = initial
        self._observers: list[Callable[[LumiState, LumiState], None]] = []

    @property
    def state(self) -> LumiState:
        return self._state

    def add_observer(self, callback: Callable[[LumiState, LumiState], None]) -> None:
        """Register a callback that receives (old_state, new_state)."""
        self._observers.append(callback)

    def transition(self, new_state: LumiState) -> bool:
        """
        Attempt to transition to new_state.
        Returns True if allowed, False if the transition is invalid.
        """
        if new_state == self._state:
            return True  # no-op

        allowed = _VALID_TRANSITIONS.get(self._state, set())
        if new_state not in allowed:
            logger.warning(
                "Invalid state transition: %s -> %s", self._state.name, new_state.name
            )
            return False

        old = self._state
        self._state = new_state
        logger.info("State: %s -> %s", old.name, new_state.name)
        for obs in self._observers:
            try:
                obs(old, new_state)
            except Exception:
                logger.exception("State observer raised")
        return True