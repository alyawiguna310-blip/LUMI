"""Rolling-window conversation memory. Does NOT persist to disk yet."""
from collections import deque

from ai.provider import ChatMessage


class ConversationMemory:
    def __init__(self, max_messages: int = 20):
        # maxlen is the number of *conversation* messages (user + assistant),
        # not including the system prompt.
        self._messages: deque[ChatMessage] = deque(maxlen=max_messages)

    def add(self, message: ChatMessage) -> None:
        self._messages.append(message)

    def get_all(self) -> list[ChatMessage]:
        return list(self._messages)

    def clear(self) -> None:
        self._messages.clear()

    def __len__(self) -> int:
        return len(self._messages)