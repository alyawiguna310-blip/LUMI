"""Provider abstraction — the LLM layer must be replaceable and fallback-capable."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProviderHealth(str, Enum):
    HEALTHY = "healthy"
    COOLDOWN = "cooldown"
    DISABLED = "disabled"
    QUOTA_EXHAUSTED = "quota"
    AUTH_FAILED = "auth"


@dataclass
class ToolCall:
    name: str
    arguments: dict
    id: str = ""


@dataclass
class ChatMessage:
    role: str
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    source_provider: str = ""
    tool_call_id: str = ""
    tool_name: str = ""
    tool_result: dict = field(default_factory=dict)
    raw_parts: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"role": self.role, "content": self.content}


@dataclass
class ChatResponse:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw_parts: list = field(default_factory=list)
    raw: Any | None = None
    source_provider: str = ""


class LLMProvider(ABC):
    name: str = "generic"

    @abstractmethod
    def chat(self, messages: list[ChatMessage], max_tokens: int = 300) -> ChatResponse:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...

    def supports_tools(self) -> bool:
        return False
