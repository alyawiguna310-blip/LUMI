"""Permission levels and policy decisions."""
from dataclasses import dataclass, field
from enum import IntEnum


class PermissionLevel(IntEnum):
    SAFE = 0
    NORMAL = 1
    DISRUPTIVE = 2
    DESTRUCTIVE = 3
    FORBIDDEN = 4


LEVEL_NAMES = {
    PermissionLevel.SAFE: "safe",
    PermissionLevel.NORMAL: "normal",
    PermissionLevel.DISRUPTIVE: "disruptive",
    PermissionLevel.DESTRUCTIVE: "destructive",
    PermissionLevel.FORBIDDEN: "forbidden",
}


@dataclass
class PermissionPolicy:
    auto_approve_max: PermissionLevel = PermissionLevel.NORMAL
    always_deny: set = field(default_factory=lambda: {PermissionLevel.FORBIDDEN})

    def decision(self, level: PermissionLevel) -> str:
        """Return 'allow', 'confirm', or 'deny'."""
        if level in self.always_deny:
            return "deny"
        if level <= self.auto_approve_max:
            return "allow"
        return "confirm"