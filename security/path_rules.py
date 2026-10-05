"""Path-based rules. Most specific (longest prefix) match wins.
   Rules can be filtered by tool level via min_level."""
import os
from dataclasses import dataclass
from typing import Optional

from security.permissions import PermissionLevel


@dataclass
class PathRule:
    pattern: str
    action: str          # "allow" | "confirm" | "deny"
    reason: str = ""
    exact: bool = False
    # If set, the rule only applies when the tool's level >= this value.
    # e.g. min_level=DISRUPTIVE → rule fires for delete/move but not for read.
    min_level: Optional[PermissionLevel] = None


PATH_RULES: list[PathRule] = [
    # --- Explicit workspace — Lumi can delete freely here ---
    PathRule(r"F:\TestProject", "allow",
             "TestProject is a controlled workspace"),

    # --- Real Windows copy on F:\ — confirm ---
    PathRule(r"F:\Windows", "confirm", "Fake Windows system files"),
    PathRule(r"F:\WindowsApps", "confirm", "WindowsApps"),
    PathRule(r"F:\Program Files", "confirm", "Program Files"),
    PathRule(r"F:\Program Files (x86)", "confirm", "Program Files (x86)"),
    PathRule(r"F:\WpSystem", "confirm", "WpSystem"),
    PathRule(r"F:\XboxGames", "confirm", "XboxGames"),

    # --- Sandbox test folders — confirm ---
    PathRule(r"F:\FakeWindows", "confirm",
             "FakeWindows contains system-looking files"),
    PathRule(r"F:\FakeViruses", "confirm",
             "FakeViruses contains suspicious-looking files"),
    PathRule(r"F:\ImportantFiles", "confirm",
             "ImportantFiles is protected"),
    PathRule(r"F:\BrokenPython", "confirm",
             "BrokenPython is source code"),
    PathRule(r"F:\MoreTests", "confirm",
             "MoreTests contains edge-case files"),

    # --- Root of F:\ itself:
    #     deny destructive ops (delete/move) with an exact match.
    #     Read-only ops (list_dir/read) fall through to base level = allowed.
    PathRule("F:\\", "deny", "cannot delete a drive root",
             exact=True, min_level=PermissionLevel.DISRUPTIVE),
]


HARD_DENY: list[PathRule] = [
    # Add paths here for absolute rejection with no confirmation.
]


def _canon(p: str) -> str:
    return os.path.normcase(os.path.realpath(p))


def _is_subpath(child_canon: str, parent_canon: str) -> bool:
    if child_canon == parent_canon:
        return True
    parent = parent_canon if parent_canon.endswith(os.sep) else parent_canon + os.sep
    return child_canon.startswith(parent)


def match_rule(path: str, rules: list[PathRule],
               tool_level: Optional[PermissionLevel] = None) -> Optional[PathRule]:
    try:
        target = _canon(path)
    except Exception:
        return None

    best: Optional[PathRule] = None
    best_len = -1
    for rule in rules:
        # Level filter
        if rule.min_level is not None and tool_level is not None:
            if tool_level < rule.min_level:
                continue

        try:
            prefix = _canon(rule.pattern)
        except Exception:
            continue

        if rule.exact:
            if target != prefix:
                continue
            if len(prefix) > best_len:
                best = rule
                best_len = len(prefix)
        else:
            if _is_subpath(target, prefix):
                if len(prefix) > best_len:
                    best = rule
                    best_len = len(prefix)
    return best


def check_hard_deny(path: str,
                    tool_level: Optional[PermissionLevel] = None) -> Optional[PathRule]:
    return match_rule(path, HARD_DENY, tool_level=tool_level)


def check_path_rules(path: str,
                     tool_level: Optional[PermissionLevel] = None) -> Optional[PathRule]:
    return match_rule(path, PATH_RULES, tool_level=tool_level)