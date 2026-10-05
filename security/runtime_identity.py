"""
security/runtime_identity.py

Pure-logic helpers for reasoning about a runtime identity. No side
effects. No subprocess. No file IO. No account creation.

The helpers here parse output from Windows tools that the human user
runs manually, and validate assumptions about the parsed identity. They
are used by tests and by future tooling that needs a stable
representation of "is this account safe to run Lumi".

They deliberately do NOT read or write Windows credentials.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple


_SID_RE = re.compile(r"^S-1-(?:\d+-)+\d+$")


@dataclass(frozen=True)
class LocalUserRecord:
    name: str
    sid: str
    enabled: bool
    error: str = ""


@dataclass(frozen=True)
class AdminCheck:
    is_member: bool
    matched_entry: Optional[str]
    error: str = ""


# ------------------------------------------------------------------ parsing


def parse_sid(sid: str) -> Tuple[bool, str]:
    """Return (ok, reason). Accepts any well-formed Windows SID string."""
    if not isinstance(sid, str) or not sid:
        return False, "sid must be a non-empty string"
    if not _SID_RE.match(sid):
        return False, f"sid does not match expected structure: {sid!r}"
    return True, ""


def parse_local_user_csv_line(line: str) -> LocalUserRecord:
    """Parse one CSV line as produced by:
        Get-LocalUser -Name LumiRuntime |
            Select-Object Name,SID,Enabled |
            ConvertTo-Csv -NoTypeInformation |
            Select-Object -Skip 1
    The line is expected to be `"Name","S-1-5-...","True"` or similar.
    Headerless because callers use -Skip 1.
    """
    if not isinstance(line, str):
        return LocalUserRecord("", "", False, "line must be a string")
    s = line.strip()
    if not s:
        return LocalUserRecord("", "", False, "line is empty")
    # Strip surrounding quotes and split on '","'.
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]
    parts = s.split('","')
    if len(parts) != 3:
        return LocalUserRecord(
            "", "", False, f"expected 3 fields, got {len(parts)}: {line!r}"
        )
    name, sid, enabled_str = parts
    ok, reason = parse_sid(sid)
    if not ok:
        return LocalUserRecord(name, sid, False, reason)
    enabled = enabled_str.strip().lower() in ("true", "1")
    return LocalUserRecord(name, sid, enabled)


def parse_admin_membership(lines: Iterable[str],
                           runtime_sid: str,
                           runtime_name: str = "") -> AdminCheck:
    """Given lines of the form 'COMPUTER\\name' or SID strings, decide
    whether the runtime identity appears in the Administrators group.

    This is intentionally simple: it accepts either a name match
    (case-insensitive, `COMPUTER\\LumiRuntime`) or a SID match.
    """
    ok, reason = parse_sid(runtime_sid)
    if not ok:
        return AdminCheck(False, None, f"invalid runtime_sid: {reason}")

    want_sid = runtime_sid.lower()
    want_name = runtime_name.lower() if runtime_name else ""
    computer = ""
    # Extract the computer prefix from name if provided as `COMPUTER\user`.
    if "\\" in want_name:
        computer, want_name = want_name.split("\\", 1)

    for raw in lines:
        entry = (raw or "").strip()
        if not entry:
            continue
        low = entry.lower()
        if low == want_sid:
            return AdminCheck(True, entry)
        if want_name and low.endswith("\\" + want_name):
            # Match regardless of computer prefix if want_name had no
            # prefix; require exact prefix if it did.
            if not computer or low.startswith(computer + "\\"):
                return AdminCheck(True, entry)
    return AdminCheck(False, None)


def is_runtime_identity_safe(
    *, runtime_name: str, runtime_sid: str, admin_lines: Iterable[str],
) -> Tuple[bool, str]:
    """Return (ok, reason). Fails closed on any error."""
    if not runtime_name:
        return False, "runtime_name is empty"
    ok, reason = parse_sid(runtime_sid)
    if not ok:
        return False, reason
    check = parse_admin_membership(
        admin_lines, runtime_sid=runtime_sid, runtime_name=runtime_name,
    )
    if check.error:
        return False, check.error
    if check.is_member:
        return False, (
            f"runtime identity {runtime_name!r} appears in Administrators"
        )
    base_name = runtime_name.split("\\")[-1].lower() if "\\" in runtime_name else runtime_name.lower()
    if base_name in ("administrator", "administrador"):
        return False, "runtime identity cannot be the built-in Administrator"
    return True, ""
    return True, ""