"""
security/acl_inspection.py

Read-only Windows ACL inspection for Lumi's control-plane paths.

This module NEVER modifies ACLs, ownership, or inheritance. It does not
invoke icacls or Set-Acl. It resolves the runtime identity and inspects
each target path via PowerShell's read-only `Get-Acl` cmdlet, parsing the
result into plain frozen dataclasses that downstream code (see
security/acl_policy.py) turns into a review plan.

Design notes
------------

- The module is deliberately read-only. It cannot enforce anything.
- Failures are reported as data on PathInspection.error rather than
  exceptions. The policy layer treats a non-empty error as fail-closed.
- All subprocess invocations use shell=False and fixed argv lists.
- Paths are quoted in the PowerShell script with single quotes (the only
  proper way to quote a literal path with -LiteralPath); any embedded
  single quote is doubled per PowerShell's escaping rules.
- On non-Windows platforms, inspection returns PathInspection with a
  non-empty error. Consumers must treat that as fail-closed.

Safety invariant
----------------

Any invocation of subprocess from this module must be a read-only
command. The unit tests assert this by mocking subprocess and checking
each argv list for modification flags. Do not add modifying flags here.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Tuple


# ------------------------------------------------------------------ data


@dataclass(frozen=True)
class RuntimeIdentity:
    username: str          # "DOMAIN\\user" (or empty)
    sid: str               # "S-1-5-21-..." (or empty)
    is_elevated: bool      # True if running with Administrator privileges
    source: str            # how the identity was resolved
    error: str = ""        # non-empty means resolution failed


@dataclass(frozen=True)
class AceEntry:
    identity: str          # "DOMAIN\\user", SID, or well-known name
    rights: Tuple[str, ...]  # e.g. ("Read", "Write") — normalized strings
    ace_type: str          # "Allow" | "Deny"
    inherited: bool


@dataclass(frozen=True)
class PathInspection:
    canonical_path: str
    exists: bool
    is_dir: bool
    owner: str
    inheritance_enabled: bool
    aces: Tuple[AceEntry, ...]
    error: str = ""


# ------------------------------------------------------------------ runtime identity


def _is_elevated() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_runtime_identity() -> RuntimeIdentity:
    """Resolve the identity Lumi is running as, without assuming it is
    Administrator and without hard-coding a username or SID.

    Returns a RuntimeIdentity with a non-empty `error` on any failure.
    """
    if os.name != "nt":
        return RuntimeIdentity("", "", False, "non-windows",
                               "runtime identity is Windows-only")

    whoami = shutil.which("whoami")
    if not whoami:
        return RuntimeIdentity("", "", _is_elevated(), "whoami-missing",
                               "whoami not found on PATH")

    try:
        proc = subprocess.run(
            [whoami, "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=10,
            shell=False, encoding="utf-8", errors="replace",
        )
    except Exception as e:
        return RuntimeIdentity("", "", _is_elevated(), "whoami-exception",
                               f"whoami failed: {e}")

    if proc.returncode != 0:
        return RuntimeIdentity(
            "", "", _is_elevated(), "whoami-exit",
            f"whoami exit {proc.returncode}: {(proc.stderr or '').strip()}",
        )

    out = (proc.stdout or "").strip()
    if not out:
        return RuntimeIdentity("", "", _is_elevated(), "whoami-empty",
                               "whoami returned no output")

    line = out.splitlines()[0]
    # Expected: "DOMAIN\\user","S-1-5-21-..."
    parts = [p.strip().strip('"') for p in line.split(",")]
    username = parts[0] if parts else ""
    sid = parts[1] if len(parts) > 1 else ""
    if not username or not sid:
        return RuntimeIdentity("", "", _is_elevated(), "whoami-parse",
                               f"could not parse whoami output: {line!r}")

    return RuntimeIdentity(username, sid, _is_elevated(), "whoami")


# ------------------------------------------------------------------ path canonicalization


def _canonicalize(path) -> str:
    if path is None:
        raise ValueError("path is None")
    if not isinstance(path, str):
        raise ValueError("path must be a string")
    s = path.strip()
    if not s:
        raise ValueError("path is empty")
    real = os.path.realpath(s)
    return os.path.normpath(real)


# ------------------------------------------------------------------ PowerShell script


def _ps_single_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _build_ps_inspect_script(path: str) -> str:
    """Return a PowerShell one-liner that prints owner, inheritance
    state, and each ACE line as structured text. Uses only read-only
    cmdlets (Get-Acl)."""
    q = _ps_single_quote(path)
    # NOTE: every brace in the PowerShell script below is doubled so it
    # survives an f-string. The emitted script uses single braces.
    return (
        f"$a = Get-Acl -LiteralPath {q}; "
        f"Write-Output ('OWNER=' + $a.Owner); "
        f"Write-Output ('PROTECTED=' + $a.AreAccessRulesProtected); "
        f"$a.Access | ForEach-Object {{ "
        f"Write-Output ('ACE=' + $_.IdentityReference + '|' + "
        f"$_.FileSystemRights + '|' + "
        f"$_.AccessControlType + '|' + $_.IsInherited) }}"
    )


def _parse_ace_rights(rights_str: str) -> Tuple[str, ...]:
    """FileSystemRights comes out as something like
    'FullControl, Synchronize' or 'ReadAndExecute, Synchronize'. We
    normalize into a small token set."""
    tokens = []
    for raw in rights_str.split(","):
        t = raw.strip()
        if not t:
            continue
        # The .NET enum serializes as a comma-separated list.
        tokens.append(t)
    return tuple(tokens)


# ------------------------------------------------------------------ inspection


def inspect_path(path) -> PathInspection:
    """Inspect a single path. Never raises. Any failure is reported as
    PathInspection.error."""
    try:
        canon = _canonicalize(path)
    except Exception as e:
        return PathInspection(
            canonical_path="", exists=False, is_dir=False,
            owner="", inheritance_enabled=False, aces=(),
            error=f"cannot canonicalize path: {e}",
        )

    exists = os.path.exists(canon)
    is_dir = os.path.isdir(canon) if exists else False

    if os.name != "nt":
        return PathInspection(
            canonical_path=canon, exists=exists, is_dir=is_dir,
            owner="", inheritance_enabled=False, aces=(),
            error="ACL inspection is Windows-only",
        )

    if not exists:
        return PathInspection(
            canonical_path=canon, exists=False, is_dir=False,
            owner="", inheritance_enabled=False, aces=(),
            error="path does not exist",
        )

    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        return PathInspection(
            canonical_path=canon, exists=exists, is_dir=is_dir,
            owner="", inheritance_enabled=False, aces=(),
            error="neither powershell nor pwsh found on PATH",
        )

    script = _build_ps_inspect_script(canon)
    try:
        proc = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=15,
            shell=False, encoding="utf-8", errors="replace",
        )
    except Exception as e:
        return PathInspection(
            canonical_path=canon, exists=exists, is_dir=is_dir,
            owner="", inheritance_enabled=False, aces=(),
            error=f"PowerShell inspection failed: {e}",
        )

    if proc.returncode != 0:
        return PathInspection(
            canonical_path=canon, exists=exists, is_dir=is_dir,
            owner="", inheritance_enabled=False, aces=(),
            error=(
                f"PowerShell exit {proc.returncode}: "
                f"{(proc.stderr or '').strip()}"
            ),
        )

    return _parse_inspection_output(canon, exists, is_dir, proc.stdout or "")


def _parse_inspection_output(
    canon: str, exists: bool, is_dir: bool, output: str
) -> PathInspection:
    owner = ""
    inheritance_enabled = False
    aces = []
    seen_protected = False

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("OWNER="):
            owner = line[len("OWNER="):].strip()
            continue
        if line.startswith("PROTECTED="):
            val = line[len("PROTECTED="):].strip()
            # AreAccessRulesProtected == True means inheritance DISABLED.
            inheritance_enabled = not (val.lower() == "true")
            seen_protected = True
            continue
        if line.startswith("ACE="):
            rest = line[len("ACE="):]
            parts = rest.split("|")
            if len(parts) != 4:
                continue
            ident, rights_str, ace_type, inherited_str = (p.strip() for p in parts)
            aces.append(AceEntry(
                identity=ident,
                rights=_parse_ace_rights(rights_str),
                ace_type=ace_type,
                inherited=(inherited_str.lower() == "true"),
            ))

    if not seen_protected:
        return PathInspection(
            canonical_path=canon, exists=exists, is_dir=is_dir,
            owner=owner, inheritance_enabled=False, aces=tuple(aces),
            error="PowerShell output did not include PROTECTED line",
        )

    return PathInspection(
        canonical_path=canon, exists=exists, is_dir=is_dir,
        owner=owner, inheritance_enabled=inheritance_enabled,
        aces=tuple(aces),
    )


# ------------------------------------------------------------------ diagnostics


def describe() -> dict:
    ident = get_runtime_identity()
    return {
        "platform": sys.platform,
        "username": ident.username,
        "sid": ident.sid,
        "is_elevated": ident.is_elevated,
        "source": ident.source,
        "error": ident.error,
    }