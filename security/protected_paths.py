"""
Protected-folder enforcement.

Uses OS-level canonicalization (os.path.realpath) which:
  - follows symlinks and Windows junctions/reparse points
  - resolves '..' components
  - normalizes case on Windows
  - expands 8.3 short names on Windows

If ANY step fails, we fail closed (deny).
"""
import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PathCheckResult:
    allowed: bool
    reason: str = ""
    canonical: str = ""

    def __bool__(self) -> bool:
        return self.allowed


def _strip_windows_prefix(s: str) -> str:
    if s.startswith("\\\\?\\"):
        rest = s[4:]
        if rest.upper().startswith("UNC\\"):
            rest = "\\\\" + rest[4:]
        return rest
    return s


def canonicalize(path) -> str:
    if path is None:
        raise ValueError("path is None")
    s = str(path).strip()
    if not s:
        raise ValueError("path is empty")

    s = _strip_windows_prefix(s)
    s = os.path.expanduser(s)
    s = os.path.expandvars(s)

    p = Path(s)
    if not p.is_absolute():
        p = Path.cwd() / p

    real = os.path.realpath(str(p))
    real = _strip_windows_prefix(real)

    if not os.path.isabs(real):
        raise ValueError(f"path is not absolute after canonicalization: {real!r}")

    return os.path.normpath(real)


def is_inside_protected(requested, protected) -> PathCheckResult:
    try:
        req_canon = canonicalize(requested)
    except Exception as e:
        return PathCheckResult(
            allowed=False,
            reason=f"cannot canonicalize requested path: {e}",
        )

    try:
        prot_canon = canonicalize(protected)
    except Exception as e:
        return PathCheckResult(
            allowed=False,
            reason=f"cannot canonicalize protected folder: {e}",
        )

    req_norm = os.path.normcase(req_canon)
    prot_norm = os.path.normcase(prot_canon)

    try:
        common = os.path.commonpath([req_norm, prot_norm])
    except ValueError:
        return PathCheckResult(allowed=True, canonical=req_canon)

    if common == prot_norm:
        return PathCheckResult(
            allowed=False,
            reason=f"path is inside protected folder ({prot_canon})",
            canonical=req_canon,
        )

    return PathCheckResult(allowed=True, canonical=req_canon)


def is_protected(requested, protected) -> bool:
    return not is_inside_protected(requested, protected).allowed