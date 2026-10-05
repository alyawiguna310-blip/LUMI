"""
security/workspace.py

Classification of paths relative to Lumi's development workspace.

The workspace is `D:\\Lumi\\workspace` (resolved at import time). It is
the preferred scope for Lumi to write application and project code.

This module is a scope/policy boundary, not an authorization grant. The
SecurityGate's normal permission, risk, and confirmation rules continue
to apply to writes inside the workspace; nothing here auto-approves
anything.

Classification results:

    WORKSPACE       Path is inside the workspace root.
    CONTROL_PLANE   Path is on the security control plane. Delegated to
                    security.control_plane and takes priority over
                    WORKSPACE.
    OTHER           Path is outside both.
    UNKNOWN         Classification failed (None, empty, malformed, or
                    canonicalization error). Callers must treat UNKNOWN
                    as fail-closed for write-class operations.

Canonicalization notes
----------------------

Same rules as security/control_plane.py: `os.path.realpath` resolves
symlinks, junctions, and reparse points; `os.path.normpath` collapses
`.` and `..` and normalizes separators; `os.path.normcase` lowercases
on Windows. Comparison is separator-aware so `D:\\Lumi\\workspaceX` is
not treated as inside `D:\\Lumi\\workspace`.
"""
from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Tuple

from security.control_plane import is_control_plane


# ------------------------------------------------------------------ roots


_THIS_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent

_WORKSPACE_ROOT_RAW = str(_PROJECT_ROOT / "workspace")


class PathClass(str, Enum):
    WORKSPACE = "workspace"
    CONTROL_PLANE = "control_plane"
    OTHER = "other"
    UNKNOWN = "unknown"


# ------------------------------------------------------------------ canonicalization


def _canon(path) -> str:
    if path is None:
        raise ValueError("path is None")
    s = str(path).strip()
    if not s:
        raise ValueError("path is empty")
    real = os.path.realpath(s)
    normalized = os.path.normpath(real)
    return os.path.normcase(normalized)


def _canon_or_raw(path: str) -> str:
    try:
        return _canon(path)
    except Exception:
        return os.path.normcase(os.path.normpath(path))


_CANON_WORKSPACE_ROOT: str = _canon_or_raw(_WORKSPACE_ROOT_RAW)


# ------------------------------------------------------------------ comparison


def _is_inside_or_equal(child: str, parent: str) -> bool:
    if child == parent:
        return True
    sep = os.sep
    if not parent.endswith(sep):
        parent = parent + sep
    return child.startswith(parent)


# ------------------------------------------------------------------ public API


def classify_path(path) -> PathClass:
    """Classify a path.

    CONTROL_PLANE has priority over WORKSPACE. Any failure (None,
    non-string, empty, or uncanonicalizable) yields UNKNOWN. Callers
    must treat UNKNOWN as fail-closed for write-class operations.
    """
    if path is None:
        return PathClass.UNKNOWN
    if not isinstance(path, str):
        return PathClass.UNKNOWN
    if not path.strip():
        return PathClass.UNKNOWN

    # CONTROL_PLANE wins. is_control_plane() fails closed on malformed
    # input, but we have already filtered None/empty/non-string above so
    # UNKNOWN here has a specific meaning distinct from CONTROL_PLANE.
    try:
        if is_control_plane(path):
            return PathClass.CONTROL_PLANE
    except Exception:
        return PathClass.UNKNOWN

    try:
        target = _canon(path)
    except Exception:
        return PathClass.UNKNOWN

    if _is_inside_or_equal(target, _CANON_WORKSPACE_ROOT):
        return PathClass.WORKSPACE
    return PathClass.OTHER


def is_workspace(path) -> bool:
    return classify_path(path) == PathClass.WORKSPACE


def is_other(path) -> bool:
    return classify_path(path) == PathClass.OTHER


def project_root() -> str:
    return str(_PROJECT_ROOT)


def workspace_root() -> str:
    return _CANON_WORKSPACE_ROOT


def describe() -> dict:
    return {
        "project_root": str(_PROJECT_ROOT),
        "workspace_root": _CANON_WORKSPACE_ROOT,
    }