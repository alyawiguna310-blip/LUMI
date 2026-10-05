"""
security/control_plane.py

Classification of Lumi's security control plane.

A path is a control-plane path when it is inside (or equal to) one of:

  * the entire `security/` directory (recursive),
  * any of the explicitly listed control-plane files:
        main.py
        config.py
        .env
        core/tool_router.py
        tools/admin_tasks.py
        tools/terminal_guard.py
        storage/audit.py

The gate denies write-class operations on any path classified as
control plane. Read-class operations (list_dir, read) are permitted so
that Lumi can inspect its own security code for debugging.

Canonicalization notes
----------------------

`os.path.realpath` resolves symlinks, junctions, and reparse points.
`os.path.normpath` collapses `.` and `..` and normalizes separators.
`os.path.normcase` lowercases on Windows. All three are applied before
comparison, so path aliases (`..` traversal, mixed separators,
short names, junction/symlink hops) do not bypass the classification.

This module fails closed. If a path is `None`, empty, or cannot be
canonicalized, `is_control_plane()` returns True.

Bootstrap note
--------------

This file is itself inside `security/`, so it is covered by the same
classification it defines. Until the OS-level ACL from Phase 5E is
applied, the source of truth is whatever is committed to the
repository. After Phase 5E, the Lumi standard-user identity cannot
rewrite this file even if the gate is somehow bypassed.

There is no runtime dependency on external configuration: the
protected list is defined here, in code, and would need a code change
to alter.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple


# ------------------------------------------------------------------ roots


_THIS_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent


# ------------------------------------------------------------------ raw entries
#
# These are stored as strings so that a naive prefix match still works
# even if canonicalization of a protected entry itself failed at import
# time. The canonical forms are computed below.

_PROTECTED_DIRS_RAW: Tuple[str, ...] = (
    str(_PROJECT_ROOT / "security"),
)

_PROTECTED_FILES_RAW: Tuple[str, ...] = (
    str(_PROJECT_ROOT / "main.py"),
    str(_PROJECT_ROOT / "config.py"),
    str(_PROJECT_ROOT / ".env"),
    str(_PROJECT_ROOT / "core" / "tool_router.py"),
    str(_PROJECT_ROOT / "tools" / "admin_tasks.py"),
    str(_PROJECT_ROOT / "tools" / "terminal_guard.py"),
    str(_PROJECT_ROOT / "storage" / "audit.py"),
)


# ------------------------------------------------------------------ canonicalization


def _canon(path) -> str:
    """Return a canonical comparison form for `path`.

    Raises on None or empty. Resolves symlinks/junctions, normalizes
    `..` and separators, and lowercases on Windows.
    """
    if path is None:
        raise ValueError("path is None")
    s = str(path).strip()
    if not s:
        raise ValueError("path is empty")
    real = os.path.realpath(s)
    normalized = os.path.normpath(real)
    return os.path.normcase(normalized)


def _canon_or_raw(path: str) -> str:
    """Canonicalize; on failure fall back to a normalized raw form so
    that comparison still has a deterministic value to work with."""
    try:
        return _canon(path)
    except Exception:
        return os.path.normcase(os.path.normpath(path))


_CANON_DIRS: Tuple[str, ...] = tuple(
    _canon_or_raw(d) for d in _PROTECTED_DIRS_RAW
)
_CANON_FILES: Tuple[str, ...] = tuple(
    _canon_or_raw(f) for f in _PROTECTED_FILES_RAW
)


# ------------------------------------------------------------------ comparison


def _is_inside_or_equal(child: str, parent: str) -> bool:
    """True if `child` equals `parent` or lies inside it. Uses the OS
    separator, so `D:\\Lumi\\securityX` is not treated as inside
    `D:\\Lumi\\security`."""
    if child == parent:
        return True
    sep = os.sep
    if not parent.endswith(sep):
        parent = parent + sep
    return child.startswith(parent)


# ------------------------------------------------------------------ public API


def is_control_plane(path) -> bool:
    """Return True if `path` names a control-plane file or directory.

    Fails closed: None, empty, and uncanonicalizable paths return True.
    """
    if path is None:
        return True
    try:
        target = _canon(path)
    except Exception:
        return True

    for d in _CANON_DIRS:
        if _is_inside_or_equal(target, d):
            return True
    for f in _CANON_FILES:
        if target == f:
            return True
    return False


def protected_dirs() -> Tuple[str, ...]:
    """Canonical protected directories. Read-only."""
    return _CANON_DIRS


def protected_files() -> Tuple[str, ...]:
    """Canonical protected files. Read-only."""
    return _CANON_FILES


def project_root() -> str:
    """The Lumi project root, as resolved at import time. Read-only."""
    return str(_PROJECT_ROOT)


def describe() -> dict:
    """Diagnostic snapshot. Read-only. Contains no secrets."""
    return {
        "project_root": str(_PROJECT_ROOT),
        "protected_dirs": list(_CANON_DIRS),
        "protected_files": list(_CANON_FILES),
    }