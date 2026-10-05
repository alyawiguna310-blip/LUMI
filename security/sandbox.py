"""
Sandbox boundary enforcement.

When SANDBOX_ENABLED is true, ONLY paths inside SANDBOX_ROOT are allowed.
Every other path — drive roots, other drives, UNC, relative-to-elsewhere,
symlinks, junctions — is denied before any other check runs.

This is the outermost wall. It comes before protected-folder checks,
before path rules, before system-pattern escalation.

Fail-closed: any error → deny.
"""
import os
from dataclasses import dataclass


@dataclass
class SandboxCheckResult:
    allowed: bool
    reason: str = ""
    canonical: str = ""

    def __bool__(self) -> bool:
        return self.allowed


def _strip_prefix(s: str) -> str:
    if s.startswith("\\\\?\\"):
        rest = s[4:]
        if rest.upper().startswith("UNC\\"):
            rest = "\\\\" + rest[4:]
        return rest
    return s


def _canon(path) -> str:
    """Canonical absolute real path. Raises on failure."""
    if path is None:
        raise ValueError("path is None")
    s = str(path).strip()
    if not s:
        raise ValueError("path is empty")
    s = _strip_prefix(s)
    s = os.path.expanduser(s)
    s = os.path.expandvars(s)
    if not os.path.isabs(s):
        s = os.path.join(os.getcwd(), s)
    real = os.path.realpath(s)
    real = _strip_prefix(real)
    if not os.path.isabs(real):
        raise ValueError(f"path is not absolute after canonicalization: {real!r}")
    return os.path.normpath(real)


def check_sandbox(path, sandbox_root: str, enabled: bool) -> SandboxCheckResult:
    """
    Determine whether `path` is inside the sandbox.
    Returns a SandboxCheckResult. All errors → deny (fail-closed).
    """
    if not enabled:
        return SandboxCheckResult(allowed=True)

    if not sandbox_root:
        return SandboxCheckResult(
            allowed=False,
            reason="sandbox enabled but no sandbox root configured",
        )

    try:
        target = _canon(path)
    except Exception as e:
        return SandboxCheckResult(
            allowed=False,
            reason=f"cannot canonicalize target path: {e}",
        )

    try:
        root = _canon(sandbox_root)
    except Exception as e:
        return SandboxCheckResult(
            allowed=False,
            reason=f"cannot canonicalize sandbox root: {e}",
        )

    t = os.path.normcase(target)
    r = os.path.normcase(root)

    # Determine whether the target is on the same drive / same UNC share
    try:
        common = os.path.commonpath([t, r])
    except ValueError:
        return SandboxCheckResult(
            allowed=False,
            reason=(
                f"path {target!r} is on a different drive than "
                f"sandbox root {root!r}"
            ),
            canonical=target,
        )

    if common != r:
        return SandboxCheckResult(
            allowed=False,
            reason=f"path {target!r} is outside sandbox {root!r}",
            canonical=target,
        )

    return SandboxCheckResult(allowed=True, canonical=target)


def canonicalize(path) -> str:
    """Public helper — same rules as the internal one."""
    return _canon(path)