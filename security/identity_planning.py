"""
security/identity_planning.py

Read-only planning module for Lumi's runtime-identity separation.

This module has NO side effects:

  - it does not create Windows users
  - it does not modify ACLs, ownership, or inheritance
  - it does not touch the registry
  - it does not invoke subprocess
  - it does not modify any file

Its only job is to produce a structured plan describing what a future
implementation phase would need to do to run Lumi under a dedicated
low-privilege Windows identity. The plan is intended for review before
any actual change is made.

The module deliberately separates:

  - the runtime identity plan (this file),
  - the ACL protection plan (security/acl_policy.py),
  - the control-plane classification (security/control_plane.py).

It imports the control-plane list from security.control_plane so that
classification remains the single source of truth.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from security.control_plane import (
    protected_dirs,
    protected_files,
    project_root,
)


# ------------------------------------------------------------------ data


@dataclass(frozen=True)
class PathRequirement:
    path: str
    access: str  # "read", "read_execute", "read_write", "deny_write"
    reason: str


@dataclass(frozen=True)
class IdentityPlan:
    human_identity: str
    runtime_identity: str
    runtime_sid: str
    rw_paths: Tuple[PathRequirement, ...]
    ro_paths: Tuple[PathRequirement, ...]
    rx_paths: Tuple[PathRequirement, ...]
    denied_paths: Tuple[PathRequirement, ...]
    user_profile_requirements: Tuple[str, ...]
    notes: Tuple[str, ...]
    warnings: Tuple[str, ...]


# ------------------------------------------------------------------ defaults


def _default_workspace_path() -> str:
    return str(Path(project_root()) / "workspace")


def _default_models_path() -> str:
    return str(Path(project_root()) / "models")


def _default_venv_path() -> str:
    return str(Path(project_root()) / "venv")


def _default_logs_path() -> str:
    """Shared logs directory. Falls back to project-relative if no
    dedicated location is configured."""
    return str(Path(project_root()) / "logs")


# ------------------------------------------------------------------ construction


def build_identity_plan(
    *,
    human_identity: str,
    runtime_identity: str,
    runtime_sid: str = "",
    workspace_path: str = "",
    models_path: str = "",
    venv_path: str = "",
    logs_path: str = "",
) -> IdentityPlan:
    """Produce a structured plan describing the intended separation.

    Does not read the filesystem, does not check whether paths exist.
    Purely data-in / data-out so that tests can construct synthetic
    plans and reviewers can reason about them offline.
    """
    workspace = workspace_path or _default_workspace_path()
    models = models_path or _default_models_path()
    venv = venv_path or _default_venv_path()
    logs = logs_path or _default_logs_path()

    rw = (
        PathRequirement(
            workspace, "read_write",
            "Lumi edits application and project code here",
        ),
        PathRequirement(
            logs, "read_write",
            "Lumi writes its runtime logs here (shared, admin-readable)",
        ),
        PathRequirement(
            rf"C:\Users\{runtime_identity}\.lumi", "read_write",
            "Lumi's memory and per-user runtime state",
        ),
        PathRequirement(
            rf"C:\Users\{runtime_identity}\.android", "read_write",
            "ADB keys are per-user; needs re-authorization once",
        ),
    )

    rx = (
        PathRequirement(
            venv, "read_execute",
            "Python interpreter and site-packages",
        ),
    )

    ro = (
        PathRequirement(
            str(Path(project_root()) / "ai"), "read",
            "Application source",
        ),
        PathRequirement(
            str(Path(project_root()) / "core"), "read",
            "Application source (tool_router protected separately)",
        ),
        PathRequirement(
            str(Path(project_root()) / "tools"), "read",
            "Application source (admin_tasks/terminal_guard protected separately)",
        ),
        PathRequirement(
            str(Path(project_root()) / "ui"), "read",
            "Application source",
        ),
        PathRequirement(
            str(Path(project_root()) / "voice"), "read",
            "Application source",
        ),
        PathRequirement(
            str(Path(project_root()) / "storage"), "read",
            "Application source (audit protected separately)",
        ),
        PathRequirement(
            models, "read",
            "TTS/STT model files",
        ),
        PathRequirement(
            str(Path(project_root()) / "main.py"), "read",
            "Entry point (control plane - read only)",
        ),
        PathRequirement(
            str(Path(project_root()) / "config.py"), "read",
            "Configuration (control plane - read only)",
        ),
        PathRequirement(
            str(Path(project_root()) / ".env"), "read",
            "Secrets (control plane - read only)",
        ),
    )

    denied = []
    for d in protected_dirs():
        denied.append(PathRequirement(
            d, "deny_write",
            "Control-plane directory; deny write/delete/rename/replace",
        ))
    for f in protected_files():
        denied.append(PathRequirement(
            f, "deny_write",
            "Control-plane file; deny write/delete/rename/replace",
        ))

    user_profile_requirements = (
        "Dedicated profile at C:\\Users\\<runtime_identity>\\ (created "
        "on first logon or first CreateProcessWithLogonW with "
        "LOGON_WITH_PROFILE)",
        "Own HKCU registry hive",
        "Own AppData\\Roaming and AppData\\Local",
        "Own .android directory for ADB keys (re-authorization of "
        "Android devices is required once)",
    )

    notes = (
        "Launch LumiRuntime's process from sulta's session via "
        "CreateProcessWithLogonW with LOGON_WITH_PROFILE so the GUI "
        "appears on the human's desktop.",
        "Do NOT grant LumiRuntime membership in Administrators.",
        "Do NOT use Everyone or Users as the deny-ACE identity for the "
        "control plane; use the runtime identity's SID explicitly.",
        "Set HF_HOME and TORCH_HOME in the launcher to a shared "
        "read-only model cache to avoid duplicate downloads.",
        "Set PYTHONPYCACHEPREFIX to a LumiRuntime-writable directory so "
        "Python does not attempt to write .pyc files into the read-only "
        "venv.",
        "Verify that privileged_pipe._make_security_attributes grants "
        "the elevated helper's token access to the pipe (the helper "
        "runs as elevated sulta, not as LumiRuntime).",
        "UAC prompts raised by LumiRuntime will show 'LumiRuntime wants "
        "to make changes' - this is expected.",
    )

    warnings = []
    if not runtime_sid:
        warnings.append(
            "runtime_sid is empty; the plan is informational only until "
            "a concrete SID is supplied"
        )
    if runtime_identity.lower() in ("sulta", "administrator"):
        warnings.append(
            f"runtime_identity {runtime_identity!r} appears to be the "
            f"human account; the plan should target a distinct identity"
        )

    return IdentityPlan(
        human_identity=human_identity,
        runtime_identity=runtime_identity,
        runtime_sid=runtime_sid,
        rw_paths=rw,
        ro_paths=ro,
        rx_paths=rx,
        denied_paths=tuple(denied),
        user_profile_requirements=user_profile_requirements,
        notes=notes,
        warnings=tuple(warnings),
    )


# ------------------------------------------------------------------ rendering


def render_identity_plan_text(plan: IdentityPlan) -> str:
    lines = []
    lines.append("Runtime Identity Separation Plan (DESIGN - not applied)")
    lines.append("=" * 60)
    lines.append(f"Human identity:   {plan.human_identity}")
    lines.append(f"Runtime identity: {plan.runtime_identity}")
    lines.append(f"Runtime SID:      {plan.runtime_sid or '(not supplied)'}")
    lines.append("")

    def _section(title, items):
        lines.append(title)
        for req in items:
            lines.append(f"  [{req.access:14}] {req.path}")
            lines.append(f"                   {req.reason}")
        lines.append("")

    _section("Read + Write:", plan.rw_paths)
    _section("Read + Execute:", plan.rx_paths)
    _section("Read only:", plan.ro_paths)
    _section("Deny write-class rights:", plan.denied_paths)

    lines.append("User profile requirements:")
    for req in plan.user_profile_requirements:
        lines.append(f"  - {req}")
    lines.append("")

    lines.append("Notes:")
    for n in plan.notes:
        lines.append(f"  - {n}")
    lines.append("")

    if plan.warnings:
        lines.append("Warnings:")
        for w in plan.warnings:
            lines.append(f"  - {w}")
        lines.append("")

    lines.append(
        "This is a plan only. No Windows user has been created, no ACL "
        "has been modified."
    )
    return "\n".join(lines)


# ------------------------------------------------------------------ CLI


def _main(argv=None) -> int:
    import getpass
    try:
        human = os.environ.get("USERNAME", "") or getpass.getuser()
    except Exception:
        human = ""
    plan = build_identity_plan(
        human_identity=human,
        runtime_identity="LumiRuntime",
        runtime_sid="",
    )
    import sys
    sys.stdout.write(render_identity_plan_text(plan))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(_main(_sys.argv[1:]))