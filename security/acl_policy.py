"""
security/acl_policy.py

ACL protection planning for Lumi's control-plane paths.

This module produces a structured, deterministic plan describing the
ACL changes that would be required to protect Lumi's control plane at
the OS level. It NEVER applies any ACL. It does not invoke any
modifying command. It is a planning and review tool.

The plan targets the eventual policy:

    Lumi runtime identity:  READ + EXECUTE allowed
                            WRITE / MODIFY / DELETE / RENAME /
                            REPLACE / CHANGE_PERMISSIONS /
                            TAKE_OWNERSHIP denied

    Human Administrator:    normal administrative maintenance remains
                            possible.

The plan is derived from:
  - the Phase 5A control-plane classifier (the single source of truth
    for "which paths are protected"),
  - the current runtime identity,
  - read-only ACL inspection results from security.acl_inspection.

Classification
--------------

A path is "control_plane" iff security.control_plane.is_control_plane
returns True for it. Everything else, including workspace paths, is
classified as "other" and receives no protection plan.

Safety
------

- The module does not import subprocess; all inspection happens in
  security.acl_inspection. The plan is data only.
- render_plan_text() returns a human-readable string. It does not
  execute anything.
- The __main__ entry point prints a plan to stdout for manual review.

CLI
---

    python -m security.acl_policy

prints the plan for the default set of control-plane paths.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

from security.acl_inspection import (
    AceEntry,
    PathInspection,
    RuntimeIdentity,
    get_runtime_identity,
    inspect_path,
)
from security.control_plane import is_control_plane


# ------------------------------------------------------------------ intended policy


# Rights that will eventually be denied to the Lumi runtime identity on
# control-plane paths.
_INTENDED_DENY_RIGHTS: Tuple[str, ...] = (
    "WRITE",
    "MODIFY",
    "DELETE",
    "RENAME",
    "REPLACE",
    "CHANGE_PERMISSIONS",
    "TAKE_OWNERSHIP",
)

# Rights that will be preserved for the runtime identity.
_PRESERVED_READ_RIGHTS: Tuple[str, ...] = ("READ", "EXECUTE")


# ------------------------------------------------------------------ data


@dataclass(frozen=True)
class PathPlan:
    canonical_path: str
    path_class: str          # "control_plane" | "other" | "unknown"
    exists: bool
    is_dir: bool
    owner: str
    runtime_identity: RuntimeIdentity
    existing_aces: Tuple[AceEntry, ...]
    intended_deny_rights: Tuple[str, ...]
    intended_preserve_read_rights: Tuple[str, ...]
    inheritance_enabled: bool
    warnings: Tuple[str, ...]
    safe_to_apply: bool


@dataclass(frozen=True)
class AclPlan:
    runtime_identity: RuntimeIdentity
    paths: Tuple[PathPlan, ...]
    warnings: Tuple[str, ...]
    safe_to_apply: bool


# ------------------------------------------------------------------ classification


def classify_for_protection(path: str) -> str:
    """Return 'control_plane', 'other', or 'unknown'. Fail-closed: any
    exception from the classifier yields 'unknown'."""
    try:
        if is_control_plane(path):
            return "control_plane"
    except Exception:
        return "unknown"
    return "other"


# ------------------------------------------------------------------ path plan


def build_path_plan(
    inspection: PathInspection,
    runtime: RuntimeIdentity,
) -> PathPlan:
    warnings = []
    klass = classify_for_protection(inspection.canonical_path)

    if klass != "control_plane":
        # Nothing to protect. Return a data-complete but non-actionable
        # entry so the reviewer can see the classification.
        return PathPlan(
            canonical_path=inspection.canonical_path,
            path_class=klass,
            exists=inspection.exists,
            is_dir=inspection.is_dir,
            owner=inspection.owner,
            runtime_identity=runtime,
            existing_aces=inspection.aces,
            intended_deny_rights=(),
            intended_preserve_read_rights=(),
            inheritance_enabled=inspection.inheritance_enabled,
            warnings=(),
            safe_to_apply=False,
        )

    safe = True

    if klass == "unknown":
        warnings.append("classifier returned 'unknown' for this path")
        safe = False

    if inspection.error:
        warnings.append(f"inspection error: {inspection.error}")
        safe = False

    if not inspection.exists:
        warnings.append(
            "path does not exist; the ACL cannot be applied to a missing "
            "path (create it, or exclude it from the plan)"
        )
        safe = False

    if not inspection.canonical_path:
        warnings.append("canonical path is empty")
        safe = False

    if runtime.error:
        warnings.append(f"runtime identity error: {runtime.error}")
        safe = False

    if not runtime.sid:
        warnings.append("runtime identity has no SID")
        safe = False

    if runtime.is_elevated:
        warnings.append(
            "runtime identity is elevated; a deny ACE against an "
            "Administrator token is not enforceable by normal means"
        )
        safe = False

    if inspection.is_dir:
        warnings.append(
            "this is a directory; the deny ACE will need (OI)(CI) flags "
            "to propagate to children and to new files"
        )

    if inspection.inheritance_enabled:
        warnings.append(
            "inheritance is enabled; explicit (OI)(CI) deny flags are "
            "required, and the reviewer must decide whether to keep "
            "inheritance or convert to explicit ACEs"
        )

    return PathPlan(
        canonical_path=inspection.canonical_path,
        path_class=klass,
        exists=inspection.exists,
        is_dir=inspection.is_dir,
        owner=inspection.owner,
        runtime_identity=runtime,
        existing_aces=inspection.aces,
        intended_deny_rights=_INTENDED_DENY_RIGHTS,
        intended_preserve_read_rights=_PRESERVED_READ_RIGHTS,
        inheritance_enabled=inspection.inheritance_enabled,
        warnings=tuple(warnings),
        safe_to_apply=safe,
    )


# ------------------------------------------------------------------ overall plan


def build_plan(
    paths: Optional[Iterable[str]] = None,
    *,
    inspections: Optional[Iterable[PathInspection]] = None,
    runtime: Optional[RuntimeIdentity] = None,
) -> AclPlan:
    """Build an ACL protection plan.

    Callers must supply either `paths` (which will be inspected via the
    read-only inspector) or `inspections` (pre-built inspection data,
    used by tests and offline review). If neither is provided, a
    ValueError is raised.

    `runtime` defaults to get_runtime_identity(). It can be passed
    explicitly to make the plan deterministic for a specific identity.
    """
    if runtime is None:
        runtime = get_runtime_identity()

    if inspections is None:
        if paths is None:
            raise ValueError(
                "build_plan requires either `paths` or `inspections`"
            )
        inspections = tuple(inspect_path(p) for p in paths)
    else:
        inspections = tuple(inspections)

    path_plans = tuple(
        build_path_plan(ins, runtime) for ins in inspections
    )

    overall_warnings = []
    if runtime.error:
        overall_warnings.append(f"runtime identity error: {runtime.error}")
    if runtime.is_elevated:
        overall_warnings.append(
            "runtime is elevated; ACL protection cannot bind against an "
            "Administrator token"
        )
    if not runtime.sid:
        overall_warnings.append("runtime identity has no SID")

    control_plane_plans = [
        p for p in path_plans if p.path_class == "control_plane"
    ]
    if not control_plane_plans:
        overall_warnings.append(
            "no control-plane paths in this plan; nothing to apply"
        )

    safe = (
        bool(control_plane_plans)
        and all(p.safe_to_apply for p in control_plane_plans)
        and not runtime.error
        and not runtime.is_elevated
        and bool(runtime.sid)
    )

    return AclPlan(
        runtime_identity=runtime,
        paths=path_plans,
        warnings=tuple(overall_warnings),
        safe_to_apply=safe,
    )


# ------------------------------------------------------------------ rendering


def render_plan_text(plan: AclPlan) -> str:
    """Human-readable rendering of the plan. Does not execute anything."""
    lines = []
    rid = plan.runtime_identity
    lines.append("ACL Protection Plan (READ-ONLY - not applied)")
    lines.append("=" * 60)
    lines.append(
        f"Runtime identity: {rid.username or '(unknown)'} "
        f"({rid.sid or '(no sid)'}) "
        f"[source={rid.source}, elevated={rid.is_elevated}]"
    )
    lines.append(f"Overall safe_to_apply: {plan.safe_to_apply}")
    for w in plan.warnings:
        lines.append(f"  WARN: {w}")
    lines.append("")

    for p in plan.paths:
        lines.append(f"Path: {p.canonical_path or '(empty)'}")
        lines.append(f"  class:       {p.path_class}")
        if not p.exists:
            kind = "missing"
        elif p.is_dir:
            kind = "directory"
        else:
            kind = "file"
        lines.append(f"  type:        {kind}")
        lines.append(f"  exists:      {p.exists}")
        lines.append(f"  owner:       {p.owner or '(unknown)'}")
        lines.append(
            f"  inheritance: "
            f"{'enabled' if p.inheritance_enabled else 'disabled'}"
        )
        if p.existing_aces:
            lines.append(f"  existing ACEs:")
            for ace in p.existing_aces:
                rights = ", ".join(ace.rights) if ace.rights else "(none)"
                inherited = " (inherited)" if ace.inherited else ""
                lines.append(
                    f"    {ace.ace_type} {ace.identity} : "
                    f"{rights}{inherited}"
                )
        if p.intended_deny_rights:
            lines.append(f"  intended deny to runtime identity:")
            for r in p.intended_deny_rights:
                lines.append(f"    - {r}")
            lines.append(f"  intended preserve read:")
            for r in p.intended_preserve_read_rights:
                lines.append(f"    - {r}")
        if p.warnings:
            lines.append(f"  warnings:")
            for w in p.warnings:
                lines.append(f"    - {w}")
        lines.append(f"  safe_to_apply: {p.safe_to_apply}")
        lines.append("")

    return "\n".join(lines)


# ------------------------------------------------------------------ default path set


def _default_control_plane_paths() -> Tuple[str, ...]:
    """The default path list for CLI review. Sourced from the Phase 5A
    control-plane module so the single source of truth is preserved."""
    # The raw (properly cased) lists are module-private but stable.
    from security import control_plane as cp
    raw_dirs = getattr(cp, "_PROTECTED_DIRS_RAW", ())
    raw_files = getattr(cp, "_PROTECTED_FILES_RAW", ())
    return tuple(raw_dirs) + tuple(raw_files)


# ------------------------------------------------------------------ CLI


def _main(argv=None) -> int:
    plan = build_plan(paths=_default_control_plane_paths())
    sys.stdout.write(render_plan_text(plan))
    sys.stdout.write("\n")
    sys.stdout.write(
        "This is a plan only. No ACL has been applied. Review it and "
        "decide separately whether to implement enforcement.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(_main())