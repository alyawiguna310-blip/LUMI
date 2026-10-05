"""
Phase 5E regression tests: read-only ACL inspection and planning.

No test modifies any real ACL. Live inspection tests inspect existing
files without touching them; all other tests use synthetic inspection
data.
"""
import os
import sys
from pathlib import Path

import pytest

from security import acl_inspection as ai
from security import acl_policy as ap
from security import control_plane as cp


ROOT = Path(cp.project_root())
SEC = ROOT / "security"
WS = ROOT / "workspace"


# =====================================================================
# helpers
# =====================================================================


def _runtime(**overrides):
    kwargs = dict(
        username="TEST\\lumi",
        sid="S-1-5-21-1111111111-2222222222-3333333333-1001",
        is_elevated=False,
        source="fake",
        error="",
    )
    kwargs.update(overrides)
    return ai.RuntimeIdentity(**kwargs)


def _ace(identity="TEST\\lumi", rights=("Read",),
         ace_type="Allow", inherited=False):
    return ai.AceEntry(identity=identity, rights=tuple(rights),
                       ace_type=ace_type, inherited=inherited)


def _inspection(path, *, exists=True, is_dir=False,
                owner="BUILTIN\\Administrators",
                inheritance_enabled=True, aces=(), error=""):
    return ai.PathInspection(
        canonical_path=str(path),
        exists=exists,
        is_dir=is_dir,
        owner=owner,
        inheritance_enabled=inheritance_enabled,
        aces=tuple(aces),
        error=error,
    )


# =====================================================================
# A. Protected-path selection
# =====================================================================


def test_a_security_directory_is_control_plane():
    plan = ap.build_plan(
        inspections=[_inspection(SEC, is_dir=True)],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "control_plane"


def test_a_file_inside_security_is_control_plane():
    plan = ap.build_plan(
        inspections=[_inspection(SEC / "gate.py")],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "control_plane"


@pytest.mark.parametrize("sub", [
    "main.py", "config.py", ".env",
    "core/tool_router.py", "tools/admin_tasks.py",
    "tools/terminal_guard.py", "storage/audit.py",
])
def test_a_all_explicit_protected_files(sub):
    plan = ap.build_plan(
        inspections=[_inspection(ROOT / sub)],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "control_plane"


def test_a_workspace_is_not_control_plane():
    plan = ap.build_plan(
        inspections=[_inspection(WS / "app.py")],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "other"


def test_a_ordinary_app_file_not_control_plane():
    plan = ap.build_plan(
        inspections=[_inspection(ROOT / "tools" / "filesystem.py")],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "other"


def test_a_similarly_named_path_not_control_plane():
    plan = ap.build_plan(
        inspections=[_inspection(ROOT / "security_notes.py")],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "other"


def test_a_workspace_security_subdir_not_control_plane():
    plan = ap.build_plan(
        inspections=[_inspection(WS / "security" / "notes.txt")],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "other"


# =====================================================================
# B. Canonicalization / malformed paths
# =====================================================================


def test_b_none_path_handled_safely():
    ins = ai.inspect_path(None)
    assert isinstance(ins, ai.PathInspection)
    assert ins.error


def test_b_empty_path_handled_safely():
    ins = ai.inspect_path("")
    assert ins.error


def test_b_whitespace_path_handled_safely():
    ins = ai.inspect_path("   ")
    assert ins.error


def test_b_non_string_path_handled_safely():
    ins = ai.inspect_path(123)
    assert ins.error
    ins = ai.inspect_path(["x"])
    assert ins.error


def test_b_relative_path_does_not_raise():
    ins = ai.inspect_path("relative/path/that/does/not/exist")
    assert isinstance(ins, ai.PathInspection)


def test_b_traversal_alias_to_control_plane_detected():
    alias = str(WS / ".." / "security" / "gate.py")
    plan = ap.build_plan(
        inspections=[_inspection(alias)],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "control_plane"


def test_b_forward_slash_path_detected():
    alias = str(SEC).replace("\\", "/") + "/gate.py"
    plan = ap.build_plan(
        inspections=[_inspection(alias)],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "control_plane"


def test_b_mixed_separators_detected():
    alias = str(SEC) + "/gate.py"
    plan = ap.build_plan(
        inspections=[_inspection(alias)],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "control_plane"


@pytest.mark.skipif(sys.platform != "win32",
                    reason="case-insensitive path check on Windows")
def test_b_case_insensitive_path_detected():
    alias = str(SEC).upper() + "\\GATE.PY"
    plan = ap.build_plan(
        inspections=[_inspection(alias)],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "control_plane"


# =====================================================================
# C. Runtime identity
# =====================================================================


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
def test_c_runtime_identity_resolves():
    ident = ai.get_runtime_identity()
    assert isinstance(ident, ai.RuntimeIdentity)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
def test_c_runtime_identity_has_sid_structure():
    ident = ai.get_runtime_identity()
    if ident.error:
        pytest.skip(f"identity unavailable: {ident.error}")
    assert ident.sid.startswith("S-1-"), ident.sid
    assert isinstance(ident.is_elevated, bool)


def test_c_runtime_identity_on_non_windows(monkeypatch):
    monkeypatch.setattr(ai.os, "name", "posix")
    ident = ai.get_runtime_identity()
    assert ident.error


def test_c_runtime_identity_handles_missing_whoami(monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows-only")
    monkeypatch.setattr(ai.shutil, "which", lambda name: None)
    ident = ai.get_runtime_identity()
    assert ident.error


# =====================================================================
# D. ACL inspection of real files (read-only)
# =====================================================================


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
def test_d_inspect_real_file():
    ins = ai.inspect_path(__file__)
    assert isinstance(ins, ai.PathInspection)
    assert ins.exists is True
    assert ins.is_dir is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
def test_d_inspect_real_directory():
    ins = ai.inspect_path(str(SEC))
    assert isinstance(ins, ai.PathInspection)
    assert ins.exists is True
    assert ins.is_dir is True


def test_d_inspect_nonexistent():
    ins = ai.inspect_path(str(ROOT / "this-path-does-not-exist-xyz-9f8a7"))
    assert isinstance(ins, ai.PathInspection)
    assert ins.exists is False


# =====================================================================
# E. ACL planning
# =====================================================================


def test_e_control_plane_receives_deny_and_preserve_lists():
    plan = ap.build_plan(
        inspections=[_inspection(SEC / "gate.py")],
        runtime=_runtime(),
    )
    p = plan.paths[0]
    assert p.path_class == "control_plane"
    for right in ("WRITE", "MODIFY", "DELETE", "RENAME", "REPLACE",
                  "CHANGE_PERMISSIONS", "TAKE_OWNERSHIP"):
        assert right in p.intended_deny_rights
    for right in ("READ", "EXECUTE"):
        assert right in p.intended_preserve_read_rights


def test_e_workspace_no_protection_plan():
    plan = ap.build_plan(
        inspections=[_inspection(WS / "app.py")],
        runtime=_runtime(),
    )
    p = plan.paths[0]
    assert p.path_class == "other"
    assert p.intended_deny_rights == ()
    assert p.intended_preserve_read_rights == ()
    assert p.safe_to_apply is False


def test_e_normal_app_file_no_protection_plan():
    plan = ap.build_plan(
        inspections=[_inspection(ROOT / "tools" / "filesystem.py")],
        runtime=_runtime(),
    )
    assert plan.paths[0].path_class == "other"
    assert plan.paths[0].intended_deny_rights == ()


def test_e_plan_is_deterministic():
    ins = [_inspection(SEC / "gate.py", inheritance_enabled=False)]
    r = _runtime()
    p1 = ap.build_plan(inspections=ins, runtime=r)
    p2 = ap.build_plan(inspections=ins, runtime=r)
    assert p1.paths[0].canonical_path == p2.paths[0].canonical_path
    assert p1.paths[0].intended_deny_rights == p2.paths[0].intended_deny_rights
    assert p1.paths[0].intended_preserve_read_rights == \
        p2.paths[0].intended_preserve_read_rights
    assert p1.paths[0].safe_to_apply == p2.paths[0].safe_to_apply
    assert p1.safe_to_apply == p2.safe_to_apply


def test_e_malformed_inspection_fails_closed():
    ins = _inspection(SEC / "gate.py", error="simulated inspection failure")
    plan = ap.build_plan(inspections=[ins], runtime=_runtime())
    assert plan.paths[0].safe_to_apply is False
    assert plan.safe_to_apply is False
    assert any("simulated" in w for w in plan.paths[0].warnings)


def test_e_nonexistent_protected_path_not_safe():
    ins = _inspection(SEC / "missing.py", exists=False)
    plan = ap.build_plan(inspections=[ins], runtime=_runtime())
    assert plan.paths[0].safe_to_apply is False
    assert plan.safe_to_apply is False


def test_e_elevated_runtime_not_safe():
    ins = _inspection(SEC / "gate.py")
    r = _runtime(is_elevated=True)
    plan = ap.build_plan(inspections=[ins], runtime=r)
    assert plan.paths[0].safe_to_apply is False
    assert plan.safe_to_apply is False


def test_e_runtime_without_sid_not_safe():
    ins = _inspection(SEC / "gate.py")
    r = _runtime(sid="")
    plan = ap.build_plan(inspections=[ins], runtime=r)
    assert plan.paths[0].safe_to_apply is False


def test_e_directory_warns_about_recursion():
    ins = _inspection(SEC, is_dir=True)
    plan = ap.build_plan(inspections=[ins], runtime=_runtime())
    text = " ".join(plan.paths[0].warnings).lower()
    assert "director" in text or "recursive" in text


def test_e_inheritance_enabled_warns():
    ins = _inspection(SEC, is_dir=True, inheritance_enabled=True)
    plan = ap.build_plan(inspections=[ins], runtime=_runtime())
    text = " ".join(plan.paths[0].warnings).lower()
    assert "inherit" in text


def test_e_render_plan_text_smoke():
    plan = ap.build_plan(
        inspections=[_inspection(SEC / "gate.py")],
        runtime=_runtime(),
    )
    text = ap.render_plan_text(plan)
    assert isinstance(text, str)
    assert "ACL Protection Plan" in text
    assert "READ-ONLY" in text


def test_e_render_does_not_include_executable_commands():
    plan = ap.build_plan(
        inspections=[_inspection(SEC / "gate.py")],
        runtime=_runtime(),
    )
    text = ap.render_plan_text(plan)
    assert "Set-Acl" not in text
    assert "icacls /deny" not in text.lower()
    assert "icacls /grant" not in text.lower()


# =====================================================================
# F. Safety invariants — planner never modifies
# =====================================================================


class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_f_inspection_uses_read_only_commands_only(monkeypatch):
    """Every subprocess invocation made by acl_inspection must be a
    read-only command. Fail if any modifying flag is seen."""
    calls = []

    def fake_run(args, **kwargs):
        calls.append([str(a) for a in args])
        # Return a valid-shaped Get-Acl response.
        return _FakeCompleted(
            returncode=0,
            stdout=(
                "OWNER=BUILTIN\\Administrators\n"
                "PROTECTED=False\n"
                "ACE=BUILTIN\\Administrators|FullControl|Allow|False\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(ai.subprocess, "run", fake_run)
    monkeypatch.setattr(
        ai.shutil, "which",
        lambda name: f"C:\\fake\\{name}.exe"
        if name in ("powershell", "pwsh", "whoami") else None,
    )

    ai.inspect_path(str(SEC / "gate.py"))

    forbidden_tokens = (
        "/deny", "/grant", "/remove", "/setowner", "/reset",
        "/inheritance", "set-acl", "icacls", "takeown", "cacls",
    )
    assert calls, "expected at least one subprocess call"
    for call_args in calls:
        joined = " ".join(call_args).lower()
        for tok in forbidden_tokens:
            assert tok not in joined, (
                f"forbidden token {tok!r} in subprocess call: {joined!r}"
            )


def test_f_inspection_only_calls_get_acl(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append([str(a) for a in args])
        return _FakeCompleted(
            returncode=0,
            stdout=(
                "OWNER=x\nPROTECTED=False\n"
            ),
        )

    monkeypatch.setattr(ai.subprocess, "run", fake_run)
    monkeypatch.setattr(
        ai.shutil, "which",
        lambda name: f"C:\\fake\\{name}.exe"
        if name in ("powershell", "pwsh") else None,
    )

    ai.inspect_path(str(SEC / "gate.py"))

    assert calls
    for call_args in calls:
        joined = " ".join(call_args)
        assert "Get-Acl" in joined or "get-acl" in joined.lower()


def test_f_build_plan_with_inspections_performs_no_io(monkeypatch):
    """When inspections are pre-built, build_plan must not call
    subprocess at all."""
    calls = []

    def fake_run(args, **kwargs):
        calls.append(1)
        return _FakeCompleted()

    monkeypatch.setattr(ai.subprocess, "run", fake_run)

    ap.build_plan(
        inspections=[_inspection(SEC / "gate.py")],
        runtime=_runtime(),
    )
    assert calls == []


def test_f_acl_policy_source_contains_no_modifying_commands():
    """Static sanity: the policy module source must not contain
    executable ACL commands or references to modifying cmdlets."""
    import inspect as _inspect
    src = _inspect.getsource(ap)
    forbidden = ("Set-Acl", "icacls /deny", "icacls /grant",
                 "takeown", "/inheritance:e", "/reset")
    for token in forbidden:
        assert token not in src, (
            f"acl_policy.py must not contain {token!r}"
        )


def test_f_path_plan_is_data_only():
    plan = ap.build_plan(
        inspections=[_inspection(SEC / "gate.py")],
        runtime=_runtime(),
    )
    for p in plan.paths:
        assert isinstance(p.intended_deny_rights, tuple)
        assert isinstance(p.intended_preserve_read_rights, tuple)
        assert isinstance(p.warnings, tuple)


def test_f_build_plan_requires_paths_or_inspections():
    with pytest.raises(ValueError):
        ap.build_plan(runtime=_runtime())


def test_f_canonical_paths_preserved_in_plan():
    """The plan must use the inspected canonical path verbatim, not a
    re-derived one."""
    canon = str(SEC / "gate.py")
    ins = _inspection(canon)
    plan = ap.build_plan(inspections=[ins], runtime=_runtime())
    assert plan.paths[0].canonical_path == canon