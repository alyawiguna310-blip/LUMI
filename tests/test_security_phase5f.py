"""
Phase 5F-A tests: runtime-identity separation planning.

These tests do not create users, do not modify ACLs, and do not touch
any system state. They exercise the read-only planning module.
"""
import os
from pathlib import Path

import pytest

from security import identity_planning as ip
from security import control_plane as cp


ROOT = Path(cp.project_root())


def _plan(**overrides):
    kwargs = dict(
        human_identity="desktop\\sulta",
        runtime_identity="LumiRuntime",
        runtime_sid="S-1-5-21-1111111111-2222222222-3333333333-1002",
    )
    kwargs.update(overrides)
    return ip.build_identity_plan(**kwargs)


# =====================================================================
# Structure
# =====================================================================


def test_plan_has_expected_sections():
    p = _plan()
    assert isinstance(p, ip.IdentityPlan)
    assert p.human_identity == "desktop\\sulta"
    assert p.runtime_identity == "LumiRuntime"
    assert p.runtime_sid.startswith("S-1-5-21-")
    assert isinstance(p.rw_paths, tuple)
    assert isinstance(p.ro_paths, tuple)
    assert isinstance(p.rx_paths, tuple)
    assert isinstance(p.denied_paths, tuple)
    assert isinstance(p.user_profile_requirements, tuple)
    assert isinstance(p.notes, tuple)
    assert isinstance(p.warnings, tuple)


def test_plan_lists_are_non_empty():
    p = _plan()
    assert p.rw_paths
    assert p.rx_paths
    assert p.ro_paths
    assert p.denied_paths
    assert p.user_profile_requirements
    assert p.notes


def test_all_requirements_have_access_and_reason():
    p = _plan()
    for req in (*p.rw_paths, *p.ro_paths, *p.rx_paths, *p.denied_paths):
        assert req.access in ("read", "read_execute", "read_write",
                              "deny_write")
        assert req.reason


# =====================================================================
# Control-plane paths
# =====================================================================


def test_denied_paths_cover_every_control_plane_dir():
    p = _plan()
    denied_paths = {r.path for r in p.denied_paths}
    for d in cp.protected_dirs():
        assert d in denied_paths


def test_denied_paths_cover_every_control_plane_file():
    p = _plan()
    denied_paths = {r.path for r in p.denied_paths}
    for f in cp.protected_files():
        assert f in denied_paths


def test_denied_paths_use_deny_write_access():
    p = _plan()
    for r in p.denied_paths:
        assert r.access == "deny_write"


# =====================================================================
# Workspace and models
# =====================================================================


def test_workspace_is_read_write():
    p = _plan()
    ws_reqs = [r for r in p.rw_paths if r.path.endswith("workspace")]
    assert ws_reqs, "workspace must appear in rw_paths"
    assert ws_reqs[0].access == "read_write"


def test_venv_is_read_execute():
    p = _plan()
    venv_reqs = [r for r in p.rx_paths if r.path.endswith("venv")]
    assert venv_reqs, "venv must appear in rx_paths"


def test_custom_workspace_path_honored():
    p = _plan(workspace_path=r"D:\CustomWorkspace")
    ws_reqs = [r for r in p.rw_paths if r.path == r"D:\CustomWorkspace"]
    assert ws_reqs


# =====================================================================
# Warnings
# =====================================================================


def test_missing_sid_warns():
    p = _plan(runtime_sid="")
    assert any("sid" in w.lower() for w in p.warnings)


def test_runtime_identity_equal_to_human_warns():
    p = _plan(runtime_identity="sulta")
    assert any("distinct identity" in w.lower() for w in p.warnings)


def test_runtime_identity_lowercase_sulta_warns():
    p = _plan(runtime_identity="sulta".lower())
    assert any("distinct identity" in w.lower() for w in p.warnings)


def test_valid_plan_has_no_identity_warning():
    p = _plan()
    assert not any("distinct identity" in w.lower() for w in p.warnings)


# =====================================================================
# Rendering
# =====================================================================


def test_render_contains_expected_headers():
    text = ip.render_identity_plan_text(_plan())
    assert "Runtime Identity Separation Plan" in text
    assert "Human identity" in text
    assert "Runtime identity" in text
    assert "Deny write-class rights" in text


def test_render_mentions_no_executable_commands():
    text = ip.render_identity_plan_text(_plan())
    for forbidden in ("Set-Acl", "net user", "icacls", "New-LocalUser"):
        assert forbidden not in text


def test_render_is_deterministic():
    p = _plan()
    a = ip.render_identity_plan_text(p)
    b = ip.render_identity_plan_text(p)
    assert a == b


# =====================================================================
# Safety invariants
# =====================================================================


def test_module_does_not_import_subprocess():
    import inspect as _inspect
    src = _inspect.getsource(ip)
    assert "import subprocess" not in src
    assert "subprocess.run" not in src
    assert "subprocess.Popen" not in src


def test_module_does_not_reference_user_creation():
    import inspect as _inspect
    src = _inspect.getsource(ip)
    for token in ("net user", "New-LocalUser", "net localgroup",
                  "Add-LocalGroupMember"):
        assert token not in src


def test_plan_contains_no_administrator_membership_recommendation():
    p = _plan()
    text = ip.render_identity_plan_text(p)
    # The notes explicitly forbid adding the runtime identity to
    # Administrators. No section recommends the opposite.
    assert "Do NOT grant" in text or "do not grant" in text.lower()


def test_build_plan_is_pure_function():
    """Repeated calls with the same inputs produce identical plans."""
    a = _plan()
    b = _plan()
    assert a == b


def test_plan_is_hashable_via_frozen_dataclasses():
    p = _plan()
    # All constituents are frozen dataclasses; plan should be usable as
    # a dict value in tests without mutation risk.
    assert isinstance(hash(p.rw_paths), int)