"""
Phase 5C regression tests: workspace classification and workspace
scope policy.

Two layers are tested:

  1. security.workspace.classify_path() directly.
  2. SecurityGate integration: workspace writes proceed through the
     normal authorization flow, control plane still wins, malformed
     paths fail closed for write-class operations.

All gate tests use a spy executor. No real file is modified.
"""
import copy
import os
import sys
from pathlib import Path

import pytest

from security import workspace as ws_policy
from security.control_plane import project_root as cp_project_root
from security.confirmation import ConfirmationResponse
from security.descriptor import Origin, Risk
from security.gate import SecurityGate, ToolRequest, ToolSpec
from security.permissions import PermissionLevel, PermissionPolicy


ROOT = Path(ws_policy.project_root())
SEC = ROOT / "security"
WS = ROOT / "workspace"


class _Spy:
    def __init__(self, return_value=None):
        self.calls = []
        self._return = return_value if return_value is not None else {"ok": True}

    def __call__(self, args):
        self.calls.append(copy.deepcopy(args))
        return dict(self._return)


def _approve(req):
    return ConfirmationResponse(approved=True, note="p5c-approve")


def _deny(req):
    return ConfirmationResponse(approved=False, note="p5c-deny")


def _make_gate(tmp_path, *, sandbox_enabled=False):
    return SecurityGate(
        protected_folder=str(tmp_path / "protected"),
        sandbox_root=str(tmp_path / "sandbox") if sandbox_enabled else "",
        sandbox_enabled=sandbox_enabled,
        policy=PermissionPolicy(auto_approve_max=PermissionLevel.NORMAL),
    )


def _register_fs(gate):
    from tools import filesystem as fs
    fs.register(gate)


def _write_request(path, content="x", origin=Origin.LOCAL_USER.value):
    return ToolRequest(
        "filesystem.write",
        {"path": path, "content": content},
        originating_source=origin,
    )


def _read_request(path):
    return ToolRequest(
        "filesystem.read",
        {"path": path, "max_bytes": 4096},
        originating_source=Origin.LOCAL_USER.value,
    )


def _list_dir_request(path):
    return ToolRequest(
        "filesystem.list_dir",
        {"path": path},
        originating_source=Origin.LOCAL_USER.value,
    )


def _rename_request(old_path, new_path):
    return ToolRequest(
        "filesystem.rename",
        {"old_path": old_path, "new_path": new_path},
        originating_source=Origin.LOCAL_USER.value,
    )


def _move_request(src, dest):
    return ToolRequest(
        "filesystem.move",
        {"src": src, "dest": dest},
        originating_source=Origin.LOCAL_USER.value,
    )


# =====================================================================
# Classifier: happy path
# =====================================================================


def test_workspace_root_classified():
    assert ws_policy.classify_path(str(WS)) == ws_policy.PathClass.WORKSPACE


def test_workspace_child_classified():
    assert ws_policy.classify_path(str(WS / "app.py")) == \
        ws_policy.PathClass.WORKSPACE


def test_nested_workspace_classified():
    assert ws_policy.classify_path(
        str(WS / "a" / "b" / "c" / "helper.py")
    ) == ws_policy.PathClass.WORKSPACE


def test_deeply_nested_workspace_classified():
    assert ws_policy.classify_path(
        str(WS / "x" / "y" / "z" / "deep" / "file.txt")
    ) == ws_policy.PathClass.WORKSPACE


# =====================================================================
# Classifier: near-miss cases
# =====================================================================


def test_workspaceX_is_not_workspace():
    """`D:\\Lumi\\workspaceX` is not inside `D:\\Lumi\\workspace`."""
    assert ws_policy.classify_path(
        str(ROOT / "workspaceX" / "app.py")
    ) == ws_policy.PathClass.OTHER


def test_workspace_substring_is_not_workspace():
    assert ws_policy.classify_path(
        str(ROOT / "myworkspace" / "app.py")
    ) == ws_policy.PathClass.OTHER


def test_workspace_notes_file_is_not_workspace():
    assert ws_policy.classify_path(
        str(ROOT / "workspace_notes.txt")
    ) == ws_policy.PathClass.OTHER


# =====================================================================
# Classifier: control-plane paths
# =====================================================================


def test_security_directory_is_control_plane():
    assert ws_policy.classify_path(str(SEC / "gate.py")) == \
        ws_policy.PathClass.CONTROL_PLANE


def test_main_py_is_control_plane():
    assert ws_policy.classify_path(str(ROOT / "main.py")) == \
        ws_policy.PathClass.CONTROL_PLANE


def test_config_py_is_control_plane():
    assert ws_policy.classify_path(str(ROOT / "config.py")) == \
        ws_policy.PathClass.CONTROL_PLANE


def test_tool_router_is_control_plane():
    assert ws_policy.classify_path(
        str(ROOT / "core" / "tool_router.py")
    ) == ws_policy.PathClass.CONTROL_PLANE


def test_workspace_subdir_named_security_is_not_control_plane():
    """A hypothetical `workspace/security/` is WORKSPACE, not control
    plane. Only the real `security/` directory is control plane."""
    assert ws_policy.classify_path(
        str(WS / "security" / "notes.txt")
    ) == ws_policy.PathClass.WORKSPACE


# =====================================================================
# Classifier: aliases
# =====================================================================


def test_traversal_alias_to_workspace():
    alias = str(WS / "a" / ".." / "app.py")
    assert ws_policy.classify_path(alias) == ws_policy.PathClass.WORKSPACE


def test_traversal_alias_from_workspace_to_security():
    """Escape workspace via .. into security/ → CONTROL_PLANE."""
    alias = str(WS / ".." / "security" / "gate.py")
    assert ws_policy.classify_path(alias) == ws_policy.PathClass.CONTROL_PLANE


def test_forward_slash_workspace_path():
    alias = str(WS).replace("\\", "/") + "/app.py"
    assert ws_policy.classify_path(alias) == ws_policy.PathClass.WORKSPACE


def test_mixed_separator_workspace_path():
    alias = str(WS) + "/subdir\\app.py"
    assert ws_policy.classify_path(alias) == ws_policy.PathClass.WORKSPACE


def test_dot_prefix_workspace_path(tmp_path, monkeypatch):
    monkeypatch.chdir(str(WS) if WS.exists() else str(ROOT))
    # Use an absolute path with a "." segment in the middle.
    alias = str(WS) + os.sep + "." + os.sep + "app.py"
    assert ws_policy.classify_path(alias) == ws_policy.PathClass.WORKSPACE


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows case-insensitive path check")
def test_case_insensitive_workspace():
    alias = str(WS).upper() + "\\APP.PY"
    assert ws_policy.classify_path(alias) == ws_policy.PathClass.WORKSPACE


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Windows case-insensitive path check")
def test_case_insensitive_control_plane():
    alias = str(SEC).upper() + "\\GATE.PY"
    assert ws_policy.classify_path(alias) == ws_policy.PathClass.CONTROL_PLANE


# =====================================================================
# Classifier: fail-closed inputs
# =====================================================================


def test_none_is_unknown():
    assert ws_policy.classify_path(None) == ws_policy.PathClass.UNKNOWN


def test_empty_is_unknown():
    assert ws_policy.classify_path("") == ws_policy.PathClass.UNKNOWN


def test_whitespace_is_unknown():
    assert ws_policy.classify_path("   ") == ws_policy.PathClass.UNKNOWN


def test_non_string_is_unknown():
    assert ws_policy.classify_path(123) == ws_policy.PathClass.UNKNOWN
    assert ws_policy.classify_path(["x"]) == ws_policy.PathClass.UNKNOWN


# =====================================================================
# Gate: workspace writes follow normal flow
# =====================================================================


def test_workspace_write_reaches_executor_after_confirmation(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy(return_value={"written": True})
    result = gate.execute(_write_request(str(WS / "app.py")), spy)
    assert result.success is True
    assert len(spy.calls) == 1


def test_workspace_write_still_consults_confirmation(tmp_path):
    """Workspace is not an auto-approve scope. The confirmation handler
    is still consulted for a DISRUPTIVE write."""
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=True, note="ok")

    gate.confirmation.set_handler(handler)
    spy = _Spy(return_value={"written": True})
    result = gate.execute(_write_request(str(WS / "app.py")), spy)
    assert result.success is True
    assert len(calls) == 1


def test_workspace_write_denied_when_handler_denies(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_deny)
    spy = _Spy()
    result = gate.execute(_write_request(str(WS / "app.py")), spy)
    assert result.denied is True
    assert len(spy.calls) == 0


# =====================================================================
# Gate: outside-workspace paths keep existing behavior
# =====================================================================


def test_outside_workspace_write_still_reaches_executor(tmp_path):
    """A normal path outside workspace but also outside control plane
    still goes through the normal flow."""
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy(return_value={"written": True})
    result = gate.execute(
        _write_request(str(ROOT / "tools" / "scratch.txt")),
        spy,
    )
    assert result.success is True
    assert len(spy.calls) == 1


def test_outside_workspace_write_still_consults_confirmation(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=True, note="ok")

    gate.confirmation.set_handler(handler)
    spy = _Spy(return_value={"written": True})
    gate.execute(_write_request(str(ROOT / "tools" / "scratch.txt")), spy)
    assert len(calls) == 1


# =====================================================================
# Gate: control plane still wins
# =====================================================================


def test_control_plane_denial_takes_priority(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        _write_request(str(SEC / "gate.py")),
        spy,
    )
    assert result.denied is True
    assert "control-plane" in result.denial_reason.lower()
    assert len(spy.calls) == 0


def test_control_plane_denial_wins_over_workspace_alias(tmp_path):
    """Even a path that traverses through workspace to reach security
    is denied."""
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    alias = str(WS / ".." / "security" / "gate.py")
    result = gate.execute(_write_request(alias), spy)
    assert result.denied is True
    assert "control-plane" in result.denial_reason.lower()
    assert len(spy.calls) == 0


# =====================================================================
# Gate: fail-closed for write-class on malformed paths
# =====================================================================


def test_none_path_denied_for_write(tmp_path):
    gate = _make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=["path"],
        description="test",
    ))
    spy = _Spy()
    result = gate.execute(
        ToolRequest("fake.write", {"path": None},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_empty_path_denied_for_write(tmp_path):
    gate = _make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=["path"],
        description="test",
    ))
    spy = _Spy()
    result = gate.execute(
        ToolRequest("fake.write", {"path": ""},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_whitespace_path_denied_for_write(tmp_path):
    gate = _make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=["path"],
        description="test",
    ))
    spy = _Spy()
    result = gate.execute(
        ToolRequest("fake.write", {"path": "   "},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_read_level_does_not_get_workspace_denial(tmp_path):
    """SAFE-level reads are not subject to the Phase 5C write-class
    classification. If they are denied, it is not by Phase 5C."""
    gate = _make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.read",
        level=PermissionLevel.SAFE,
        path_params=["path"],
        description="test",
    ))
    spy = _Spy()
    result = gate.execute(
        ToolRequest("fake.read", {"path": ""},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert "classify" not in (result.denial_reason or "").lower()


# =====================================================================
# Gate: multi-path operations (rename, move)
# =====================================================================


def test_rename_both_paths_checked_workspace_side(tmp_path):
    """Normal rename inside workspace still works."""
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy(return_value={"renamed": True})
    result = gate.execute(
        _rename_request(str(WS / "a.py"), str(WS / "b.py")),
        spy,
    )
    assert result.success is True
    assert len(spy.calls) == 1


def test_rename_with_empty_old_path_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        _rename_request("", str(WS / "b.py")),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_rename_with_empty_new_path_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        _rename_request(str(WS / "a.py"), ""),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_move_with_empty_src_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        _move_request("", str(WS / "b.py")),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_move_with_empty_dest_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        _move_request(str(WS / "a.py"), ""),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_rename_into_control_plane_denied_before_classification(tmp_path):
    """Control-plane denial fires before workspace classification."""
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        _rename_request(str(WS / "a.py"), str(SEC / "gate.py")),
        spy,
    )
    assert result.denied is True
    assert "control-plane" in result.denial_reason.lower()
    assert len(spy.calls) == 0


# =====================================================================
# Gate: reads remain compatible
# =====================================================================


def test_read_control_plane_allowed(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    spy = _Spy(return_value={"content": "x"})
    result = gate.execute(_read_request(str(SEC / "gate.py")), spy)
    assert result.success is True
    assert len(spy.calls) == 1


def test_read_workspace_allowed(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    spy = _Spy(return_value={"content": "x"})
    result = gate.execute(_read_request(str(WS / "app.py")), spy)
    assert result.success is True
    assert len(spy.calls) == 1


def test_list_dir_workspace_allowed(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    spy = _Spy(return_value={"entries": []})
    result = gate.execute(_list_dir_request(str(WS)), spy)
    assert result.success is True
    assert len(spy.calls) == 1


def test_list_dir_security_allowed(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy(return_value={"entries": []})
    result = gate.execute(_list_dir_request(str(SEC)), spy)
    assert result.success is True
    assert len(spy.calls) == 1


# =====================================================================
# Origin invariance
# =====================================================================


def test_ai_internal_workspace_write_still_confirms(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=True, note="ok")

    gate.confirmation.set_handler(handler)
    spy = _Spy(return_value={"written": True})
    result = gate.execute(
        _write_request(str(WS / "app.py"),
                       origin=Origin.AI_INTERNAL.value),
        spy,
    )
    assert result.success is True
    assert len(calls) == 1


def test_local_user_write_to_control_plane_still_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        _write_request(str(SEC / "gate.py"),
                       origin=Origin.LOCAL_USER.value),
        spy,
    )
    assert result.denied is True
    assert "control-plane" in result.denial_reason.lower()


def test_ai_internal_cannot_bypass_workspace_classification(tmp_path):
    """AI_INTERNAL origin does not bypass the fail-closed workspace
    classification for write-class operations."""
    gate = _make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=["path"],
        description="test",
    ))
    spy = _Spy()
    result = gate.execute(
        ToolRequest("fake.write", {"path": ""},
                    originating_source=Origin.AI_INTERNAL.value),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


# =====================================================================
# Independence from sandbox
# =====================================================================


def test_sandbox_enabled_workspace_write_still_normal_flow(tmp_path):
    """With sandbox enabled and workspace outside the sandbox root,
    the sandbox denies the write. This is the sandbox's behavior, not
    Phase 5C's. We simply confirm Phase 5C does not introduce a new
    denial on top."""
    gate = _make_gate(tmp_path, sandbox_enabled=True)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_write_request(str(WS / "app.py")), spy)
    # Denied by sandbox (workspace is outside sandbox root). The reason
    # must not be a Phase 5C classification failure.
    if result.denied:
        assert "classify" not in result.denial_reason.lower()


def test_sandbox_disabled_workspace_write_normal_flow(tmp_path):
    gate = _make_gate(tmp_path, sandbox_enabled=False)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy(return_value={"written": True})
    result = gate.execute(_write_request(str(WS / "app.py")), spy)
    assert result.success is True
    assert len(spy.calls) == 1


# =====================================================================
# describe()
# =====================================================================


def test_describe_shape():
    d = ws_policy.describe()
    assert set(d.keys()) == {"project_root", "workspace_root"}
    assert isinstance(d["project_root"], str)
    assert isinstance(d["workspace_root"], str)


def test_workspace_root_is_project_root_subdir():
    assert ws_policy.workspace_root().endswith("workspace")
    assert ws_policy.project_root() == cp_project_root()