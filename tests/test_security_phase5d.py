"""
Phase 5D regression tests: explicit mutation classification.

Verifies:

  * The mutation classifier is explicit (tool identity, not level).
  * Control-plane enforcement fires for mutations only.
  * Reads are unaffected by control-plane / workspace write checks.
  * Bypass attempts (/force, auto-approval, broad grants, wrong origin)
    cannot weaken the control-plane denial.
  * Malformed paths on mutations are fail-closed.

All gate tests use spy executors. No real file is modified.
"""
import copy
from pathlib import Path

import pytest

from security import control_plane as cp
from security import workspace as ws_policy
from security.confirmation import ConfirmationResponse
from security.descriptor import Origin, Risk
from security.gate import (
    SecurityGate,
    ToolRequest,
    ToolSpec,
    _is_mutation,
    _KNOWN_MUTATION_TOOLS,
    _KNOWN_READ_TOOLS,
)
from security.grants import Grant, GrantStore, Permission
from security.permissions import (
    PermissionLevel, PermissionPolicy,
)


ROOT = Path(cp.project_root())
SEC = ROOT / "security"
WS = ROOT / "workspace"

GATE_PY = str(SEC / "gate.py")
TOKENS_PY = str(SEC / "tokens.py")
CONFIG_PY = str(ROOT / "config.py")
MAIN_PY = str(ROOT / "main.py")
TOOL_ROUTER = str(ROOT / "core" / "tool_router.py")
ADMIN_TASKS = str(ROOT / "tools" / "admin_tasks.py")
NORMAL_FILE = str(WS / "app.py")
OTHER_FILE = str(ROOT / "tools" / "scratch.txt")


class _Spy:
    def __init__(self, return_value=None):
        self.calls = []
        self._return = return_value if return_value is not None else {"ok": True}

    def __call__(self, args):
        self.calls.append(copy.deepcopy(args))
        return dict(self._return)


def _approve(req):
    return ConfirmationResponse(approved=True, note="p5d-approve")


def _deny(req):
    return ConfirmationResponse(approved=False, note="p5d-deny")


def _make_gate(tmp_path, *, grants=None, auto_approve=PermissionLevel.NORMAL):
    return SecurityGate(
        protected_folder=str(tmp_path / "protected"),
        sandbox_enabled=False,
        policy=PermissionPolicy(auto_approve_max=auto_approve),
        grants=grants,
    )


def _register_fs(gate):
    from tools import filesystem as fs
    fs.register(gate)


def _write(path, content="x", origin=Origin.LOCAL_USER.value):
    return ToolRequest("filesystem.write", {"path": path, "content": content},
                       originating_source=origin)


def _create_dir(path, origin=Origin.LOCAL_USER.value):
    return ToolRequest("filesystem.create_dir", {"path": path},
                       originating_source=origin)


def _rename(old_path, new_path, origin=Origin.LOCAL_USER.value):
    return ToolRequest("filesystem.rename",
                       {"old_path": old_path, "new_path": new_path},
                       originating_source=origin)


def _move(src, dest, origin=Origin.LOCAL_USER.value):
    return ToolRequest("filesystem.move", {"src": src, "dest": dest},
                       originating_source=origin)


def _delete(path, origin=Origin.LOCAL_USER.value):
    return ToolRequest("filesystem.delete", {"path": path},
                       originating_source=origin)


def _read(path):
    return ToolRequest("filesystem.read",
                       {"path": path, "max_bytes": 4096},
                       originating_source=Origin.LOCAL_USER.value)


def _list_dir(path):
    return ToolRequest("filesystem.list_dir", {"path": path},
                       originating_source=Origin.LOCAL_USER.value)


# =====================================================================
# A. Mutation classification
# =====================================================================


def _spec(name, level=PermissionLevel.DISRUPTIVE, path_params=None,
          mutating=None, **kw):
    return ToolSpec(
        name=name,
        level=level,
        path_params=path_params or [],
        description="test",
        mutating=mutating,
        **kw,
    )


def test_a_mutation_classification_filesystem_write():
    assert _is_mutation(_spec("filesystem.write", path_params=["path"])) is True


def test_a_mutation_classification_filesystem_create_dir():
    assert _is_mutation(
        _spec("filesystem.create_dir", path_params=["path"])
    ) is True


def test_a_mutation_classification_filesystem_rename():
    assert _is_mutation(
        _spec("filesystem.rename", path_params=["old_path", "new_path"])
    ) is True


def test_a_mutation_classification_filesystem_move():
    assert _is_mutation(
        _spec("filesystem.move", path_params=["src", "dest"])
    ) is True


def test_a_mutation_classification_filesystem_delete():
    assert _is_mutation(
        _spec("filesystem.delete", path_params=["path"])
    ) is True


def test_a_mutation_classification_filesystem_read():
    assert _is_mutation(
        _spec("filesystem.read", level=PermissionLevel.SAFE,
              path_params=["path"])
    ) is False


def test_a_mutation_classification_filesystem_list_dir():
    assert _is_mutation(
        _spec("filesystem.list_dir", level=PermissionLevel.SAFE,
              path_params=["path"])
    ) is False


def test_a_known_mutation_set_is_explicit():
    assert _KNOWN_MUTATION_TOOLS == frozenset({
        "filesystem.write",
        "filesystem.create_dir",
        "filesystem.rename",
        "filesystem.move",
        "filesystem.delete",
    })


def test_a_known_read_set_is_explicit():
    assert _KNOWN_READ_TOOLS == frozenset({
        "filesystem.read",
        "filesystem.list_dir",
    })


def test_a_classification_does_not_depend_solely_on_level():
    """A NORMAL-level unknown tool with no path_params is NOT a mutation,
    and a SAFE-level unknown tool with path_params IS fail-closed to
    mutation. Neither case is determined by PermissionLevel alone."""
    # Unknown name, SAFE level, no path_params -> False.
    assert _is_mutation(
        _spec("custom.tool", level=PermissionLevel.SAFE, path_params=[])
    ) is False
    # Unknown name, SAFE level, has path_params -> fail closed to True.
    assert _is_mutation(
        _spec("custom.tool", level=PermissionLevel.SAFE,
              path_params=["path"])
    ) is True


def test_a_explicit_mutating_flag_on_unknown_tool():
    assert _is_mutation(
        _spec("custom.mut", level=PermissionLevel.NORMAL, mutating=True)
    ) is True
    assert _is_mutation(
        _spec("custom.read", level=PermissionLevel.DISRUPTIVE,
              path_params=["path"], mutating=False)
    ) is False


def test_a_known_sets_override_explicit_flag():
    """An explicit mutating=False on a known mutation is ignored."""
    assert _is_mutation(
        _spec("filesystem.write", path_params=["path"], mutating=False)
    ) is True


# =====================================================================
# B. Control-plane enforcement for mutations
# =====================================================================


def _assert_cp_denial(result, spy):
    assert result.denied is True
    assert "control-plane" in result.denial_reason.lower()
    assert len(spy.calls) == 0


def test_b_write_gate_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_write(GATE_PY), spy)
    _assert_cp_denial(result, spy)


def test_b_delete_gate_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_delete(GATE_PY), spy)
    _assert_cp_denial(result, spy)


def test_b_create_dir_under_security_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_create_dir(str(SEC / "newdir")), spy)
    _assert_cp_denial(result, spy)


def test_b_rename_into_control_plane_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_rename(NORMAL_FILE, GATE_PY), spy)
    _assert_cp_denial(result, spy)


def test_b_rename_out_of_control_plane_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_rename(GATE_PY, NORMAL_FILE), spy)
    _assert_cp_denial(result, spy)


def test_b_move_into_control_plane_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_move(NORMAL_FILE, GATE_PY), spy)
    _assert_cp_denial(result, spy)


def test_b_move_out_of_control_plane_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_move(GATE_PY, NORMAL_FILE), spy)
    _assert_cp_denial(result, spy)


@pytest.mark.parametrize("target", [MAIN_PY, CONFIG_PY, ADMIN_TASKS,
                                    TOOL_ROUTER, TOKENS_PY])
def test_b_write_to_various_control_plane_files_denied(tmp_path, target):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_write(target), spy)
    _assert_cp_denial(result, spy)


def test_b_all_path_params_checked_in_rename(tmp_path):
    """The first param being normal does not mask the second."""
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_rename(NORMAL_FILE, GATE_PY), spy)
    _assert_cp_denial(result, spy)


def test_b_all_path_params_checked_in_move(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_move(OTHER_FILE, GATE_PY), spy)
    _assert_cp_denial(result, spy)


# =====================================================================
# C. Bypass resistance
# =====================================================================


def test_c_force_cannot_bypass(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.enable_force(seconds=10, reason="p5d")
    handler_calls = []

    def handler(req):
        handler_calls.append(req)
        return ConfirmationResponse(approved=True)

    gate.confirmation.set_handler(handler)
    spy = _Spy()
    result = gate.execute(_write(GATE_PY), spy)
    _assert_cp_denial(result, spy)
    assert handler_calls == []


def test_c_auto_approve_cannot_bypass(tmp_path):
    gate = _make_gate(tmp_path, auto_approve=PermissionLevel.DESTRUCTIVE)
    _register_fs(gate)
    spy = _Spy()
    result = gate.execute(_write(GATE_PY), spy)
    _assert_cp_denial(result, spy)


def test_c_broad_grant_cannot_bypass(tmp_path):
    grants = GrantStore()
    grants.add(Grant(
        grant_id="broad", domain="fs", permission=Permission.DELETE,
        scope=(str(ROOT),), grant_type="per_operation",
        max_risk=Risk.HIGH_RISK,
    ))
    gate = _make_gate(tmp_path, grants=grants)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_write(GATE_PY), spy)
    _assert_cp_denial(result, spy)


def test_c_confirmation_handler_not_reached(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=True)

    gate.confirmation.set_handler(handler)
    spy = _Spy()
    gate.execute(_write(GATE_PY), spy)
    assert calls == []


def test_c_token_not_issued(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    issued = []
    real = gate.tokens.issue
    gate.tokens.issue = lambda d: (issued.append(d), real(d))[1]
    spy = _Spy()
    gate.execute(_write(GATE_PY), spy)
    assert issued == []


def test_c_executor_not_reached(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    gate.execute(_write(GATE_PY), spy)
    assert spy.calls == []


def test_c_elevated_helper_not_reached(tmp_path):
    gate = _make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="custom.elevated_fs",
        level=PermissionLevel.DESTRUCTIVE,
        path_params=["path"],
        description="test",
        capability="fs.delete",
        domain="fs",
        requested_privilege="elevated",
    ))
    gate.confirmation.set_handler(_approve)
    elevated_calls = []

    def elevated(frozen_args, descriptor, token_id, claims):
        elevated_calls.append(1)
        return {"outcome": "success",
                "operation_id": descriptor.operation_id}

    spy = _Spy()
    result = gate.execute(
        ToolRequest("custom.elevated_fs", {"path": GATE_PY},
                    originating_source=Origin.LOCAL_USER.value),
        executor=spy,
        elevated_executor=elevated,
    )
    assert result.denied is True
    assert "control-plane" in result.denial_reason.lower()
    assert elevated_calls == []
    assert spy.calls == []


# =====================================================================
# D. Read compatibility
# =====================================================================


def test_d_read_control_plane_allowed(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    spy = _Spy(return_value={"content": "x"})
    result = gate.execute(_read(GATE_PY), spy)
    assert result.success is True
    assert len(spy.calls) == 1


def test_d_list_control_plane_allowed(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy(return_value={"entries": []})
    result = gate.execute(_list_dir(str(SEC)), spy)
    assert result.success is True
    assert len(spy.calls) == 1


def test_d_read_workspace_allowed(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    spy = _Spy(return_value={"content": "x"})
    result = gate.execute(_read(NORMAL_FILE), spy)
    assert result.success is True
    assert len(spy.calls) == 1


def test_d_list_workspace_allowed(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    spy = _Spy(return_value={"entries": []})
    result = gate.execute(_list_dir(str(WS)), spy)
    assert result.success is True
    assert len(spy.calls) == 1


# =====================================================================
# E. Workspace behavior
# =====================================================================


def test_e_workspace_mutation_follows_normal_authorization(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=True, note="ok")

    gate.confirmation.set_handler(handler)
    spy = _Spy(return_value={"written": True})
    result = gate.execute(_write(NORMAL_FILE), spy)
    assert result.success is True
    assert len(calls) == 1
    assert len(spy.calls) == 1


def test_e_workspace_classification_does_not_self_authorize(tmp_path):
    """A workspace path still requires the confirmation handler; it is
    not auto-approved."""
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_deny)
    spy = _Spy()
    result = gate.execute(_write(NORMAL_FILE), spy)
    assert result.denied is True
    assert len(spy.calls) == 0


def test_e_denied_confirmation_prevents_execution(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_deny)
    spy = _Spy()
    result = gate.execute(_write(NORMAL_FILE), spy)
    assert result.denied is True
    assert len(spy.calls) == 0


def test_e_approved_confirmation_permits_normal_execution(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy(return_value={"written": True})
    result = gate.execute(_write(NORMAL_FILE), spy)
    assert result.success is True
    assert len(spy.calls) == 1


# =====================================================================
# F. Malformed paths fail closed for mutations
# =====================================================================


@pytest.mark.parametrize("bad_path", [None, "", "   "])
def test_f_empty_or_none_path_denied_for_write(tmp_path, bad_path):
    gate = _make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="custom.mut", level=PermissionLevel.DISRUPTIVE,
        path_params=["path"], description="test",
    ))
    spy = _Spy()
    result = gate.execute(
        ToolRequest("custom.mut", {"path": bad_path},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_f_none_path_denied_for_delete(tmp_path):
    gate = _make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="custom.del", level=PermissionLevel.DESTRUCTIVE,
        path_params=["path"], description="test",
    ))
    spy = _Spy()
    result = gate.execute(
        ToolRequest("custom.del", {"path": None},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_f_rename_with_empty_old_path_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_rename("", NORMAL_FILE), spy)
    assert result.denied is True
    assert len(spy.calls) == 0


def test_f_rename_with_empty_new_path_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_rename(NORMAL_FILE, ""), spy)
    assert result.denied is True
    assert len(spy.calls) == 0


def test_f_move_with_empty_src_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_move("", NORMAL_FILE), spy)
    assert result.denied is True
    assert len(spy.calls) == 0


def test_f_move_with_empty_dest_denied(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_move(NORMAL_FILE, ""), spy)
    assert result.denied is True
    assert len(spy.calls) == 0


# =====================================================================
# G. Origin / provenance interaction
# =====================================================================


def test_g_ai_internal_cannot_bypass_control_plane(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_write(GATE_PY, origin=Origin.AI_INTERNAL.value),
                          spy)
    _assert_cp_denial(result, spy)


def test_g_local_user_cannot_bypass_control_plane(tmp_path):
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_write(GATE_PY, origin=Origin.LOCAL_USER.value),
                          spy)
    _assert_cp_denial(result, spy)


def test_g_external_origin_denied_for_consequential_write(tmp_path):
    """External origin + CONSEQUENTIAL+ is denied by Phase 4, before
    reaching the executor. This behavior is preserved."""
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        _write(str(ROOT / "tools" / "scratch.txt"),
               origin=Origin.DISCORD.value),
        spy,
    )
    assert result.denied is True
    assert "external origin" in result.denial_reason.lower()
    assert len(spy.calls) == 0


def test_g_external_origin_denied_before_mutation_classification(tmp_path):
    """An external-origin mutation to control plane is denied by Phase
    5B, not by the Phase 4 provenance check, because Phase 5B fires
    first."""
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(_write(GATE_PY, origin=Origin.DISCORD.value), spy)
    assert result.denied is True
    assert "control-plane" in result.denial_reason.lower()


def test_g_mutation_classification_does_not_change_provenance(tmp_path):
    """Descriptor must preserve originating_source/derived_from for
    mutation-classified tools."""
    gate = _make_gate(tmp_path); _register_fs(gate)
    captured = {}
    real = gate.tokens.issue
    gate.tokens.issue = lambda d: (captured.setdefault("d", d), real(d))[1]
    gate.confirmation.set_handler(_approve)
    spy = _Spy(return_value={"written": True})
    gate.execute(_write(NORMAL_FILE, origin=Origin.LOCAL_USER.value), spy)
    assert captured["d"].originating_source == Origin.LOCAL_USER.value


# =====================================================================
# H. Regression safety: Phase 5A / 5B / 5C integration intact
# =====================================================================


def test_h_phase5a_classifier_still_works():
    assert cp.is_control_plane(GATE_PY) is True
    assert cp.is_control_plane(NORMAL_FILE) is False


def test_h_phase5c_classifier_still_works():
    assert ws_policy.classify_path(NORMAL_FILE) == \
        ws_policy.PathClass.WORKSPACE
    assert ws_policy.classify_path(GATE_PY) == \
        ws_policy.PathClass.CONTROL_PLANE


def test_h_control_plane_check_precedes_workspace_check(tmp_path):
    """A path inside workspace/security (which classifies as WORKSPACE,
    not CONTROL_PLANE, because it is under workspace/) is not confused
    with the real security/ directory."""
    gate = _make_gate(tmp_path); _register_fs(gate)
    gate.confirmation.set_handler(_approve)
    spy = _Spy(return_value={"written": True})
    # workspace/security is inside workspace, not the real security dir.
    result = gate.execute(
        _write(str(WS / "security" / "notes.txt")), spy
    )
    # Allowed by control-plane check (path is workspace), then normal
    # confirmation flow.
    assert result.success is True
    assert len(spy.calls) == 1


def test_h_registered_tool_mutation_classification_is_reported(tmp_path):
    """Registration works without error for a spec with the new field."""
    gate = _make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="custom.tool", level=PermissionLevel.NORMAL,
        path_params=[], description="test",
        mutating=False,
    ))
    assert "custom.tool" in gate._tools