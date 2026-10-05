"""
Phase 5B regression tests: SecurityGate control-plane hard deny.

Every test uses a spy executor; no real file is modified. The tests
assert that:

  * write/delete/rename/move on control-plane paths are denied
    unconditionally,
  * the denial happens before confirmation, grants, tokens, executor,
    and elevated dispatch,
  * read/list_dir on control-plane paths are not blocked by Phase 5B,
  * normal workspace files remain writable.

The tests do not special-case test filenames. They build their paths
from security.control_plane.project_root() so the classification is
exercised end to end.
"""

import copy
from pathlib import Path

import pytest

from security import control_plane as cp
from security.confirmation import ConfirmationResponse
from security.descriptor import Origin, Risk
from security.gate import SecurityGate, ToolRequest, ToolSpec
from security.grants import Grant, GrantStore, Permission
from security.permissions import (
    PermissionLevel,
    PermissionPolicy,
)


ROOT = Path(cp.project_root())
SEC = ROOT / "security"

GATE_PY = str(SEC / "gate.py")
TOKENS_PY = str(SEC / "tokens.py")
MAIN_PY = str(ROOT / "main.py")
CONFIG_PY = str(ROOT / "config.py")
ENV_FILE = str(ROOT / ".env")
TOOL_ROUTER = str(ROOT / "core" / "tool_router.py")
ADMIN_TASKS = str(ROOT / "tools" / "admin_tasks.py")
TERM_GUARD = str(ROOT / "tools" / "terminal_guard.py")
AUDIT_PY = str(ROOT / "storage" / "audit.py")

WORKSPACE = ROOT / "workspace"
NORMAL_FILE = str(WORKSPACE / "app.py")
NORMAL_FILE_2 = str(WORKSPACE / "subdir" / "helper.py")


class _Spy:
    def __init__(self, return_value=None):
        self.calls = []
        self._return = (
            return_value if return_value is not None else {"ok": True}
        )

    def __call__(self, args):
        self.calls.append(copy.deepcopy(args))
        return dict(self._return)


def _approve(req):
    return ConfirmationResponse(
        approved=True,
        note="p5b-approve",
    )


def _make_gate(
    tmp_path,
    *,
    sandbox_enabled=False,
    grants=None,
    auto_approve=PermissionLevel.NORMAL,
):
    return SecurityGate(
        protected_folder=str(tmp_path / "protected"),
        sandbox_root=str(tmp_path / "sandbox")
        if sandbox_enabled
        else "",
        sandbox_enabled=sandbox_enabled,
        policy=PermissionPolicy(
            auto_approve_max=auto_approve
        ),
        grants=grants,
    )


def _register_fs(gate):
    from tools import filesystem as fs

    fs.register(gate)


def _write_request(path, content="x"):
    return ToolRequest(
        "filesystem.write",
        {
            "path": path,
            "content": content,
        },
        originating_source=Origin.LOCAL_USER.value,
    )


def _delete_request(path):
    return ToolRequest(
        "filesystem.delete",
        {
            "path": path,
        },
        originating_source=Origin.LOCAL_USER.value,
    )


def _rename_request(old_path, new_path):
    return ToolRequest(
        "filesystem.rename",
        {
            "old_path": old_path,
            "new_path": new_path,
        },
        originating_source=Origin.LOCAL_USER.value,
    )


def _move_request(src, dest):
    return ToolRequest(
        "filesystem.move",
        {
            "src": src,
            "dest": dest,
        },
        originating_source=Origin.LOCAL_USER.value,
    )


def _read_request(path):
    return ToolRequest(
        "filesystem.read",
        {
            "path": path,
            "max_bytes": 4096,
        },
        originating_source=Origin.LOCAL_USER.value,
    )


def _list_dir_request(path):
    return ToolRequest(
        "filesystem.list_dir",
        {
            "path": path,
        },
        originating_source=Origin.LOCAL_USER.value,
    )


def _assert_control_plane_denial(result, spy):
    assert result.denied is True, (
        f"expected denial, got success={result.success}, "
        f"reason={result.denial_reason!r}"
    )
    assert (
        "control-plane" in result.denial_reason.lower()
    ), result.denial_reason
    assert len(spy.calls) == 0, (
        f"executor was called: {spy.calls}"
    )


# =====================================================================
# 1-6: filesystem write/delete/rename/move to/from security/
# =====================================================================


def test_1_write_to_gate_py_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()
    result = gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_2_delete_gate_py_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()
    result = gate.execute(
        _delete_request(GATE_PY),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_3_rename_normal_to_security_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()
    result = gate.execute(
        _rename_request(
            NORMAL_FILE,
            GATE_PY,
        ),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_4_rename_security_to_normal_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()
    result = gate.execute(
        _rename_request(
            GATE_PY,
            NORMAL_FILE,
        ),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_5_move_into_security_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()
    result = gate.execute(
        _move_request(
            NORMAL_FILE,
            GATE_PY,
        ),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_6_move_out_of_security_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()
    result = gate.execute(
        _move_request(
            GATE_PY,
            NORMAL_FILE,
        ),
        spy,
    )

    _assert_control_plane_denial(result, spy)


# =====================================================================
# 7-13: writes to other control-plane files
# =====================================================================


@pytest.mark.parametrize(
    "target",
    [
        MAIN_PY,
        CONFIG_PY,
        ENV_FILE,
        TOOL_ROUTER,
        ADMIN_TASKS,
        TERM_GUARD,
        AUDIT_PY,
    ],
    ids=[
        "main",
        "config",
        "env",
        "tool_router",
        "admin_tasks",
        "terminal_guard",
        "audit",
    ],
)
def test_7_to_13_write_to_control_plane_file_denied(
    tmp_path,
    target,
):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()
    result = gate.execute(
        _write_request(target),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_13b_delete_other_control_plane_files(tmp_path):
    """The delete denial is not limited to security/gate.py."""
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    for target in (
        MAIN_PY,
        CONFIG_PY,
        ADMIN_TASKS,
        AUDIT_PY,
    ):
        spy = _Spy()

        result = gate.execute(
            _delete_request(target),
            spy,
        )

        _assert_control_plane_denial(result, spy)


# =====================================================================
# 14-15: reads remain permitted by the Phase 5B control-plane check
# =====================================================================


def test_14_read_gate_py_allowed(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)

    spy = _Spy(
        return_value={
            "content": "fake content",
        }
    )

    result = gate.execute(
        _read_request(GATE_PY),
        spy,
    )

    assert result.success is True
    assert len(spy.calls) == 1


def test_14b_read_config_py_allowed(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)

    spy = _Spy(
        return_value={
            "content": "config content",
        }
    )

    result = gate.execute(
        _read_request(CONFIG_PY),
        spy,
    )

    assert result.success is True
    assert len(spy.calls) == 1


def test_15_list_security_dir_allowed(tmp_path):
    """
    Phase 5B must not deny list_dir merely because the target is
    inside the control plane.

    The confirmation handler is installed because the existing
    SecurityGate policy may still require confirmation for list_dir.
    This test is specifically about Phase 5B not producing a
    control-plane denial.
    """
    gate = _make_gate(tmp_path)
    _register_fs(gate)

    # Existing policy may require confirmation for list_dir.
    # We want this test to exercise the executor rather than fail
    # because no confirmation handler was installed.
    gate.confirmation.set_handler(_approve)

    spy = _Spy(
        return_value={
            "entries": [],
        }
    )

    result = gate.execute(
        _list_dir_request(str(SEC)),
        spy,
    )

    assert result.success is True
    assert len(spy.calls) == 1


# =====================================================================
# 16: traversal alias
# =====================================================================


def test_16_traversal_alias_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    alias = str(
        WORKSPACE
        / ".."
        / "security"
        / "gate.py"
    )

    result = gate.execute(
        _write_request(alias),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_16b_forward_slash_alias_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    alias = "/".join(
        [
            str(ROOT),
            "security",
            "gate.py",
        ]
    )

    result = gate.execute(
        _write_request(alias),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_16c_mixed_separator_alias_denied(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    alias = (
        str(ROOT)
        + "/security\\gate.py"
    )

    result = gate.execute(
        _write_request(alias),
        spy,
    )

    _assert_control_plane_denial(result, spy)


# =====================================================================
# 17-21: /force, auto-approve, confirmation, tokens, executor
# =====================================================================


def test_17_force_cannot_bypass(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)

    gate.confirmation.enable_force(
        seconds=10,
        reason="p5b-test",
    )

    handler_calls = []

    def handler(req):
        handler_calls.append(req)
        return ConfirmationResponse(
            approved=False
        )

    gate.confirmation.set_handler(handler)

    spy = _Spy()

    result = gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    _assert_control_plane_denial(result, spy)
    assert handler_calls == []


def test_18_auto_approve_cannot_bypass(tmp_path):
    """
    Even with an auto_approve_max that would skip confirmation,
    the control-plane check fires first.
    """
    gate = _make_gate(
        tmp_path,
        auto_approve=PermissionLevel.DISRUPTIVE,
    )
    _register_fs(gate)

    spy = _Spy()

    result = gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_18b_auto_approve_max_destructive_cannot_bypass(
    tmp_path,
):
    gate = _make_gate(
        tmp_path,
        auto_approve=PermissionLevel.DESTRUCTIVE,
    )
    _register_fs(gate)

    spy = _Spy()

    result = gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_19_confirmation_handler_not_called(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)

    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(
            approved=True
        )

    gate.confirmation.set_handler(handler)

    spy = _Spy()

    gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    assert calls == []


def test_20_token_not_issued(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    issued = []
    real_issue = gate.tokens.issue

    def spy_issue(desc):
        issued.append(desc)
        return real_issue(desc)

    gate.tokens.issue = spy_issue

    spy = _Spy()

    gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    assert issued == []


def test_21_executor_not_called(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    assert spy.calls == []


# =====================================================================
# 22: broad grant cannot authorize control-plane writes
# =====================================================================


def test_22_broad_grant_cannot_authorize(tmp_path):
    grants = GrantStore()

    grants.add(
        Grant(
            grant_id="broad",
            domain="fs",
            permission=Permission.DELETE,
            scope=(str(ROOT),),
            grant_type="per_operation",
            max_risk=Risk.HIGH_RISK,
        )
    )

    gate = _make_gate(
        tmp_path,
        grants=grants,
    )
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    result = gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_22b_broad_grant_does_not_cover_other_control_plane_files(
    tmp_path,
):
    grants = GrantStore()

    grants.add(
        Grant(
            grant_id="broad",
            domain="fs",
            permission=Permission.DELETE,
            scope=(str(ROOT),),
            grant_type="per_operation",
            max_risk=Risk.HIGH_RISK,
        )
    )

    gate = _make_gate(
        tmp_path,
        grants=grants,
    )
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    for target in (
        MAIN_PY,
        CONFIG_PY,
        ADMIN_TASKS,
        AUDIT_PY,
    ):
        spy = _Spy()

        result = gate.execute(
            _write_request(target),
            spy,
        )

        _assert_control_plane_denial(result, spy)


# =====================================================================
# 23: normal workspace file remains writable
# =====================================================================


def test_23_normal_workspace_file_writable(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy(
        return_value={
            "written": True,
        }
    )

    result = gate.execute(
        _write_request(NORMAL_FILE),
        spy,
    )

    assert result.success is True
    assert len(spy.calls) == 1


def test_23b_normal_subdir_workspace_file_writable(
    tmp_path,
):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy(
        return_value={
            "written": True,
        }
    )

    result = gate.execute(
        _write_request(NORMAL_FILE_2),
        spy,
    )

    assert result.success is True
    assert len(spy.calls) == 1


def test_23c_read_workspace_file_remains_writable_without_handler(
    tmp_path,
):
    """
    A normal file write must reach the normal confirmation layer;
    the Phase 5B control-plane check must not fire.
    """
    gate = _make_gate(tmp_path)
    _register_fs(gate)

    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(
            approved=False,
            note="user-no",
        )

    gate.confirmation.set_handler(handler)

    spy = _Spy()

    result = gate.execute(
        _write_request(NORMAL_FILE),
        spy,
    )

    # Not a control-plane denial: the normal confirmation
    # handler was consulted.
    assert len(calls) == 1
    assert (
        "control-plane"
        not in (result.denial_reason or "").lower()
    )


# =====================================================================
# 24-25: sandbox enabled/disabled
# =====================================================================


def test_24_sandbox_enabled_still_denies(tmp_path):
    gate = _make_gate(
        tmp_path,
        sandbox_enabled=True,
    )
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    result = gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    assert result.denied is True
    assert (
        "control-plane"
        in result.denial_reason.lower()
    )
    assert len(spy.calls) == 0


def test_25_sandbox_disabled_still_denies(tmp_path):
    gate = _make_gate(
        tmp_path,
        sandbox_enabled=False,
    )
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    result = gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    _assert_control_plane_denial(result, spy)


# =====================================================================
# 26: all path_params are checked
# =====================================================================


def test_26_rename_both_params_checked_old_first(
    tmp_path,
):
    """old_path in security, new_path normal -> denied."""
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    result = gate.execute(
        _rename_request(
            GATE_PY,
            NORMAL_FILE,
        ),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_26b_rename_second_param_checked(tmp_path):
    """
    old_path normal, new_path in security -> denied.
    """
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    result = gate.execute(
        _rename_request(
            NORMAL_FILE,
            GATE_PY,
        ),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_26c_move_both_params_checked(tmp_path):
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    result = gate.execute(
        _move_request(
            GATE_PY,
            NORMAL_FILE,
        ),
        spy,
    )

    _assert_control_plane_denial(result, spy)

    spy2 = _Spy()

    result2 = gate.execute(
        _move_request(
            NORMAL_FILE,
            GATE_PY,
        ),
        spy2,
    )

    _assert_control_plane_denial(result2, spy2)


# =====================================================================
# 27: control-plane denial before elevated execution
# =====================================================================


def test_27_control_plane_denied_before_elevated(
    tmp_path,
):
    """
    Even for an elevated tool, if a path_param is on the
    control plane, the operation is denied before the elevated
    executor is called.
    """
    gate = _make_gate(tmp_path)

    gate.register_tool(
        ToolSpec(
            name="test.elevated_fs",
            level=PermissionLevel.DESTRUCTIVE,
            path_params=["path"],
            description="elevated fs test",
            capability="fs.delete",
            domain="fs",
            requested_privilege="elevated",
        )
    )

    gate.confirmation.set_handler(_approve)

    elevated_calls = []

    def elevated(
        frozen_args,
        descriptor,
        token_id,
        claims,
    ):
        elevated_calls.append(1)

        return {
            "outcome": "success",
            "operation_id": descriptor.operation_id,
        }

    spy = _Spy()

    result = gate.execute(
        ToolRequest(
            "test.elevated_fs",
            {
                "path": GATE_PY,
            },
            originating_source=Origin.LOCAL_USER.value,
        ),
        executor=spy,
        elevated_executor=elevated,
    )

    assert result.denied is True
    assert (
        "control-plane"
        in result.denial_reason.lower()
    )
    assert len(elevated_calls) == 0
    assert len(spy.calls) == 0


# =====================================================================
# Additional invariants
# =====================================================================


def test_ai_internal_cannot_bypass_control_plane(
    tmp_path,
):
    """
    The denial does not depend on origin;
    AI_INTERNAL is denied too.
    """
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    result = gate.execute(
        ToolRequest(
            "filesystem.write",
            {
                "path": GATE_PY,
                "content": "x",
            },
            originating_source=Origin.AI_INTERNAL.value,
        ),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_local_user_cannot_bypass_control_plane(
    tmp_path,
):
    """
    Even LOCAL_USER origin cannot authorize a
    control-plane write.
    """
    gate = _make_gate(tmp_path)
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    result = gate.execute(
        ToolRequest(
            "filesystem.write",
            {
                "path": GATE_PY,
                "content": "x",
            },
            originating_source=Origin.LOCAL_USER.value,
        ),
        spy,
    )

    _assert_control_plane_denial(result, spy)


def test_safe_level_tool_not_checked(tmp_path):
    """
    A SAFE-level tool with a control-plane path_param must not
    be denied by the Phase 5B control-plane check.
    """
    gate = _make_gate(tmp_path)
    _register_fs(gate)

    spy = _Spy(
        return_value={
            "content": "x",
        }
    )

    result = gate.execute(
        _read_request(GATE_PY),
        spy,
    )

    assert result.success is True
    assert len(spy.calls) == 1


def test_control_plane_deny_returns_before_sandbox_logging(
    tmp_path,
):
    """
    When both sandbox and control-plane would deny,
    the control-plane reason is the one reported.
    """
    gate = _make_gate(
        tmp_path,
        sandbox_enabled=True,
    )
    _register_fs(gate)
    gate.confirmation.set_handler(_approve)

    spy = _Spy()

    result = gate.execute(
        _write_request(GATE_PY),
        spy,
    )

    assert result.denied is True
    assert (
        "control-plane"
        in result.denial_reason.lower()
    )
    assert (
        "sandbox"
        not in result.denial_reason.lower()
    )