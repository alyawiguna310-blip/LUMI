"""
Phase 2 audit regression tests (post-hardening).

These tests verify that the F-1 through F-6 findings have been fixed.
They exercise runtime behavior, not source text.

Each test documents which finding it exercises.
"""
import copy
import json
import threading
import time

import pytest

from security.confirmation import ConfirmationResponse
from security.descriptor import OperationDescriptor, Origin, Risk, Permission
from security.gate import SecurityGate, ToolRequest, ToolSpec
from security.grants import Grant, GrantStore
from security.permissions import (
    PermissionLevel, PermissionPolicy,
)
from security.tokens import TokenStore


class _Spy:
    def __init__(self):
        self.calls = []

    def __call__(self, args):
        self.calls.append(copy.deepcopy(args))
        return {"ok": True}


def _gate(tmp_path, grants=None):
    return SecurityGate(
        protected_folder=str(tmp_path / "protected"),
        sandbox_enabled=False,
        policy=PermissionPolicy(auto_approve_max=PermissionLevel.NORMAL),
        grants=grants,
    )


# =====================================================================
# F-1 — /force cannot bypass a Phase 2 HIGH_RISK confirmation
# =====================================================================


def test_f1_high_risk_confirm_is_reached_even_with_force(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="audit.highrisk",
        level=PermissionLevel.NORMAL,
        path_params=[],
        description="audit",
        declared_risk=Risk.HIGH_RISK,
    ))
    gate.confirmation.enable_force(seconds=10, reason="audit")

    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=False, note="audit-deny")

    gate.confirmation.set_handler(handler)

    spy = _Spy()
    result = gate.execute(
        ToolRequest("audit.highrisk", {},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )

    assert len(calls) == 1, (
        "F-1: /force bypassed the confirmation handler for a HIGH_RISK "
        "operation. The handler was never called."
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_f1_high_risk_executor_not_called_under_force(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="audit.highrisk2",
        level=PermissionLevel.NORMAL,
        path_params=[],
        description="audit",
        declared_risk=Risk.HIGH_RISK,
    ))
    gate.confirmation.enable_force(seconds=10, reason="audit")
    gate.confirmation.set_handler(
        lambda req: ConfirmationResponse(approved=False, note="audit-deny")
    )

    spy = _Spy()
    result = gate.execute(
        ToolRequest("audit.highrisk2", {},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )

    assert len(spy.calls) == 0, (
        "F-1: HIGH_RISK operation executed despite /force and a "
        "denying handler."
    )
    assert result.denied is True


# =====================================================================
# F-2 — ToolRequest requires explicit origin
# =====================================================================


def test_f2_toolrequest_requires_origin():
    """Constructing ToolRequest without originating_source must raise."""
    with pytest.raises(TypeError):
        ToolRequest(tool_name="x", arguments={})


def test_f2_origin_field_is_respected_by_gate(tmp_path):
    """The gate distinguishes LOCAL_USER from external origins."""
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="audit.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="audit",
    ))
    gate.confirmation.set_handler(
        lambda r: ConfirmationResponse(approved=True, note="ok")
    )

    # LOCAL_USER reaches confirmation.
    spy1 = _Spy()
    result1 = gate.execute(
        ToolRequest("audit.write", {},
                    originating_source=Origin.LOCAL_USER.value),
        spy1,
    )

    # DISCORD origin is denied for consequential.
    spy2 = _Spy()
    result2 = gate.execute(
        ToolRequest("audit.write", {},
                    originating_source=Origin.DISCORD.value),
        spy2,
    )

    assert result1.success is True
    assert result2.denied is True
    assert len(spy1.calls) == 1
    assert len(spy2.calls) == 0


# =====================================================================
# F-3 — Grant.scope is enforced
# =====================================================================


def test_f3_grant_scope_is_enforced():
    store = GrantStore()
    store.add(Grant(
        grant_id="g-scoped",
        domain="fs",
        permission=Permission.WRITE,
        scope=("D:\\LumiProject",),
        grant_type="persistent",
        max_risk=Risk.CONSEQUENTIAL,
    ))

    outside = json.dumps({"path": "C:\\Users\\Other\\secret.txt"})
    inside = json.dumps({"path": "D:\\LumiProject\\a.txt"})

    assert store.find_covering("fs", Permission.WRITE,
                                Risk.CONSEQUENTIAL, outside) is None
    assert store.find_covering("fs", Permission.WRITE,
                                Risk.CONSEQUENTIAL, inside) is not None


def test_f3_scope_fails_closed_on_malformed_target():
    store = GrantStore()
    store.add(Grant(
        grant_id="g-scoped",
        domain="fs",
        permission=Permission.WRITE,
        scope=("D:\\LumiProject",),
        grant_type="persistent",
        max_risk=Risk.CONSEQUENTIAL,
    ))

    assert store.find_covering("fs", Permission.WRITE,
                                Risk.CONSEQUENTIAL, "not json") is None
    assert store.find_covering("fs", Permission.WRITE,
                                Risk.CONSEQUENTIAL, "") is None


# =====================================================================
# F-4 — TOCTOU on nested arguments
# =====================================================================


def test_f4_nested_mutation_does_not_reach_executor(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="audit.nested",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="audit",
    ))

    seen = {}

    def spy(args):
        seen["received"] = copy.deepcopy(args)
        return {"ok": True}

    args = {"target": {"path": "C:\\safe"}}

    def mutating_handler(req):
        args["target"]["path"] = "C:\\Windows\\System32\\evil.exe"
        return ConfirmationResponse(approved=True, note="mutated")

    gate.confirmation.set_handler(mutating_handler)

    result = gate.execute(
        ToolRequest("audit.nested", args,
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )

    assert seen["received"]["target"]["path"] == "C:\\safe", (
        "F-4: executor observed a nested argument mutation that "
        "occurred after authorization."
    )


# =====================================================================
# F-5 — Malformed grants are rejected and fail closed
# =====================================================================


def test_f5_malformed_grant_rejected_at_add():
    store = GrantStore()
    with pytest.raises(ValueError):
        store.add(Grant(
            grant_id="bad",
            domain="shell",
            permission=None,
            grant_type="persistent",
            max_risk=Risk.CONSEQUENTIAL,
        ))


def test_f5_invalid_grant_type_rejected():
    store = GrantStore()
    with pytest.raises(ValueError):
        store.add(Grant(
            grant_id="bad2",
            domain="shell",
            permission=Permission.READ,
            grant_type="bogus",
            max_risk=Risk.NORMAL,
        ))


def test_f5_covers_returns_false_on_bad_input():
    """Even if a malformed grant reaches covers(), it must fail closed."""
    malformed = Grant.__new__(Grant)
    object.__setattr__(malformed, "grant_id", "x")
    object.__setattr__(malformed, "domain", "fs")
    object.__setattr__(malformed, "permission", "not-a-permission")
    object.__setattr__(malformed, "scope", ())
    object.__setattr__(malformed, "grant_type", "persistent")
    object.__setattr__(malformed, "max_risk", Risk.NORMAL)
    object.__setattr__(malformed, "expires_at", 0.0)

    result = malformed.covers("fs", Permission.READ, Risk.LOW, "{}")
    assert result is False


# =====================================================================
# F-6 — capability/domain consistency
# =====================================================================


def test_f6_mismatched_capability_domain_rejected(tmp_path):
    gate = _gate(tmp_path)
    with pytest.raises(ValueError):
        gate.register_tool(ToolSpec(
            name="audit.mismatch",
            level=PermissionLevel.DISRUPTIVE,
            path_params=[],
            description="audit",
            capability="fs.write",
            domain="shell",
        ))


def test_f6_only_one_of_capability_domain_rejected(tmp_path):
    gate = _gate(tmp_path)
    with pytest.raises(ValueError):
        gate.register_tool(ToolSpec(
            name="audit.partial",
            level=PermissionLevel.DISRUPTIVE,
            path_params=[],
            description="audit",
            capability="fs.write",
        ))


def test_f6_consistent_capability_domain_accepted(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="audit.consistent",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="audit",
        capability="fs.write",
        domain="fs",
    ))


# =====================================================================
# Positive cases (should continue to pass)
# =====================================================================


def test_positive_external_origin_denies_consequential(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="audit.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="audit",
    ))
    req = ToolRequest("audit.write", {},
                      originating_source=Origin.DISCORD.value)
    spy = _Spy()
    result = gate.execute(req, spy)
    assert result.denied is True
    assert "external origin" in result.denial_reason.lower()


def test_positive_token_reuse_denied():
    d = OperationDescriptor.create(
        tool_name="t", capability="fs.read", domain="fs",
        target={}, parameters={}, declared_risk=Risk.LOW,
    )
    store = TokenStore()
    tid = store.issue(d)
    ok1, _ = store.consume(tid, d)
    ok2, reason2 = store.consume(tid, d)
    assert ok1 is True
    assert ok2 is False
    assert reason2 == "already_used"


def test_positive_token_concurrent_consumption():
    d = OperationDescriptor.create(
        tool_name="t", capability="fs.read", domain="fs",
        target={}, parameters={}, declared_risk=Risk.LOW,
    )
    store = TokenStore()
    tid = store.issue(d)

    results = []
    lock = threading.Lock()

    def consume():
        ok, _ = store.consume(tid, d)
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=consume) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1
    assert results.count(False) == 7


def test_positive_phase1_deny_not_overridden_by_grant(tmp_path):
    grants = GrantStore()
    grants.add(Grant(
        grant_id="g",
        domain="fs",
        permission=Permission.DELETE,
        grant_type="per_operation",
        max_risk=Risk.HIGH_RISK,
    ))

    gate = SecurityGate(
        protected_folder=str(tmp_path / "protected"),
        sandbox_enabled=False,
        policy=PermissionPolicy(auto_approve_max=PermissionLevel.SAFE),
        grants=grants,
    )

    from tools import filesystem as fs
    fs.register(gate)

    protected_file = str(tmp_path / "protected" / "secret.txt")
    spy = _Spy()
    result = gate.execute(
        ToolRequest("filesystem.delete", {"path": protected_file},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert result.denied is True
    assert "protected" in result.denial_reason.lower()
    assert len(spy.calls) == 0