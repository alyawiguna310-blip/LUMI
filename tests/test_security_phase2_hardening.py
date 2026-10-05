"""
Additional Phase 2 hardening regression tests for F-1..F-6.

These complement tests/test_security_phase2_audit.py by covering edge
cases around scope enforcement, capability/domain validation, and
token bindings.
"""
import json

import pytest

from security.confirmation import ConfirmationResponse
from security.descriptor import (
    capability_domain_consistent,
    Origin,
    Permission,
    Risk,
)
from security.gate import SecurityGate, ToolRequest, ToolSpec
from security.grants import Grant, GrantStore
from security.permissions import PermissionLevel, PermissionPolicy


class _Spy:
    def __init__(self):
        self.calls = []

    def __call__(self, args):
        self.calls.append(dict(args))
        return {"ok": True}


def _gate(tmp_path, grants=None):
    return SecurityGate(
        protected_folder=str(tmp_path / "protected"),
        sandbox_enabled=False,
        policy=PermissionPolicy(auto_approve_max=PermissionLevel.NORMAL),
        grants=grants,
    )


# ============================================================ F-3 scope


def test_f3_multiple_targets_all_must_be_in_scope():
    store = GrantStore()
    store.add(Grant(
        grant_id="g", domain="fs", permission=Permission.WRITE,
        scope=("D:\\LumiProject",),
        grant_type="persistent", max_risk=Risk.CONSEQUENTIAL,
    ))
    both_in = json.dumps({
        "src": "D:\\LumiProject\\a", "dest": "D:\\LumiProject\\b",
    })
    one_out = json.dumps({
        "src": "D:\\LumiProject\\a", "dest": "C:\\elsewhere\\b",
    })
    assert store.find_covering("fs", Permission.WRITE,
                                Risk.CONSEQUENTIAL, both_in) is not None
    assert store.find_covering("fs", Permission.WRITE,
                                Risk.CONSEQUENTIAL, one_out) is None


def test_f3_empty_scope_covers_all():
    store = GrantStore()
    store.add(Grant(
        grant_id="g", domain="fs", permission=Permission.WRITE,
        scope=(),
        grant_type="persistent", max_risk=Risk.CONSEQUENTIAL,
    ))
    any_target = json.dumps({"path": "C:\\anywhere\\x"})
    assert store.find_covering("fs", Permission.WRITE,
                                Risk.CONSEQUENTIAL, any_target) is not None


def test_f3_no_paths_in_target_fails_closed_when_scoped():
    store = GrantStore()
    store.add(Grant(
        grant_id="g", domain="fs", permission=Permission.WRITE,
        scope=("D:\\LumiProject",),
        grant_type="persistent", max_risk=Risk.CONSEQUENTIAL,
    ))
    # Target is empty (no path values) — must fail closed under scope.
    assert store.find_covering("fs", Permission.WRITE,
                                Risk.CONSEQUENTIAL, "{}") is None


# ============================================================ F-5 validation


def test_f5_invalid_domain_rejected():
    store = GrantStore()
    with pytest.raises(ValueError):
        store.add(Grant(
            grant_id="g", domain="not_a_domain",
            permission=Permission.READ, grant_type="persistent",
            max_risk=Risk.NORMAL,
        ))


def test_f5_invalid_permission_type_rejected():
    store = GrantStore()
    with pytest.raises(ValueError):
        store.add(Grant(
            grant_id="g", domain="fs",
            permission="read",
            grant_type="persistent", max_risk=Risk.NORMAL,
        ))


def test_f5_invalid_max_risk_type_rejected():
    store = GrantStore()
    with pytest.raises(ValueError):
        store.add(Grant(
            grant_id="g", domain="fs",
            permission=Permission.READ, grant_type="persistent",
            max_risk=2,
        ))


def test_f5_negative_expiry_rejected():
    store = GrantStore()
    with pytest.raises(ValueError):
        store.add(Grant(
            grant_id="g", domain="fs",
            permission=Permission.READ, grant_type="persistent",
            max_risk=Risk.NORMAL, expires_at=-1.0,
        ))


def test_f5_scope_with_non_string_entry_rejected():
    store = GrantStore()
    with pytest.raises(ValueError):
        store.add(Grant(
            grant_id="g", domain="fs",
            permission=Permission.READ, grant_type="persistent",
            max_risk=Risk.NORMAL, scope=("path", 42),
        ))


# ============================================================ F-6 consistency


def test_f6_capability_domain_consistent_accepts_matching():
    ok, _ = capability_domain_consistent("fs.write", "fs")
    assert ok is True
    ok, _ = capability_domain_consistent("shell.execute", "shell")
    assert ok is True
    ok, _ = capability_domain_consistent("adb.modify", "adb")
    assert ok is True


def test_f6_capability_domain_consistent_rejects_mismatch():
    ok, reason = capability_domain_consistent("fs.write", "shell")
    assert ok is False
    assert "requires domain" in reason


def test_f6_capability_domain_consistent_rejects_unknown_prefix():
    ok, reason = capability_domain_consistent("madeup.read", "madeup")
    assert ok is False
    assert "unknown capability prefix" in reason


# ============================================================ F-1 integration


def test_f1_high_risk_under_force_confirms_and_denies(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="hardening.hr",
        level=PermissionLevel.NORMAL,
        path_params=[],
        description="hardening",
        declared_risk=Risk.HIGH_RISK,
    ))
    gate.confirmation.enable_force(seconds=5, reason="hardening")

    handler_calls = []

    def handler(req):
        handler_calls.append(req)
        return ConfirmationResponse(approved=False, note="deny")

    gate.confirmation.set_handler(handler)
    spy = _Spy()
    result = gate.execute(
        ToolRequest("hardening.hr", {},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert len(handler_calls) == 1
    assert handler_calls[0].forceable is False
    assert result.denied
    assert len(spy.calls) == 0


def test_f1_ordinary_forceable_still_auto_approves(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="hardening.ord",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="hardening",
    ))
    gate.confirmation.enable_force(seconds=5, reason="hardening")

    handler_calls = []

    def handler(req):
        handler_calls.append(req)
        return ConfirmationResponse(approved=False, note="should not run")

    gate.confirmation.set_handler(handler)
    spy = _Spy()
    result = gate.execute(
        ToolRequest("hardening.ord", {},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert len(handler_calls) == 0
    assert result.success
    assert len(spy.calls) == 1


# ============================================================ F-2 integration


def test_f2_external_origin_denied_for_consequential(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="hardening.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="hardening",
    ))
    spy = _Spy()
    for src in (Origin.DISCORD.value, Origin.WHATSAPP.value,
                Origin.WEB.value, Origin.FILE.value,
                Origin.API.value, Origin.UNKNOWN.value):
        result = gate.execute(
            ToolRequest("hardening.write", {}, originating_source=src),
            spy,
        )
        assert result.denied, f"origin {src} must be denied"
    assert len(spy.calls) == 0


def test_f2_ai_internal_reaches_confirmation(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="hardening.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="hardening",
    ))
    handler_calls = []

    def handler(req):
        handler_calls.append(req)
        return ConfirmationResponse(approved=True, note="ok")

    gate.confirmation.set_handler(handler)
    spy = _Spy()
    result = gate.execute(
        ToolRequest("hardening.write", {},
                    originating_source=Origin.AI_INTERNAL.value),
        spy,
    )
    assert len(handler_calls) == 1
    assert result.success
    assert len(spy.calls) == 1