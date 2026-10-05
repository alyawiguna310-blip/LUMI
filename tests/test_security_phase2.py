"""
Phase 2 tests: Operation Descriptor, Risk, Permission, Tokens, Grants,
Origin trust boundary, and gate integration.
"""
import json
import time
from dataclasses import replace as dc_replace

import pytest

from security.descriptor import (
    OperationDescriptor,
    Origin,
    Risk,
    Permission,
    Domain,
    permission_from_capability,
)
from security.grants import Grant, GrantStore
from security.tokens import TokenStore
from security.gate import SecurityGate, ToolRequest, ToolSpec
from security.permissions import PermissionLevel, PermissionPolicy
from security.confirmation import ConfirmationResponse


def _descriptor(**overrides):
    kwargs = dict(
        tool_name="fake.tool",
        capability="fs.read",
        domain="fs",
        target={"path": "C:\\x"},
        parameters={"path": "C:\\x"},
        declared_risk=Risk.LOW,
        operation_id="op-fixed",
    )
    kwargs.update(overrides)
    return OperationDescriptor.create(**kwargs)


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


# ============================================================ Descriptor


def test_descriptor_is_frozen():
    d = _descriptor()
    with pytest.raises(Exception):
        d.tool_name = "other"


def test_descriptor_hash_deterministic():
    d1 = _descriptor()
    d2 = _descriptor()
    assert d1.descriptor_hash() == d2.descriptor_hash()


def test_descriptor_hash_changes_with_capability():
    d1 = _descriptor()
    d2 = dc_replace(d1, capability="fs.write")
    assert d1.descriptor_hash() != d2.descriptor_hash()


def test_descriptor_hash_changes_with_target():
    d1 = _descriptor(target={"path": "C:\\a"})
    d2 = _descriptor(target={"path": "C:\\b"})
    assert d1.descriptor_hash() != d2.descriptor_hash()


def test_descriptor_hash_changes_with_privilege():
    d1 = _descriptor(requested_privilege="standard")
    d2 = _descriptor(requested_privilege="elevated")
    assert d1.descriptor_hash() != d2.descriptor_hash()


def test_descriptor_operation_id_unique():
    d1 = OperationDescriptor.create(
        tool_name="t", capability="fs.read", domain="fs",
        target={}, parameters={}, declared_risk=Risk.LOW,
    )
    d2 = OperationDescriptor.create(
        tool_name="t", capability="fs.read", domain="fs",
        target={}, parameters={}, declared_risk=Risk.LOW,
    )
    assert d1.operation_id != d2.operation_id


def test_descriptor_origin_round_trip():
    for origin in Origin:
        d = _descriptor(originating_source=origin)
        assert d.origin == origin


def test_descriptor_invalid_origin_becomes_unknown():
    d = _descriptor(originating_source="garbage")
    assert d.origin == Origin.UNKNOWN


def test_descriptor_required_permission():
    assert _descriptor(capability="fs.read").required_permission == Permission.READ
    assert _descriptor(capability="fs.write").required_permission == Permission.WRITE
    assert _descriptor(capability="fs.delete").required_permission == Permission.DELETE
    assert _descriptor(capability="shell.execute").required_permission == Permission.EXECUTE
    assert _descriptor(capability="shell.admin").required_permission == Permission.ADMIN


def test_permission_from_capability_unknown_is_none():
    assert permission_from_capability("something.odd") == Permission.NONE
    assert permission_from_capability("") == Permission.NONE


# ============================================================ Risk


def test_effective_risk_is_max():
    assert max(Risk.LOW, Risk.HIGH_RISK) == Risk.HIGH_RISK
    assert max(Risk.NORMAL, Risk.CONSEQUENTIAL) == Risk.CONSEQUENTIAL
    assert max(Risk.HIGH_RISK, Risk.HIGH_RISK) == Risk.HIGH_RISK


def test_tool_declared_risk_cannot_be_lowered_by_gate(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.highrisk",
        level=PermissionLevel.SAFE,
        path_params=[],
        description="test",
        declared_risk=Risk.HIGH_RISK,
    ))
    spy = _Spy()
    req = ToolRequest(
        "fake.highrisk", {},
        originating_source=Origin.DISCORD.value,
    )
    result = gate.execute(req, spy)
    assert result.denied
    assert len(spy.calls) == 0


def test_system_looking_escalates_risk(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.read",
        level=PermissionLevel.SAFE,
        path_params=["path"],
        description="test",
    ))
    spy = _Spy()
    req = ToolRequest(
        "fake.read", {"path": "C:\\Windows\\System32\\x"},
        originating_source=Origin.DISCORD.value,
    )
    result = gate.execute(req, spy)
    assert result.denied
    assert len(spy.calls) == 0


# ============================================================ Permission/grants


def test_read_grant_does_not_authorize_write():
    store = GrantStore()
    store.add(Grant(
        grant_id="g1", domain="fs", permission=Permission.READ,
        grant_type="persistent", max_risk=Risk.NORMAL,
    ))
    assert store.find_covering("fs", Permission.WRITE, Risk.NORMAL, "{}") is None


def test_write_grant_does_not_authorize_delete():
    store = GrantStore()
    store.add(Grant(
        grant_id="g1", domain="fs", permission=Permission.WRITE,
        grant_type="persistent", max_risk=Risk.CONSEQUENTIAL,
    ))
    assert store.find_covering("fs", Permission.DELETE,
                                Risk.CONSEQUENTIAL, "{}") is None


def test_normal_grant_cannot_authorize_high_risk():
    store = GrantStore()
    store.add(Grant(
        grant_id="g1", domain="fs", permission=Permission.DELETE,
        grant_type="persistent", max_risk=Risk.CONSEQUENTIAL,
    ))
    assert store.find_covering("fs", Permission.DELETE,
                                Risk.HIGH_RISK, "{}") is None


def test_persistent_grant_cannot_cover_high_risk_even_with_max_risk():
    store = GrantStore()
    store.add(Grant(
        grant_id="g1", domain="root", permission=Permission.EXECUTE,
        grant_type="persistent", max_risk=Risk.HIGH_RISK,
    ))
    assert store.find_covering("root", Permission.EXECUTE,
                                Risk.HIGH_RISK, "{}") is None


def test_per_operation_grant_covers_high_risk():
    store = GrantStore()
    store.add(Grant(
        grant_id="g1", domain="root", permission=Permission.EXECUTE,
        grant_type="per_operation", max_risk=Risk.HIGH_RISK,
    ))
    assert store.find_covering("root", Permission.EXECUTE,
                                Risk.HIGH_RISK, "{}") is not None


def test_domain_separation_adb_vs_fastboot():
    store = GrantStore()
    store.add(Grant(
        grant_id="g1", domain="adb", permission=Permission.EXECUTE,
        grant_type="per_operation", max_risk=Risk.HIGH_RISK,
    ))
    assert store.find_covering("fastboot", Permission.EXECUTE,
                                Risk.HIGH_RISK, "{}") is None


def test_domain_separation_shell_vs_fastboot():
    store = GrantStore()
    store.add(Grant(
        grant_id="g1", domain="shell", permission=Permission.EXECUTE,
        grant_type="per_operation", max_risk=Risk.HIGH_RISK,
    ))
    assert store.find_covering("fastboot", Permission.EXECUTE,
                                Risk.HIGH_RISK, "{}") is None


def test_domain_separation_adb_read_vs_adb_modify():
    store = GrantStore()
    store.add(Grant(
        grant_id="g1", domain="adb", permission=Permission.READ,
        grant_type="persistent", max_risk=Risk.CONSEQUENTIAL,
    ))
    assert store.find_covering("adb", Permission.WRITE, Risk.NORMAL, "{}") is None


def test_root_guide_does_not_grant_root_execute():
    store = GrantStore()
    store.add(Grant(
        grant_id="g1", domain="root", permission=Permission.READ,
        grant_type="persistent", max_risk=Risk.NORMAL,
    ))
    assert store.find_covering("root", Permission.EXECUTE,
                                Risk.HIGH_RISK, "{}") is None


# ============================================================ Tokens


def test_token_valid_once():
    store = TokenStore()
    d = _descriptor()
    tid = store.issue(d)
    ok, reason = store.consume(tid, d)
    assert ok and reason == ""
    ok2, reason2 = store.consume(tid, d)
    assert not ok2 and reason2 == "already_used"


def test_token_unknown():
    store = TokenStore()
    d = _descriptor()
    ok, reason = store.consume("nonexistent", d)
    assert not ok and reason == "unknown_token"


def test_token_malformed():
    store = TokenStore()
    d = _descriptor()
    ok, reason = store.consume("", d)
    assert not ok and reason == "malformed_token"


def test_token_expired():
    store = TokenStore(default_ttl_seconds=1)
    d = _descriptor()
    tid = store.issue(d)
    time.sleep(1.1)
    ok, reason = store.consume(tid, d)
    assert not ok and reason == "expired"


def test_token_operation_id_mismatch():
    store = TokenStore()
    d1 = _descriptor(operation_id="op-1")
    tid = store.issue(d1)
    d2 = _descriptor(operation_id="op-2")
    ok, reason = store.consume(tid, d2)
    assert not ok and reason == "operation_id_mismatch"


def test_token_descriptor_mismatch():
    store = TokenStore()
    d1 = _descriptor()
    tid = store.issue(d1)
    d2 = dc_replace(d1, capability="fs.write")
    ok, reason = store.consume(tid, d2)
    assert not ok and reason == "descriptor_mismatch"


def test_token_target_mismatch_denies():
    store = TokenStore()
    d1 = _descriptor(target={"path": "C:\\a"})
    tid = store.issue(d1)
    d2 = dc_replace(d1, target_json=json.dumps({"path": "C:\\b"}))
    ok, _ = store.consume(tid, d2)
    assert not ok


def test_token_privilege_mismatch_denies():
    store = TokenStore()
    d1 = _descriptor(requested_privilege="standard")
    tid = store.issue(d1)
    d2 = dc_replace(d1, requested_privilege="elevated")
    ok, _ = store.consume(tid, d2)
    assert not ok


def test_token_capability_mismatch_denies():
    store = TokenStore()
    d1 = _descriptor(capability="fs.read")
    tid = store.issue(d1)
    d2 = dc_replace(d1, capability="fs.write")
    ok, _ = store.consume(tid, d2)
    assert not ok


# ============================================================ Origin


@pytest.mark.parametrize("src", [
    Origin.DISCORD.value,
    Origin.WHATSAPP.value,
    Origin.WEB.value,
    Origin.FILE.value,
    Origin.API.value,
    Origin.UNKNOWN.value,
])
def test_external_origin_cannot_authorize_consequential(tmp_path, src):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="test",
    ))
    spy = _Spy()
    req = ToolRequest("fake.write", {}, originating_source=src)
    result = gate.execute(req, spy)
    assert result.denied, f"origin {src} must be denied"
    assert "external origin" in result.denial_reason.lower()
    assert len(spy.calls) == 0


def test_local_user_can_authorize_consequential_via_confirmation(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="test",
    ))
    gate.confirmation.set_handler(
        lambda req: ConfirmationResponse(approved=True, note="ok")
    )
    spy = _Spy()
    result = gate.execute(
        ToolRequest("fake.write", {},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert result.success
    assert len(spy.calls) == 1


def test_ai_internal_cannot_authorize_consequential(tmp_path):
    """With no confirmation handler installed, an AI_INTERNAL consequential
    request fails closed (denied by default-deny confirmation path)."""
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="test",
    ))
    spy = _Spy()
    req = ToolRequest("fake.write", {},
                      originating_source=Origin.AI_INTERNAL.value)
    result = gate.execute(req, spy)
    assert result.denied
    assert len(spy.calls) == 0


def test_external_origin_allows_low_risk_read(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.read",
        level=PermissionLevel.SAFE,
        path_params=[],
        description="test",
    ))
    spy = _Spy()
    req = ToolRequest("fake.read", {},
                      originating_source=Origin.DISCORD.value)
    result = gate.execute(req, spy)
    assert result.success
    assert len(spy.calls) == 1


# ============================================================ Gate integration


def test_gate_builds_descriptor_and_executes(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.read",
        level=PermissionLevel.SAFE,
        path_params=[],
        description="test",
    ))
    spy = _Spy()
    result = gate.execute(
        ToolRequest("fake.read", {},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    assert result.success
    assert len(spy.calls) == 1


def test_gate_executor_receives_copy_of_arguments(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.read",
        level=PermissionLevel.SAFE,
        path_params=[],
        description="test",
    ))
    seen = {}

    def spy(args):
        seen["received"] = dict(args)
        return {"ok": True}

    args = {"x": "1"}
    gate.execute(
        ToolRequest("fake.read", args,
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )
    args["x"] = "mutated"
    assert seen["received"]["x"] == "1"


def test_gate_denies_external_origin_for_system_looking(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.read",
        level=PermissionLevel.SAFE,
        path_params=["path"],
        description="test",
    ))
    spy = _Spy()
    req = ToolRequest(
        "fake.read", {"path": "C:\\Windows\\System32\\x"},
        originating_source=Origin.FILE.value,
    )
    result = gate.execute(req, spy)
    assert result.denied
    assert len(spy.calls) == 0