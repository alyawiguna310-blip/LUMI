"""
Phase 4 regression tests: external input isolation.

The tests exercise the actual gate path where possible. Executors,
elevated executors, and confirmation handlers are spies; no subprocess
is spawned, no privileged operation runs.
"""
import copy
import json

import pytest

from security.confirmation import ConfirmationResponse
from security.descriptor import (
    EXTERNAL_ORIGINS,
    OperationDescriptor,
    Origin,
    Risk,
)
from security.gate import SecurityGate, ToolRequest, ToolSpec
from security.permissions import PermissionLevel, PermissionPolicy


# =====================================================================
# helpers
# =====================================================================


class _Spy:
    def __init__(self, return_value=None):
        self.calls = []
        self._return = return_value if return_value is not None else {"ok": True}

    def __call__(self, args):
        self.calls.append(copy.deepcopy(args))
        return dict(self._return)


def _gate(tmp_path, grants=None):
    return SecurityGate(
        protected_folder=str(tmp_path / "protected"),
        sandbox_enabled=False,
        policy=PermissionPolicy(auto_approve_max=PermissionLevel.NORMAL),
        grants=grants,
    )


def _approve(req):
    return ConfirmationResponse(approved=True, note="p4-approve")


def _deny(req):
    return ConfirmationResponse(approved=False, note="p4-deny")


def _spec_read(name="p4.read"):
    return ToolSpec(
        name=name, level=PermissionLevel.SAFE,
        path_params=[], description="read",
    )


def _spec_write(name="p4.write"):
    return ToolSpec(
        name=name, level=PermissionLevel.DISRUPTIVE,
        path_params=[], description="write",
    )


def _spec_high(name="p4.high"):
    return ToolSpec(
        name=name, level=PermissionLevel.DESTRUCTIVE,
        path_params=[], description="high",
    )


def _spec_elevated(name="p4.elevated"):
    return ToolSpec(
        name=name, level=PermissionLevel.DESTRUCTIVE,
        path_params=[], description="elevated",
        capability="shell.admin", domain="shell",
        requested_privilege="elevated",
    )


# =====================================================================
# P4-01 / P4-02 / P4-14 / P4-15 — origin identity and preservation
# =====================================================================


def test_p4_01_derived_from_preserved_in_descriptor(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_read())
    gate.confirmation.set_handler(_deny)

    seen = {}
    def spy_exec(args):
        return {"ok": True}
    # Capture the descriptor via the token store's issue().
    real_issue = gate.tokens.issue
    def spy_issue(desc):
        seen["descriptor"] = desc
        return real_issue(desc)
    gate.tokens.issue = spy_issue

    gate.execute(
        ToolRequest("p4.read", {},
                    originating_source=Origin.AI_INTERNAL.value,
                    derived_from=Origin.DISCORD.value),
        spy_exec,
    )
    assert seen["descriptor"].derived_from == Origin.DISCORD.value
    assert seen["descriptor"].originating_source == Origin.AI_INTERNAL.value


def test_p4_02_ai_internal_is_not_local_user():
    assert Origin.AI_INTERNAL.value != Origin.LOCAL_USER.value
    assert Origin.AI_INTERNAL.value not in EXTERNAL_ORIGINS
    assert Origin.LOCAL_USER.value not in EXTERNAL_ORIGINS


def test_p4_14_ai_internal_cannot_manufacture_local_user(tmp_path):
    """An AI_INTERNAL request cannot auto-approve a HIGH_RISK operation
    without confirmation."""
    gate = _gate(tmp_path)
    gate.register_tool(_spec_high())
    # No confirmation handler — default deny.
    spy = _Spy()
    result = gate.execute(
        ToolRequest("p4.high", {},
                    originating_source=Origin.AI_INTERNAL.value),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_p4_15_origin_survives_descriptor_creation(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_read())
    seen = {}
    real_issue = gate.tokens.issue
    def spy_issue(desc):
        seen["descriptor"] = desc
        return real_issue(desc)
    gate.tokens.issue = spy_issue

    gate.execute(
        ToolRequest("p4.read", {},
                    originating_source=Origin.FILE.value),
        _Spy(),
    )
    assert seen["descriptor"].originating_source == Origin.FILE.value


# =====================================================================
# P4-03 / P4-04 — read-only external operations permitted
# =====================================================================


def test_p4_03_discord_origin_low_risk_read_allowed(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_read())
    spy = _Spy()
    result = gate.execute(
        ToolRequest("p4.read", {},
                    originating_source=Origin.DISCORD.value),
        spy,
    )
    assert result.success
    assert len(spy.calls) == 1


def test_p4_04_whatsapp_origin_low_risk_read_allowed(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_read())
    spy = _Spy()
    result = gate.execute(
        ToolRequest("p4.read", {},
                    originating_source=Origin.WHATSAPP.value),
        spy,
    )
    assert result.success
    assert len(spy.calls) == 1


# =====================================================================
# P4-05 / P4-06 / P4-07 — external consequential denied
# =====================================================================


@pytest.mark.parametrize("origin", sorted(EXTERNAL_ORIGINS))
def test_p4_05_external_consequential_denied(tmp_path, origin):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_write())
    gate.confirmation.set_handler(_approve)  # even with approval
    spy = _Spy()
    result = gate.execute(
        ToolRequest("p4.write", {}, originating_source=origin),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0
    assert "external origin" in result.denial_reason.lower()


@pytest.mark.parametrize("origin", sorted(EXTERNAL_ORIGINS))
def test_p4_07_external_high_risk_denied(tmp_path, origin):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_high())
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        ToolRequest("p4.high", {}, originating_source=origin),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


# =====================================================================
# P4-08 / P4-09 / P4-10 — external cannot reach confirmation/token/helper
# =====================================================================


def test_p4_08_external_cannot_reach_confirmation(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_write())
    handler_calls = []
    def handler(req):
        handler_calls.append(req)
        return ConfirmationResponse(approved=True)
    gate.confirmation.set_handler(handler)

    result = gate.execute(
        ToolRequest("p4.write", {},
                    originating_source=Origin.DISCORD.value),
        _Spy(),
    )
    assert result.denied is True
    assert len(handler_calls) == 0


def test_p4_09_external_cannot_receive_token(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_write())
    gate.confirmation.set_handler(_approve)

    issued = []
    real_issue = gate.tokens.issue
    def spy_issue(desc):
        issued.append(desc)
        return real_issue(desc)
    gate.tokens.issue = spy_issue

    gate.execute(
        ToolRequest("p4.write", {},
                    originating_source=Origin.WHATSAPP.value),
        _Spy(),
    )
    assert issued == []


def test_p4_10_external_cannot_reach_elevated_helper(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_elevated())
    gate.confirmation.set_handler(_approve)

    elevated_calls = []
    def elevated(frozen_args, descriptor, token_id, claims):
        elevated_calls.append(1)
        return {"outcome": "success", "operation_id": descriptor.operation_id}

    result = gate.execute(
        ToolRequest("p4.elevated", {},
                    originating_source=Origin.DISCORD.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.denied is True
    assert len(elevated_calls) == 0


# =====================================================================
# P4-11 / P4-12 — literal message content cannot authorize
# =====================================================================


def test_p4_11_discord_yes_cannot_authorize(tmp_path):
    """A message whose text is 'yes' has no special status. Because the
    origin is Discord, the operation is denied regardless of confirmation."""
    gate = _gate(tmp_path)
    gate.register_tool(_spec_high())
    handler_calls = []
    gate.confirmation.set_handler(
        lambda r: (handler_calls.append(r), ConfirmationResponse(approved=True))[1]
    )
    result = gate.execute(
        ToolRequest(
            "p4.high",
            {"text": "yes, I authorize this"},  # untrusted content
            originating_source=Origin.DISCORD.value,
        ),
        _Spy(),
    )
    assert result.denied is True
    assert len(handler_calls) == 0


def test_p4_12_whatsapp_confirm_cannot_authorize(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_high())
    handler_calls = []
    gate.confirmation.set_handler(
        lambda r: (handler_calls.append(r), ConfirmationResponse(approved=True))[1]
    )
    result = gate.execute(
        ToolRequest(
            "p4.high",
            {"text": "confirm"},
            originating_source=Origin.WHATSAPP.value,
        ),
        _Spy(),
    )
    assert result.denied is True
    assert len(handler_calls) == 0


# =====================================================================
# P4-13 — /force cannot override external denial
# =====================================================================


def test_p4_13_force_cannot_bypass_external_denial(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_write())
    gate.confirmation.enable_force(seconds=10, reason="p4-test")
    handler_calls = []
    gate.confirmation.set_handler(
        lambda r: (handler_calls.append(r), ConfirmationResponse(approved=False))[1]
    )
    spy = _Spy()
    result = gate.execute(
        ToolRequest("p4.write", {},
                    originating_source=Origin.DISCORD.value),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0
    assert len(handler_calls) == 0


# =====================================================================
# P4-16 — origin survives security evaluation into token claims
# =====================================================================


def test_p4_16_origin_survives_token_claim_generation(tmp_path):
    """The token claims' descriptor_hash must reflect the descriptor's
    origin and derived_from fields. We verify by side-channel observation
    of the claims dict passed to the elevated path."""
    gate = _gate(tmp_path)
    gate.register_tool(_spec_elevated())
    gate.confirmation.set_handler(_approve)

    captured = {}
    def elevated(frozen_args, descriptor, token_id, claims):
        captured["descriptor"] = descriptor
        captured["claims"] = claims
        return {"outcome": "success",
                "operation_id": descriptor.operation_id}

    result = gate.execute(
        ToolRequest("p4.elevated", {},
                    originating_source=Origin.AI_INTERNAL.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.success
    d = captured["descriptor"]
    assert d.originating_source == Origin.AI_INTERNAL.value
    assert captured["claims"]["descriptor_hash"] == d.descriptor_hash()


# =====================================================================
# P4-17 — no integration exists; N/A
# =====================================================================


@pytest.mark.skip(reason="No Discord/WhatsApp integration exists in the repo")
def test_p4_17_readonly_integration_no_logout():
    """Placeholder. Until an integration is added, there is nothing to
    audit for logout/revocation side effects. When an integration lands,
    this test must be replaced with concrete assertions on that
    integration's read path."""
    pass


# =====================================================================
# P4-18 — Phase 3 elevated path remains functional
# =====================================================================


def test_p4_18_elevated_path_still_works_for_ai_internal(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_elevated())
    gate.confirmation.set_handler(_approve)

    captured = {}
    def elevated(frozen_args, descriptor, token_id, claims):
        captured["token_id"] = token_id
        captured["descriptor"] = descriptor
        return {"outcome": "success", "stdout": "ok",
                "operation_id": descriptor.operation_id}

    result = gate.execute(
        ToolRequest("p4.elevated", {"task": "flush_dns"},
                    originating_source=Origin.AI_INTERNAL.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.success
    assert captured["descriptor"].authorization_source == \
        "local_user_confirmation"
    # Token was consumed after helper returned
    assert gate.tokens.is_used(captured["token_id"]) is True


def test_p4_18b_elevated_path_consumes_token_on_error(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_elevated())
    gate.confirmation.set_handler(_approve)

    captured = {}
    def elevated(frozen_args, descriptor, token_id, claims):
        captured["token_id"] = token_id
        return {"outcome": "error", "reason": "boom",
                "operation_id": descriptor.operation_id}

    gate.execute(
        ToolRequest("p4.elevated", {"task": "flush_dns"},
                    originating_source=Origin.AI_INTERNAL.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert gate.tokens.is_used(captured["token_id"]) is True


# =====================================================================
# derived_from new-path tests
# =====================================================================


@pytest.mark.parametrize("origin", sorted(EXTERNAL_ORIGINS))
def test_p4_21_derived_from_external_denies_consequential(
    tmp_path, origin
):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_write())
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        ToolRequest("p4.write", {},
                    originating_source=Origin.AI_INTERNAL.value,
                    derived_from=origin),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0
    assert "externally-derived content" in result.denial_reason.lower()


def test_p4_22_derived_from_unknown_denies_consequential(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_high())
    gate.confirmation.set_handler(_approve)
    spy = _Spy()
    result = gate.execute(
        ToolRequest("p4.high", {},
                    originating_source=Origin.AI_INTERNAL.value,
                    derived_from=Origin.UNKNOWN.value),
        spy,
    )
    assert result.denied is True
    assert len(spy.calls) == 0


def test_p4_23_derived_from_unknown_allows_low_risk(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_read())
    spy = _Spy()
    result = gate.execute(
        ToolRequest("p4.read", {},
                    originating_source=Origin.AI_INTERNAL.value,
                    derived_from=Origin.UNKNOWN.value),
        spy,
    )
    assert result.success
    assert len(spy.calls) == 1


def test_p4_24_derived_from_empty_ai_internal_reaches_confirmation(tmp_path):
    """An AI_INTERNAL request with no external derivation is treated as
    an ordinary AI proposal: CONSEQUENTIAL requires confirmation."""
    gate = _gate(tmp_path)
    gate.register_tool(_spec_write())
    calls = []
    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=True)
    gate.confirmation.set_handler(handler)
    spy = _Spy()
    result = gate.execute(
        ToolRequest("p4.write", {},
                    originating_source=Origin.AI_INTERNAL.value,
                    derived_from=""),
        spy,
    )
    assert result.success
    assert len(calls) == 1
    assert len(spy.calls) == 1


# =====================================================================
# authorization_source lifecycle
# =====================================================================


def test_p4_25_authorization_source_transitions_after_confirmation(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_elevated())
    gate.confirmation.set_handler(_approve)

    captured = {}
    def elevated(frozen_args, descriptor, token_id, claims):
        captured["descriptor"] = descriptor
        return {"outcome": "success",
                "operation_id": descriptor.operation_id}

    gate.execute(
        ToolRequest("p4.elevated", {"task": "flush_dns"},
                    originating_source=Origin.AI_INTERNAL.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert captured["descriptor"].authorization_source == \
        "local_user_confirmation"


def test_p4_26_authorization_source_remains_none_when_no_confirmation(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_spec_read())

    captured = {}
    real_issue = gate.tokens.issue
    def spy_issue(desc):
        captured["descriptor"] = desc
        return real_issue(desc)
    gate.tokens.issue = spy_issue

    gate.execute(
        ToolRequest("p4.read", {},
                    originating_source=Origin.AI_INTERNAL.value),
        _Spy(),
    )
    assert captured["descriptor"].authorization_source == "none"


def test_p4_27_authorization_source_included_in_hash(tmp_path):
    d1 = OperationDescriptor.create(
        tool_name="t", capability="fs.read", domain="fs",
        target={}, parameters={}, declared_risk=Risk.LOW,
        authorization_source="none",
    )
    d2 = OperationDescriptor.create(
        tool_name="t", capability="fs.read", domain="fs",
        target={}, parameters={}, declared_risk=Risk.LOW,
        authorization_source="local_user_confirmation",
    )
    assert d1.descriptor_hash() != d2.descriptor_hash()


def test_p4_28_derived_from_included_in_hash(tmp_path):
    d1 = OperationDescriptor.create(
        tool_name="t", capability="fs.read", domain="fs",
        target={}, parameters={}, declared_risk=Risk.LOW,
        derived_from="",
    )
    d2 = OperationDescriptor.create(
        tool_name="t", capability="fs.read", domain="fs",
        target={}, parameters={}, declared_risk=Risk.LOW,
        derived_from=Origin.DISCORD.value,
    )
    assert d1.descriptor_hash() != d2.descriptor_hash()


def test_p4_29_descriptor_is_still_frozen():
    d = OperationDescriptor.create(
        tool_name="t", capability="fs.read", domain="fs",
        target={}, parameters={}, declared_risk=Risk.LOW,
    )
    with pytest.raises(Exception):
        d.authorization_source = "local_user_confirmation"


def test_p4_30_with_authorization_creates_new_immutable_descriptor():
    d = OperationDescriptor.create(
        tool_name="t", capability="fs.read", domain="fs",
        target={}, parameters={}, declared_risk=Risk.LOW,
    )
    d2 = d.with_authorization("local_user_confirmation")
    assert d.authorization_source == "none"
    assert d2.authorization_source == "local_user_confirmation"
    assert d.operation_id == d2.operation_id
    assert d.descriptor_hash() != d2.descriptor_hash()


def test_p4_31_invalid_authorization_source_rejected():
    with pytest.raises(ValueError):
        OperationDescriptor.create(
            tool_name="t", capability="fs.read", domain="fs",
            target={}, parameters={}, declared_risk=Risk.LOW,
            authorization_source="totally_made_up",
        )


def test_p4_32_invalid_derived_from_rejected():
    with pytest.raises(ValueError):
        OperationDescriptor.create(
            tool_name="t", capability="fs.read", domain="fs",
            target={}, parameters={}, declared_risk=Risk.LOW,
            derived_from="not_an_origin",
        )


# =====================================================================
# Helper defense-in-depth
# =====================================================================


def _make_wire_request(
    *, derived_from="", authorization_source="local_user_confirmation",
    privilege="elevated", capability="shell.admin", domain="shell",
    task="flush_dns",
):
    desc = OperationDescriptor.create(
        tool_name="terminal.run_admin",
        capability=capability,
        domain=domain,
        target={},
        parameters={"task": task, "timeout_s": 30},
        declared_risk=Risk.HIGH_RISK,
        requested_privilege=privilege,
        originating_source=Origin.LOCAL_USER.value,
        derived_from=derived_from,
        authorization_source=authorization_source,
    )
    claims = {
        "operation_id": desc.operation_id,
        "descriptor_hash": desc.descriptor_hash(),
        "capability": desc.capability,
        "target_hash": desc.target_hash(),
        "requested_privilege": desc.requested_privilege,
    }
    return {
        "protocol_version": 1,
        "token_id": "deadbeef" * 4,
        "token_claims": claims,
        "descriptor": {
            "operation_id": desc.operation_id,
            "tool_name": desc.tool_name,
            "capability": desc.capability,
            "domain": desc.domain,
            "target_json": desc.target_json,
            "parameters_json": desc.parameters_json,
            "declared_risk": desc.declared_risk,
            "requested_scope": desc.requested_scope,
            "requested_privilege": desc.requested_privilege,
            "reversibility": desc.reversibility,
            "originating_source": desc.originating_source,
            "derived_from": desc.derived_from,
            "authorization_source": desc.authorization_source,
        },
    }


def test_p4_33_helper_rejects_external_derived_elevated():
    from security.privileged_helper import _verify_request
    req = _make_wire_request(derived_from=Origin.DISCORD.value)
    ok, reason, *_ = _verify_request(req)
    assert not ok
    assert "externally derived" in reason.lower()


def test_p4_34_helper_rejects_none_authorization_for_elevated():
    from security.privileged_helper import _verify_request
    req = _make_wire_request(authorization_source="none")
    ok, reason, *_ = _verify_request(req)
    assert not ok
    assert "local_user_confirmation" in reason.lower()


def test_p4_35_helper_accepts_valid_ai_internal_authorized_request():
    from security.privileged_helper import _verify_request
    req = _make_wire_request()
    ok, reason, descriptor, params = _verify_request(req)
    assert ok, reason
    assert descriptor.authorization_source == "local_user_confirmation"


# =====================================================================
# ToolRouter does not manufacture LOCAL_USER
# =====================================================================


def test_p4_36_toolrouter_uses_ai_internal_never_local_user(tmp_path):
    """Confirm the router's origin choice by exercising the public
    constructor indirectly: a ToolRequest created by the router has
    originating_source == AI_INTERNAL. We assert by inspecting the
    gate's recorded descriptor via the token store spy, using the actual
    ToolRouter to route a SAFE tool."""
    from core.tool_router import ToolRouter
    from tools import filesystem as fs

    gate = SecurityGate(
        protected_folder=str(tmp_path / "protected"),
        sandbox_enabled=False,
    )
    fs.register(gate)

    captured = {}
    real_issue = gate.tokens.issue
    def spy_issue(desc):
        captured["descriptor"] = desc
        return real_issue(desc)
    gate.tokens.issue = spy_issue

    router = ToolRouter(gate)
    # Bypass the real filesystem by swapping the executor.
    router._executors["filesystem.list_dir"] = lambda args: {"entries": []}

    result = router.route("filesystem.list_dir", {"path": str(tmp_path)})
    assert result["ok"] is True
    assert captured["descriptor"].originating_source == \
        Origin.AI_INTERNAL.value
    assert captured["descriptor"].derived_from == ""