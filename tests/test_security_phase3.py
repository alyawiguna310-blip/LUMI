"""
Phase 3 regression tests.

Coverage:
  - Protocol framing, size limits, malformed input
  - Allowlist resolution and timeout clamping
  - Helper request verification (descriptor hash, claims, allowlist)
  - Gate elevated branch: success, denied, error, timeout, unknown
  - Token lifecycle on the elevated path (consume after, including on raise)
  - Non-Windows skip on pipe transport tests
  - No automatic retry on any failure outcome

Phase 4 update: the wire-format descriptor now includes `derived_from`
and `authorization_source`. Fixtures that build wire requests set them
explicitly so the tests exercise the field they intend to exercise,
not a missing-field rejection. This file does not weaken helper
validation; it aligns with the current descriptor schema.
"""
import io
import json
import os
import sys

import pytest

from security.confirmation import ConfirmationResponse
from security.descriptor import OperationDescriptor, Origin, Risk
from security.gate import SecurityGate, ToolRequest, ToolSpec
from security.permissions import PermissionLevel, PermissionPolicy
from security import privileged_ops
from security.privileged_protocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    encode_message,
    read_length_prefixed,
)


# =====================================================================
# helpers
# =====================================================================


def _make_elevated_spec(name="test.admin"):
    return ToolSpec(
        name=name,
        level=PermissionLevel.DESTRUCTIVE,
        path_params=[],
        description="test elevated",
        capability="shell.admin",
        domain="shell",
        requested_privilege="elevated",
    )


def _gate(tmp_path):
    return SecurityGate(
        protected_folder=str(tmp_path / "protected"),
        sandbox_enabled=False,
        policy=PermissionPolicy(auto_approve_max=PermissionLevel.NORMAL),
    )


def _approve(req):
    return ConfirmationResponse(approved=True, note="test-approve")


def _deny(req):
    return ConfirmationResponse(approved=False, note="test-deny")


def _stream_reader(data: bytes):
    """Return a position-advancing reader over `data`, matching the
    contract of read_length_prefixed's `reader(n) -> bytes` argument:
    successive calls consume bytes from the stream in order."""
    buf = io.BytesIO(data)
    return buf.read


# =====================================================================
# Protocol
# =====================================================================


def test_protocol_roundtrip():
    payload = {"a": 1, "b": "x", "nested": {"k": [1, 2, 3]}}
    data = encode_message(payload)
    # Length prefix is 4 bytes.
    assert len(data) > 4
    decoded = read_length_prefixed(
        _stream_reader(data), max_bytes=1024 * 1024,
    )
    assert decoded == payload


def test_protocol_rejects_oversized():
    big = {"x": "a" * (MAX_REQUEST_BYTES + 100)}
    with pytest.raises(ProtocolError):
        encode_message(big, max_bytes=MAX_REQUEST_BYTES)


def test_protocol_rejects_non_object():
    with pytest.raises(ProtocolError):
        encode_message(["not", "a", "dict"])  # type: ignore[arg-type]


def test_protocol_truncated_length_prefix():
    data = b"\x00\x00"
    with pytest.raises(ProtocolError):
        read_length_prefixed(_stream_reader(data), max_bytes=1024)


def test_protocol_declared_too_large():
    # Length says 10000, but max is 100.
    data = (10000).to_bytes(4, "big") + b"x" * 10000
    with pytest.raises(ProtocolError):
        read_length_prefixed(_stream_reader(data), max_bytes=100)


def test_protocol_malformed_json():
    payload = b"not json"
    data = len(payload).to_bytes(4, "big") + payload
    with pytest.raises(ProtocolError):
        read_length_prefixed(_stream_reader(data), max_bytes=1024)


def test_protocol_reader_position_advances():
    """Directly assert that the fixture's reader advances across calls,
    which is what the previous version of this suite failed to do."""
    data = b"AAAABBBBCCCC"
    reader = _stream_reader(data)
    assert reader(4) == b"AAAA"
    assert reader(4) == b"BBBB"
    assert reader(4) == b"CCCC"
    assert reader(4) == b""


# =====================================================================
# Allowlist resolution
# =====================================================================


def test_resolve_known_task():
    op = privileged_ops.resolve("flush_dns")
    assert op is not None
    assert op.steps[0][0][0] == "ipconfig"
    assert op.max_timeout_seconds <= privileged_ops.HARD_MAX_TIMEOUT_SECONDS


def test_resolve_unknown_task():
    assert privileged_ops.resolve("format_c_drive") is None
    assert privileged_ops.resolve("") is None
    assert privileged_ops.resolve(None) is None


def test_resolve_restart_service_allowlisted():
    op = privileged_ops.resolve("restart_service:spooler")
    assert op is not None
    assert len(op.steps) == 2
    assert op.steps[0][0][:2] == ("sc", "stop")
    assert op.steps[1][0][:2] == ("sc", "start")
    # No cmd.exe in the resolved argv.
    for argv, _delay in op.steps:
        assert "cmd" not in argv[0].lower()
        assert "/c" not in argv


def test_resolve_restart_service_not_allowlisted():
    assert privileged_ops.resolve("restart_service:winlogon") is None
    assert privileged_ops.resolve("restart_service:rpcss") is None
    assert privileged_ops.resolve("restart_service:") is None


def test_resolve_sfc_scan_has_high_timeout():
    op = privileged_ops.resolve("sfc_scan")
    assert op is not None
    assert op.max_timeout_seconds == 3600


def test_clamp_timeout_bounds():
    assert privileged_ops.clamp_timeout(10, 30) == 10
    assert privileged_ops.clamp_timeout(100, 30) == 30
    assert privileged_ops.clamp_timeout(1, 30) == privileged_ops.MIN_TIMEOUT_SECONDS
    assert privileged_ops.clamp_timeout("bad", 30) == 30
    assert privileged_ops.clamp_timeout(99999, 99999) == \
        privileged_ops.HARD_MAX_TIMEOUT_SECONDS


# =====================================================================
# Helper request verification
# =====================================================================


def _build_valid_request(task="flush_dns", timeout_s=30):
    """Build a wire request that satisfies the current descriptor schema.

    Phase 4 requires `derived_from` and `authorization_source` to be
    present as strings, and the helper requires
    `authorization_source == "local_user_confirmation"` for elevated
    operations. This fixture sets both, so each test exercises the
    field it intends to exercise rather than a missing-field rejection.
    """
    desc = OperationDescriptor.create(
        tool_name="terminal.run_admin",
        capability="shell.admin",
        domain="shell",
        target={},
        parameters={"task": task, "timeout_s": timeout_s},
        declared_risk=Risk.HIGH_RISK,
        requested_privilege="elevated",
        originating_source=Origin.LOCAL_USER.value,
        derived_from="",
        authorization_source="local_user_confirmation",
    )
    claims = {
        "operation_id": desc.operation_id,
        "descriptor_hash": desc.descriptor_hash(),
        "capability": desc.capability,
        "target_hash": desc.target_hash(),
        "requested_privilege": desc.requested_privilege,
    }
    return {
        "protocol_version": PROTOCOL_VERSION,
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


def test_verify_valid_request():
    from security.privileged_helper import _verify_request
    ok, reason, descriptor, parameters = _verify_request(
        _build_valid_request()
    )
    assert ok, reason
    assert descriptor.capability == "shell.admin"
    assert parameters["task"] == "flush_dns"


def test_verify_rejects_wrong_protocol_version():
    from security.privileged_helper import _verify_request
    req = _build_valid_request()
    req["protocol_version"] = 999
    ok, reason, *_ = _verify_request(req)
    assert not ok
    assert "protocol" in reason.lower()


def test_verify_rejects_hash_mismatch():
    from security.privileged_helper import _verify_request
    req = _build_valid_request()
    req["token_claims"]["descriptor_hash"] = "0" * 64
    ok, reason, *_ = _verify_request(req)
    assert not ok
    assert "hash" in reason.lower()


def test_verify_rejects_capability_mismatch():
    from security.privileged_helper import _verify_request
    req = _build_valid_request()
    req["token_claims"]["capability"] = "fs.write"
    ok, reason, *_ = _verify_request(req)
    assert not ok
    assert "capability" in reason.lower()


def test_verify_rejects_target_hash_mismatch():
    from security.privileged_helper import _verify_request
    req = _build_valid_request()
    req["token_claims"]["target_hash"] = "0" * 64
    ok, reason, *_ = _verify_request(req)
    assert not ok
    assert "target_hash" in reason.lower()


def test_verify_rejects_privilege_mismatch():
    from security.privileged_helper import _verify_request
    req = _build_valid_request()
    req["token_claims"]["requested_privilege"] = "standard"
    ok, reason, *_ = _verify_request(req)
    assert not ok


def test_verify_rejects_non_elevated_descriptor():
    from security.privileged_helper import _verify_request
    desc = OperationDescriptor.create(
        tool_name="terminal.run_admin",
        capability="shell.admin",
        domain="shell",
        target={},
        parameters={"task": "flush_dns"},
        declared_risk=Risk.HIGH_RISK,
        requested_privilege="standard",
        originating_source=Origin.LOCAL_USER.value,
        derived_from="",
        authorization_source="local_user_confirmation",
    )
    req = {
        "protocol_version": PROTOCOL_VERSION,
        "token_id": "x" * 16,
        "token_claims": {
            "operation_id": desc.operation_id,
            "descriptor_hash": desc.descriptor_hash(),
            "capability": desc.capability,
            "target_hash": desc.target_hash(),
            "requested_privilege": desc.requested_privilege,
        },
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
    ok, reason, *_ = _verify_request(req)
    assert not ok
    assert "elevated" in reason.lower()


def test_verify_rejects_unknown_capability():
    from security.privileged_helper import _verify_request
    desc = OperationDescriptor.create(
        tool_name="terminal.run_admin",
        capability="fs.write",
        domain="fs",
        target={},
        parameters={"task": "flush_dns"},
        declared_risk=Risk.HIGH_RISK,
        requested_privilege="elevated",
        originating_source=Origin.LOCAL_USER.value,
        derived_from="",
        authorization_source="local_user_confirmation",
    )
    req = {
        "protocol_version": PROTOCOL_VERSION,
        "token_id": "x" * 16,
        "token_claims": {
            "operation_id": desc.operation_id,
            "descriptor_hash": desc.descriptor_hash(),
            "capability": desc.capability,
            "target_hash": desc.target_hash(),
            "requested_privilege": desc.requested_privilege,
        },
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
    ok, reason, *_ = _verify_request(req)
    assert not ok


def test_verify_rejects_unknown_task_through_handle(monkeypatch):
    """The helper's handler refuses tasks not in the allowlist."""
    from security import privileged_helper

    # Strip out the actual execution so no subprocess is spawned.
    monkeypatch.setattr(
        privileged_helper, "_execute_steps",
        lambda steps, t: {"outcome": "success"},
    )

    req = _build_valid_request(task="not_a_task")
    result = privileged_helper._handle(req)
    assert result["outcome"] == "denied"
    assert "allowlist" in result["reason"].lower()


def test_handle_executes_allowlisted_task(monkeypatch):
    from security import privileged_helper

    seen = {}
    def fake_exec(steps, t):
        seen["steps"] = steps
        seen["timeout"] = t
        return {"outcome": "success", "exit_code": 0,
                "stdout": "ok", "stderr": ""}
    monkeypatch.setattr(privileged_helper, "_execute_steps", fake_exec)

    req = _build_valid_request(task="flush_dns", timeout_s=15)
    result = privileged_helper._handle(req)
    assert result["outcome"] == "success"
    assert seen["steps"][0][0][0] == "ipconfig"
    assert seen["timeout"] == 15


def test_handle_clamps_timeout(monkeypatch):
    from security import privileged_helper

    seen = {}
    def fake_exec(steps, t):
        seen["timeout"] = t
        return {"outcome": "success"}
    monkeypatch.setattr(privileged_helper, "_execute_steps", fake_exec)

    # sfc_scan has max 3600; request 99999 -> clamp to 3600.
    req = _build_valid_request(task="sfc_scan", timeout_s=99999)
    result = privileged_helper._handle(req)
    assert result["outcome"] == "success"
    assert seen["timeout"] == 3600


# =====================================================================
# Gate elevated branch
# =====================================================================


def test_gate_elevated_success_consumes_token(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_make_elevated_spec())
    gate.confirmation.set_handler(_approve)

    captured = {}
    def elevated(frozen_args, descriptor, token_id, claims):
        captured["token_id"] = token_id
        captured["claims"] = claims
        captured["descriptor"] = descriptor
        return {"outcome": "success", "stdout": "hi", "exit_code": 0,
                "operation_id": descriptor.operation_id}

    result = gate.execute(
        ToolRequest("test.admin", {"task": "flush_dns", "timeout_s": 30},
                    originating_source=Origin.LOCAL_USER.value),
        executor=lambda a: {"never": True},
        elevated_executor=elevated,
    )
    assert result.success is True
    assert captured["token_id"]
    # Token has been consumed.
    assert gate.tokens.is_used(captured["token_id"]) is True
    # Claims cross-verify against the descriptor.
    d = captured["descriptor"]
    assert captured["claims"]["descriptor_hash"] == d.descriptor_hash()
    assert captured["claims"]["capability"] == d.capability
    assert captured["claims"]["requested_privilege"] == "elevated"


def test_gate_elevated_denied_still_consumes_token(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_make_elevated_spec())
    gate.confirmation.set_handler(_approve)

    captured = {}
    def elevated(frozen_args, descriptor, token_id, claims):
        captured["token_id"] = token_id
        return {"outcome": "denied", "reason": "test-denied",
                "operation_id": descriptor.operation_id}

    result = gate.execute(
        ToolRequest("test.admin", {"task": "flush_dns"},
                    originating_source=Origin.LOCAL_USER.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.denied is True
    assert gate.tokens.is_used(captured["token_id"]) is True


def test_gate_elevated_error_outcome(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_make_elevated_spec())
    gate.confirmation.set_handler(_approve)

    def elevated(frozen_args, descriptor, token_id, claims):
        return {"outcome": "error", "reason": "boom",
                "operation_id": descriptor.operation_id}

    result = gate.execute(
        ToolRequest("test.admin", {"task": "flush_dns"},
                    originating_source=Origin.LOCAL_USER.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.success is False
    assert not result.denied
    assert "boom" in result.error


def test_gate_elevated_timeout_outcome(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_make_elevated_spec())
    gate.confirmation.set_handler(_approve)

    def elevated(frozen_args, descriptor, token_id, claims):
        return {"outcome": "timeout", "reason": "too slow",
                "operation_id": descriptor.operation_id}

    result = gate.execute(
        ToolRequest("test.admin", {"task": "flush_dns"},
                    originating_source=Origin.LOCAL_USER.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.success is False
    assert result.output["outcome"] == "timeout"


def test_gate_elevated_unknown_outcome_no_retry(tmp_path):
    """A single invocation, one call to the elevated executor, no retry."""
    gate = _gate(tmp_path)
    gate.register_tool(_make_elevated_spec())
    gate.confirmation.set_handler(_approve)

    calls = []
    def elevated(frozen_args, descriptor, token_id, claims):
        calls.append(1)
        return {"outcome": "unknown", "reason": "state undetermined",
                "operation_id": descriptor.operation_id}

    result = gate.execute(
        ToolRequest("test.admin", {"task": "flush_dns"},
                    originating_source=Origin.LOCAL_USER.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.success is False
    assert result.output["outcome"] == "unknown"
    assert len(calls) == 1  # exactly one helper invocation


def test_gate_elevated_exception_consumes_token(tmp_path):
    gate = _gate(tmp_path)
    gate.register_tool(_make_elevated_spec())
    gate.confirmation.set_handler(_approve)

    captured = {}
    def elevated(frozen_args, descriptor, token_id, claims):
        captured["token_id"] = token_id
        raise RuntimeError("simulated helper failure")

    result = gate.execute(
        ToolRequest("test.admin", {"task": "flush_dns"},
                    originating_source=Origin.LOCAL_USER.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.success is False
    assert "simulated helper failure" in result.error
    assert gate.tokens.is_used(captured["token_id"]) is True


def test_gate_elevated_confirmation_denied_no_helper(tmp_path):
    """If the user denies confirmation, the elevated executor must never
    be called."""
    gate = _gate(tmp_path)
    gate.register_tool(_make_elevated_spec())
    gate.confirmation.set_handler(_deny)

    called = []
    def elevated(frozen_args, descriptor, token_id, claims):
        called.append(1)
        return {"outcome": "success"}

    result = gate.execute(
        ToolRequest("test.admin", {"task": "flush_dns"},
                    originating_source=Origin.LOCAL_USER.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.denied is True
    assert len(called) == 0


def test_gate_elevated_external_origin_denied(tmp_path):
    """An external origin cannot reach the elevated helper."""
    gate = _gate(tmp_path)
    gate.register_tool(_make_elevated_spec())
    gate.confirmation.set_handler(_approve)

    called = []
    def elevated(frozen_args, descriptor, token_id, claims):
        called.append(1)
        return {"outcome": "success"}

    result = gate.execute(
        ToolRequest("test.admin", {"task": "flush_dns"},
                    originating_source=Origin.DISCORD.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.denied is True
    assert len(called) == 0


def test_gate_elevated_force_cannot_bypass(tmp_path):
    """Phase 2 /force rules remain in force for elevated tools."""
    gate = _gate(tmp_path)
    gate.register_tool(_make_elevated_spec())
    gate.confirmation.enable_force(seconds=10, reason="test")

    handler_calls = []
    def handler(req):
        handler_calls.append(req)
        return ConfirmationResponse(approved=False, note="denied")

    gate.confirmation.set_handler(handler)

    called = []
    def elevated(frozen_args, descriptor, token_id, claims):
        called.append(1)
        return {"outcome": "success"}

    result = gate.execute(
        ToolRequest("test.admin", {"task": "flush_dns"},
                    originating_source=Origin.LOCAL_USER.value),
        executor=lambda a: None,
        elevated_executor=elevated,
    )
    assert result.denied is True
    assert len(handler_calls) == 1
    assert handler_calls[0].forceable is False
    assert len(called) == 0


def test_gate_standard_path_unchanged_by_phase3(tmp_path):
    """Standard path still consumes the token before execution."""
    gate = _gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="test.standard",
        level=PermissionLevel.SAFE,
        path_params=[],
        description="standard",
    ))

    spy_calls = []
    def spy(args):
        spy_calls.append(args)
        return {"ok": True}

    result = gate.execute(
        ToolRequest("test.standard", {},
                    originating_source=Origin.LOCAL_USER.value),
        executor=spy,
    )
    assert result.success
    assert len(spy_calls) == 1


# =====================================================================
# Pipe transport (Windows-only, guarded)
# =====================================================================


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
def test_pipe_name_validation():
    from security.privileged_pipe import _validate_pipe_name
    assert _validate_pipe_name("abc_123-XYZ")
    with pytest.raises(ValueError):
        _validate_pipe_name("has space")
    with pytest.raises(ValueError):
        _validate_pipe_name("with\\slash")
    with pytest.raises(ValueError):
        _validate_pipe_name("")
    with pytest.raises(ValueError):
        _validate_pipe_name("x" * 300)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
def test_pipe_roundtrip_roundtrip():
    """Same-process server + client exchange one message."""
    import threading
    import time
    from security.privileged_pipe import PipeServer, PipeClient

    name = "lumi_priv_test_" + os.urandom(8).hex()
    server = PipeServer(name)
    result = {}

    def server_side():
        try:
            result["response"] = server.exchange_blocking(
                {"hello": "world"},
                max_response_bytes=1024,
                response_timeout_s=5.0,
            )
        except Exception as e:
            result["error"] = e

    t = threading.Thread(target=server_side, daemon=True)
    t.start()

    time.sleep(0.1)
    try:
        client = PipeClient.connect(name, timeout_s=5.0)
        try:
            client.write_message({"echo": "ping"}, max_bytes=1024)
            reply = client.read_message(max_bytes=1024, timeout_s=5.0)
            assert reply == {"hello": "world"}
        finally:
            client.close()
    finally:
        t.join(timeout=10.0)
        server.close()

    assert "error" not in result