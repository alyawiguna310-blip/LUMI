"""
Main-process side of the privileged helper protocol.

Creates a restrictive named pipe, launches the helper via ShellExecuteW
with the `runas` verb (single UAC prompt), exchanges exactly one request
and one response, and returns a structured outcome dict.

Never raises. Returns a dict with at least {"outcome": ..., "reason": ...}
where outcome ∈ {success, denied, error, timeout, unknown}.
"""
from __future__ import annotations

import logging
import secrets
import sys
import threading
from typing import Optional

from security.descriptor import OperationDescriptor
from security.privileged_protocol import (
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_VERSION,
)

logger = logging.getLogger(__name__)

_PIPE_PREFIX = "lumi_priv_"


def _gen_pipe_name() -> str:
    return _PIPE_PREFIX + secrets.token_hex(16)


def _build_request(
    descriptor: OperationDescriptor,
    token_id: str,
    token_claims: dict,
) -> dict:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "token_id": token_id,
        "token_claims": {
            "operation_id": token_claims.get("operation_id", ""),
            "descriptor_hash": token_claims.get("descriptor_hash", ""),
            "capability": token_claims.get("capability", ""),
            "target_hash": token_claims.get("target_hash", ""),
            "requested_privilege":
                token_claims.get("requested_privilege", ""),
        },
        "descriptor": {
            "operation_id": descriptor.operation_id,
            "tool_name": descriptor.tool_name,
            "capability": descriptor.capability,
            "domain": descriptor.domain,
            "target_json": descriptor.target_json,
            "parameters_json": descriptor.parameters_json,
            "declared_risk": descriptor.declared_risk,
            "requested_scope": descriptor.requested_scope,
            "requested_privilege": descriptor.requested_privilege,
            "reversibility": descriptor.reversibility,
            "originating_source": descriptor.originating_source,
            # Phase 4: provenance and authorization-source fields. They
            # are part of the descriptor hash; sending them keeps the
            # helper's reconstruction consistent with the gate's.
            "derived_from": descriptor.derived_from,
            "authorization_source": descriptor.authorization_source,
        },
    }


def _launch_helper(
    *, helper_python: str, helper_cwd: str, pipe_name: str,
) -> Optional[str]:
    """Return None on success, or a reason string on failure."""
    import ctypes
    from ctypes import wintypes

    SW_HIDE = 0
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteW.argtypes = [
        wintypes.HWND, ctypes.c_wchar_p, ctypes.c_wchar_p,
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int,
    ]
    shell32.ShellExecuteW.restype = ctypes.c_void_p

    params = f"-m security.privileged_helper --pipe {pipe_name}"

    try:
        result = shell32.ShellExecuteW(
            None, "runas", helper_python, params, helper_cwd, SW_HIDE,
        )
    except Exception as e:
        return f"ShellExecuteW raised: {e}"

    inst = int(result or 0)
    if inst <= 32:
        if inst == 5:
            return "user dismissed the Windows UAC prompt"
        if inst == 2:
            return f"helper interpreter not found: {helper_python}"
        if inst == 31:
            return "ShellExecuteW: no association for 'runas' verb"
        return f"ShellExecuteW failed with code {inst}"
    return None


def invoke_privileged_helper(
    *,
    descriptor: OperationDescriptor,
    token_id: str,
    token_claims: dict,
    connect_timeout_s: int,
    response_timeout_s: int,
    helper_python: str,
    helper_cwd: str,
) -> dict:
    if sys.platform != "win32":
        return {
            "outcome": "error",
            "reason": "privileged helper is Windows-only",
            "operation_id": descriptor.operation_id,
        }

    try:
        from security.privileged_pipe import PipeServer
    except Exception as e:
        return {
            "outcome": "error",
            "reason": f"pipe module unavailable: {e}",
            "operation_id": descriptor.operation_id,
        }

    pipe_name = _gen_pipe_name()
    try:
        server = PipeServer(pipe_name)
    except Exception as e:
        logger.exception("failed to create pipe")
        return {
            "outcome": "error",
            "reason": f"pipe create failed: {e}",
            "operation_id": descriptor.operation_id,
        }

    try:
        launch_err = _launch_helper(
            helper_python=helper_python,
            helper_cwd=helper_cwd,
            pipe_name=pipe_name,
        )
        if launch_err is not None:
            return {
                "outcome": "denied",
                "reason": launch_err,
                "operation_id": descriptor.operation_id,
            }

        request = _build_request(descriptor, token_id, token_claims)

        total_budget = (
            float(connect_timeout_s) + float(response_timeout_s) + 10.0
        )
        result_holder: dict = {}

        def worker():
            try:
                result_holder["response"] = server.exchange_blocking(
                    request,
                    max_response_bytes=MAX_RESPONSE_BYTES,
                    response_timeout_s=float(response_timeout_s),
                )
            except Exception as e:
                result_holder["error"] = e

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=total_budget)

        if t.is_alive():
            return {
                "outcome": "unknown",
                "reason": (
                    f"helper did not complete within {total_budget:.0f}s "
                    f"(connect={connect_timeout_s}s, "
                    f"response={response_timeout_s}s)"
                ),
                "operation_id": descriptor.operation_id,
            }

        if "error" in result_holder:
            err = result_holder["error"]
            return {
                "outcome": "error",
                "reason": f"pipe exchange failed: {err}",
                "operation_id": descriptor.operation_id,
            }

        response = result_holder.get("response", {})
        if not isinstance(response, dict):
            return {
                "outcome": "unknown",
                "reason": "helper returned a non-object response",
                "operation_id": descriptor.operation_id,
            }

        outcome = response.get("outcome")
        if outcome not in ("success", "denied", "error", "timeout", "unknown"):
            return {
                "outcome": "unknown",
                "reason": f"invalid helper outcome: {outcome!r}",
                "operation_id": descriptor.operation_id,
            }

        if response.get("operation_id") != descriptor.operation_id:
            return {
                "outcome": "unknown",
                "reason": "helper response operation_id mismatch",
                "operation_id": descriptor.operation_id,
            }

        return response
    finally:
        try:
            server.close()
        except Exception:
            pass