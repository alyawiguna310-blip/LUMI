"""
Elevated privileged helper. One-shot per operation.

Usage:
    python -m security.privileged_helper --pipe <name>

Only `--pipe <name>` is accepted. No positional arguments, no other
flags. The helper never accepts arbitrary commands, executables,
service names, or argv. Operations are resolved exclusively from
tools/admin_tasks.py via security.privileged_ops.

Run as an elevated process. It exits when the single exchange ends.
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import time
from typing import Optional

logger = logging.getLogger("lumi.privileged_helper")


# ---------------------------------------------------------------- argv


def _parse_argv(argv: list) -> Optional[str]:
    if not isinstance(argv, list):
        return None
    pipe_name = None
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--pipe":
            if i + 1 >= len(argv):
                return None
            pipe_name = argv[i + 1]
            i += 2
            continue
        return None
    if pipe_name is None:
        return None
    if not isinstance(pipe_name, str):
        return None
    if not (1 <= len(pipe_name) <= 256):
        return None
    for ch in pipe_name:
        if not (ch.isalnum() or ch in "_-"):
            return None
    return pipe_name


# ---------------------------------------------------------------- verify


def _verify_request(request: dict):
    """Return (ok, reason, descriptor_or_None, parameters_or_None)."""
    from security.descriptor import (
        EXTERNAL_ORIGINS,
        OperationDescriptor,
    )

    if not isinstance(request, dict):
        return False, "request not an object", None, None
    if request.get("protocol_version") != 1:
        return False, "protocol version mismatch", None, None

    desc_dict = request.get("descriptor")
    claims = request.get("token_claims")
    token_id = request.get("token_id")

    if not isinstance(desc_dict, dict):
        return False, "descriptor missing or not an object", None, None
    if not isinstance(claims, dict):
        return False, "token_claims missing or not an object", None, None
    if not isinstance(token_id, str) or not token_id:
        return False, "token_id missing or not a string", None, None

    required = (
        "operation_id", "tool_name", "capability", "domain",
        "target_json", "parameters_json", "declared_risk",
        "requested_scope", "requested_privilege", "reversibility",
        "originating_source",
        # Phase 4: the wire message always carries these. If either is
        # missing, the reconstruction would silently use a default and
        # the resulting hash would not match the claims. Require them.
        "derived_from", "authorization_source",
    )
    for field in required:
        if field not in desc_dict:
            return False, f"descriptor missing field: {field}", None, None
        if not isinstance(desc_dict[field], str):
            return False, f"descriptor field not a string: {field}", None, None

    try:
        descriptor = OperationDescriptor(
            operation_id=desc_dict["operation_id"],
            tool_name=desc_dict["tool_name"],
            capability=desc_dict["capability"],
            domain=desc_dict["domain"],
            target_json=desc_dict["target_json"],
            parameters_json=desc_dict["parameters_json"],
            declared_risk=desc_dict["declared_risk"],
            requested_scope=desc_dict["requested_scope"],
            requested_privilege=desc_dict["requested_privilege"],
            reversibility=desc_dict["reversibility"],
            originating_source=desc_dict["originating_source"],
            derived_from=desc_dict["derived_from"],
            authorization_source=desc_dict["authorization_source"],
        )
    except Exception as e:
        return False, f"descriptor reconstruction failed: {e}", None, None

    # Independently recompute the descriptor hash and cross-check claims.
    if claims.get("descriptor_hash") != descriptor.descriptor_hash():
        return False, "descriptor_hash mismatch", None, None
    if claims.get("operation_id") != descriptor.operation_id:
        return False, "operation_id mismatch", None, None
    if claims.get("capability") != descriptor.capability:
        return False, "capability mismatch", None, None
    if claims.get("target_hash") != descriptor.target_hash():
        return False, "target_hash mismatch", None, None
    if claims.get("requested_privilege") != descriptor.requested_privilege:
        return False, "requested_privilege mismatch", None, None

    if descriptor.requested_privilege != "elevated":
        return False, "only elevated requests may reach the helper", None, None
    if descriptor.capability != "shell.admin":
        return False, "capability not allowed for helper", None, None
    if descriptor.domain != "shell":
        return False, "domain not allowed for helper", None, None

    # Phase 4 defense-in-depth: even if the gate were to forward an
    # elevated request that came from outside, the helper refuses.
    if descriptor.derived_from in EXTERNAL_ORIGINS:
        return False, "elevated operation cannot be externally derived", None, None
    if descriptor.authorization_source != "local_user_confirmation":
        return False, (
            "elevated operation requires local_user_confirmation"
        ), None, None

    try:
        parameters = json.loads(descriptor.parameters_json)
    except Exception as e:
        return False, f"parameters_json invalid: {e}", None, None
    if not isinstance(parameters, dict):
        return False, "parameters must be a JSON object", None, None

    return True, "", descriptor, parameters


# ---------------------------------------------------------------- execute


def _execute_steps(steps, max_timeout_s: int) -> dict:
    t_total = time.time()
    step_results = []
    overall_stdout = []
    overall_stderr = []
    last_exit_code = 0

    for argv_tuple, delay in steps:
        if delay > 0:
            time.sleep(delay)

        argv = list(argv_tuple)
        elapsed = time.time() - t_total
        remaining = max_timeout_s - elapsed
        if remaining <= 0:
            return {
                "outcome": "timeout",
                "reason": f"operation exceeded max timeout {max_timeout_s}s",
                "steps": step_results,
                "operation_id": "",
                "protocol_version": 1,
                "duration_s": round(time.time() - t_total, 3),
            }

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                timeout=min(remaining, max_timeout_s),
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
            stdout = (proc.stdout or "")[:65536]
            stderr = (proc.stderr or "")[:65536]
            step_results.append({
                "argv": argv,
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
            })
            overall_stdout.append(stdout)
            overall_stderr.append(stderr)
            last_exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            step_results.append({
                "argv": argv,
                "exit_code": -1,
                "stdout": "",
                "stderr": "timed out",
            })
            return {
                "outcome": "timeout",
                "reason": f"step timed out: {argv}",
                "steps": step_results,
                "operation_id": "",
                "protocol_version": 1,
                "duration_s": round(time.time() - t_total, 3),
            }
        except Exception as e:
            step_results.append({
                "argv": argv,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"launch error: {e}",
            })
            return {
                "outcome": "error",
                "reason": f"step launch error: {e}",
                "steps": step_results,
                "operation_id": "",
                "protocol_version": 1,
                "duration_s": round(time.time() - t_total, 3),
            }

    outcome = "success" if last_exit_code == 0 else "error"
    return {
        "outcome": outcome,
        "reason": "" if outcome == "success"
                  else f"last step exit_code={last_exit_code}",
        "exit_code": last_exit_code,
        "stdout": "\n".join(overall_stdout)[:65536],
        "stderr": "\n".join(overall_stderr)[:65536],
        "steps": step_results,
        "operation_id": "",
        "protocol_version": 1,
        "duration_s": round(time.time() - t_total, 3),
    }


def _handle(request: dict) -> dict:
    from security.privileged_ops import resolve, clamp_timeout

    op_id = ""
    if isinstance(request, dict):
        d = request.get("descriptor")
        if isinstance(d, dict) and isinstance(d.get("operation_id"), str):
            op_id = d["operation_id"]

    ok, reason, descriptor, parameters = _verify_request(request)
    if not ok:
        logger.warning("helper request rejected: %s", reason)
        return {
            "protocol_version": 1,
            "outcome": "denied",
            "reason": reason,
            "operation_id": op_id,
        }

    task_name = parameters.get("task")
    if not isinstance(task_name, str) or not task_name.strip():
        return {
            "protocol_version": 1,
            "outcome": "denied",
            "reason": "missing task parameter",
            "operation_id": descriptor.operation_id,
        }

    resolved = resolve(task_name.strip())
    if resolved is None:
        logger.warning("task not in allowlist: %r", task_name)
        return {
            "protocol_version": 1,
            "outcome": "denied",
            "reason": f"task not in allowlist: {task_name!r}",
            "operation_id": descriptor.operation_id,
        }

    requested = parameters.get("timeout_s", resolved.max_timeout_seconds)
    timeout_s = clamp_timeout(requested, resolved.max_timeout_seconds)

    logger.info(
        "executing task=%s timeout=%ds operation_id=%s",
        resolved.task_name, timeout_s, descriptor.operation_id,
    )

    result = _execute_steps(resolved.steps, timeout_s)
    result["operation_id"] = descriptor.operation_id
    result["task"] = resolved.task_name
    return result


# ---------------------------------------------------------------- main


def main(argv: list) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="[helper] %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    pipe_name = _parse_argv(argv)
    if pipe_name is None:
        logger.error("usage: python -m security.privileged_helper --pipe <name>")
        return 2

    try:
        from security.privileged_pipe import PipeClient
        from security.privileged_protocol import (
            MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
        )
    except Exception:
        logger.exception("cannot import transport modules")
        return 3

    try:
        client = PipeClient.connect(pipe_name, timeout_s=30.0)
    except Exception:
        logger.exception("cannot connect to pipe")
        return 4

    try:
        try:
            request = client.read_message(
                max_bytes=MAX_REQUEST_BYTES, timeout_s=60.0,
            )
        except Exception as e:
            logger.warning("cannot read request: %s", e)
            try:
                client.write_message(
                    {
                        "protocol_version": 1,
                        "outcome": "denied",
                        "reason": f"malformed or unreadable request: {e}",
                        "operation_id": "",
                    },
                    max_bytes=MAX_RESPONSE_BYTES,
                )
            except Exception:
                pass
            return 5

        try:
            response = _handle(request)
        except Exception as e:
            logger.exception("handler raised")
            op_id = ""
            if isinstance(request, dict):
                d = request.get("descriptor")
                if isinstance(d, dict) and isinstance(
                    d.get("operation_id"), str
                ):
                    op_id = d["operation_id"]
            response = {
                "protocol_version": 1,
                "outcome": "error",
                "reason": f"internal helper error: {e}",
                "operation_id": op_id,
            }

        try:
            client.write_message(response, max_bytes=MAX_RESPONSE_BYTES)
        except Exception as e:
            logger.warning("cannot write response: %s", e)
            return 6
    finally:
        try:
            client.close()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))