"""
Central dispatcher for LLM tool calls.

Routes every call through the SecurityGate. The gate is the sole authority.
Originating source is AI_INTERNAL: the AI can propose operations but cannot
authorize them; authorization happens via confirmation (LOCAL_USER) or a
matching grant.

Elevated tools route through a separate elevated executor provided by the
tool module. The gate decides which executor to use based on the tool's
declared `requested_privilege`.
"""
import logging
from typing import Any, Callable

from ai.tool_schema import parse_tool_call
from security.descriptor import Origin
from security.gate import SecurityGate, ToolRequest, ToolResult
from tools import applications, diagnostics, filesystem, terminal

logger = logging.getLogger(__name__)


class ToolRouter:
    def __init__(self, gate: SecurityGate):
        self.gate = gate
        self._executors: dict[str, Callable[[dict], Any]] = {
            "filesystem.list_dir":   filesystem._do_list_dir,
            "filesystem.read":       filesystem._do_read,
            "filesystem.write":      filesystem._do_write,
            "filesystem.create_dir": filesystem._do_create_dir,
            "filesystem.rename":     filesystem._do_rename,
            "filesystem.move":       filesystem._do_move,
            "filesystem.delete":     filesystem._do_delete,
            "terminal.run":          terminal._do_run,
            "terminal.run_admin":    terminal._do_run_admin_elevated,
            "applications.search":         applications._do_search,
            "applications.list_installed": applications._do_list_installed,
            "applications.launch":          applications._do_launch,
            "applications.install":        applications._do_install,\n            "diagnostics.read_log":          diagnostics._do_read_log,\n            "diagnostics.python_check":        diagnostics._do_python_check,
        }
        self._elevated_executors: dict[str, Callable] = {
            "terminal.run_admin": terminal._do_run_admin_elevated,
        }

    def route(self, name: str, args: dict) -> dict:
        ok, err, cleaned = parse_tool_call(name, args)
        if not ok:
            logger.warning("Tool call rejected: %s — %s", name, err)
            return {"ok": False, "status": "invalid", "tool": name, "error": err}

        executor = self._executors.get(name)
        if executor is None:
            logger.warning("No executor for tool: %s", name)
            return {"ok": False, "status": "unknown_tool", "tool": name,
                    "error": f"unknown tool: {name}"}

        elevated_executor = self._elevated_executors.get(name)

        try:
            result: ToolResult = self.gate.execute(
                ToolRequest(
                    tool_name=name,
                    arguments=cleaned,
                    originating_source=Origin.AI_INTERNAL.value,
                ),
                executor=executor,
                elevated_executor=elevated_executor,
            )
        except Exception as e:
            logger.exception("Gate raised for %s", name)
            return {"ok": False, "status": "error", "tool": name, "error": str(e)}

        if result.denied:
            return {
                "ok": False, "status": "denied", "tool": name,
                "reason": result.denial_reason,
                "confirmation_needed": bool(result.confirmation_needed),
            }
        if not result.success:
            return {"ok": False, "status": "error", "tool": name,
                    "error": result.error or "unknown error",
                    "output": result.output}

        output = result.output
        if isinstance(output, dict) and output.get("denied"):
            return {"ok": False, "status": "denied", "tool": name,
                    "reason": output.get("reason", "denied by executor")}

        return {"ok": True, "status": "ok", "tool": name, "output": output}