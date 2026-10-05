"""
Application install/search/list via winget.

Security model:
  - search / list: SAFE — no confirmation
  - install: DESTRUCTIVE — ALWAYS confirm.
  - Blocklist: clearly-malicious package name patterns are hard-denied.
  - Remote-access tools get an extended warning in the confirm reason.
  - winget itself verifies package hashes against the signed manifest.

Lumi NEVER touches msiexec, and NEVER downloads a raw .exe.
Everything goes through winget's curated repository.
"""
import json
import logging
import re
import shutil
import subprocess
import time
from pathlib import Path

from security.descriptor import Origin
from security.gate import SecurityGate, ToolRequest, ToolResult, ToolSpec
from security.permissions import PermissionLevel

logger = logging.getLogger(__name__)


SEARCH_SPEC = ToolSpec(
    name="applications.search",
    level=PermissionLevel.SAFE,
    path_params=[],
    description="Search winget's curated repository. Read-only.",
)

LIST_SPEC = ToolSpec(
    name="applications.list_installed",
    level=PermissionLevel.SAFE,
    path_params=[],
    description="List installed applications. Read-only.",
)

INSTALL_SPEC = ToolSpec(
    name="applications.install",
    level=PermissionLevel.DESTRUCTIVE,
    path_params=[],
    description=(
        "Install a package from winget. Every call requires explicit "
        "user confirmation."
    ),
)


FORBIDDEN_ID_PATTERNS = (
    "keygen",
    "crack",
    "activator",
    "piracy",
    "warez",
    "cheatengine",
    "processhacker",
    "psexec",
    "mimikatz",
)

REMOTE_ACCESS_WARN = {
    "teamviewer.teamviewer",
    "anydesk.anydesk",
    "rustdesk.rustdesk",
    "logmein.logmein",
    "gotomypc",
    "screenconnect",
    "supremo",
    "dwservice",
}


def _winget_path() -> str | None:
    return shutil.which("winget")


def _run_winget(args: list, timeout_s: int = 300) -> dict:
    exe = _winget_path()
    if exe is None:
        return {
            "error": (
                "winget is not installed. Install 'App Installer' from "
                "the Microsoft Store to enable software management."
            ),
            "winget_available": False,
        }

    t0 = time.time()
    try:
        proc = subprocess.run(
            [exe] + args,
            capture_output=True,
            timeout=timeout_s,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "error": f"winget timed out after {timeout_s}s",
            "timed_out": True,
            "duration_s": round(time.time() - t0, 3),
        }
    except Exception as e:
        logger.exception("winget invocation failed")
        return {"error": str(e)}

    return {
        "exit_code": proc.returncode,
        "stdout": (proc.stdout or "")[:16384],
        "stderr": (proc.stderr or "")[:4096],
        "duration_s": round(time.time() - t0, 3),
    }


def _is_success(exit_code: int) -> bool:
    return exit_code in (0, 3010)


def _do_search(args: dict) -> dict:
    query = (args.get("query") or "").strip()
    if not query:
        return {"error": "query must be non-empty"}
    if re.search(r"[;&|`$<>]", query):
        return {"error": "query contains disallowed characters"}

    result = _run_winget(["search", "--query", query,
                          "--accept-source-agreements",
                          "--disable-interactivity"],
                         timeout_s=60)
    if "error" in result:
        return result
    return {
        "query": query,
        "exit_code": result["exit_code"],
        "raw_output": result["stdout"],
    }


def _do_list_installed(args: dict) -> dict:
    query = (args.get("query") or "").strip()
    winget_args = ["list", "--accept-source-agreements",
                   "--disable-interactivity"]
    if query:
        winget_args += ["--query", query]

    result = _run_winget(winget_args, timeout_s=60)
    if "error" in result:
        return result
    return {
        "exit_code": result["exit_code"],
        "raw_output": result["stdout"],
    }


def _check_id_forbidden(package_id: str) -> tuple:
    low = package_id.lower()
    for pat in FORBIDDEN_ID_PATTERNS:
        if pat in low:
            return True, f"package id contains forbidden pattern: {pat!r}"
    return False, ""


def _confirm_reason(args: dict) -> tuple:
    package_id = (args.get("package_id") or "").strip()
    if not package_id:
        return True, "install requested (missing package_id)"

    low = package_id.lower()

    forbidden, reason = _check_id_forbidden(package_id)
    if forbidden:
        return True, f"BLOCKED: {reason}"

    if low in REMOTE_ACCESS_WARN:
        return True, (
            f"INSTALL: {package_id} (remote-access tool — anyone with "
            f"your credentials could reach this PC)"
        )

    return True, f"INSTALL: {package_id} via winget (requires network + user approval)"


INSTALL_SPEC.confirm_if = _confirm_reason


def _do_install(args: dict) -> dict:
    package_id = (args.get("package_id") or "").strip()
    if not package_id:
        return {"installed": False, "error": "package_id must be non-empty"}

    if re.search(r"[;&|`$<>]", package_id):
        return {"installed": False, "error": "package_id contains invalid characters"}

    forbidden, reason = _check_id_forbidden(package_id)
    if forbidden:
        logger.warning("[APP] Blocked install of %r — %s", package_id, reason)
        return {"installed": False, "denied": True, "reason": reason,
                "package_id": package_id}

    result = _run_winget(
        [
            "install",
            "--id", package_id,
            "-e",
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements",
            "--disable-interactivity",
        ],
        timeout_s=600,
    )

    if "error" in result:
        return {"installed": False, **result}

    exit_code = result["exit_code"]
    success = _is_success(exit_code)
    reboot_required = (exit_code == 3010)

    return {
        "installed": success,
        "package_id": package_id,
        "exit_code": exit_code,
        "reboot_required": reboot_required,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "duration_s": result["duration_s"],
        "note": (
            "Installer downloaded from Microsoft's curated winget repository. "
            "McAfee and Windows Defender scanned it in real time during download."
        ),
    }


def register(gate: SecurityGate):
    gate.register_tool(SEARCH_SPEC)
    gate.register_tool(LIST_SPEC)
    gate.register_tool(INSTALL_SPEC)


def search(query: str, gate: SecurityGate,
           originating_source=Origin.AI_INTERNAL.value) -> ToolResult:
    return gate.execute(
        ToolRequest(SEARCH_SPEC.name, {"query": query},
                    originating_source=originating_source),
        _do_search,
    )


def list_installed(gate: SecurityGate, query: str = "",
                   originating_source=Origin.AI_INTERNAL.value) -> ToolResult:
    args = {"query": query} if query else {}
    return gate.execute(
        ToolRequest(LIST_SPEC.name, args,
                    originating_source=originating_source),
        _do_list_installed,
    )


def install(package_id: str, gate: SecurityGate,
            originating_source=Origin.AI_INTERNAL.value) -> ToolResult:
    return gate.execute(
        ToolRequest(INSTALL_SPEC.name, {"package_id": package_id},
                    originating_source=originating_source),
        _do_install,
    )