"""
Terminal tools.

  - terminal.run        - normal-user command execution (allowlisted)
  - terminal.run_admin  - curated admin task, elevated via a constrained
                          privileged helper (Phase 3).

Every run goes through TerminalGuard (kill switch + rate limit) and is
logged to ~/.lumi/logs/terminal.log.
"""
import ctypes
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from core.events import bus
from security.descriptor import Origin
from security.gate import SecurityGate, ToolRequest, ToolResult, ToolSpec
from security.permissions import PermissionLevel
from storage import terminal_log
from tools import admin_tasks
from tools.terminal_guard import guard

logger = logging.getLogger(__name__)


# ------------------------------------------------------------ specs

TERMINAL_SPEC = ToolSpec(
    name="terminal.run",
    level=PermissionLevel.NORMAL,
    path_params=["cwd"],
    description=(
        "Run an allowlisted command. Read-only commands auto-approve; "
        "scripts, package installs, file modifications, and ALL "
        "ADB/fastboot commands require confirmation."
    ),
)

ADMIN_TERMINAL_SPEC = ToolSpec(
    name="terminal.run_admin",
    level=PermissionLevel.DESTRUCTIVE,
    path_params=[],
    description=(
        "Run a curated admin task elevated via a constrained privileged "
        "helper. The helper accepts only named tasks from admin_tasks.py."
    ),
    capability="shell.admin",
    domain="shell",
    requested_privilege="elevated",
)


# ------------------------------------------------------------ allowlists

_READONLY_TOOLS = {
    "dir", "type", "echo", "cd", "where", "ver", "whoami", "hostname",
    "date", "time", "tree", "more", "findstr", "sort",
    "tasklist", "systeminfo", "ipconfig",
    "ls", "cat", "pwd", "grep", "head", "tail", "wc", "find", "which",
    "printf", "env", "uname",
}

_DEV_TOOLS = {
    "python", "python3", "py", "pip", "pip3",
    "node", "npm", "npx", "yarn", "pnpm",
    "cargo", "rustc", "go", "dotnet",
    "java", "javac", "mvn", "gradle",
    "make", "cmake", "ninja",
    "git", "pytest", "uv", "poetry", "pipenv",
    "ffmpeg", "ffprobe",
}

_FILE_MOD_TOOLS = {
    "copy", "xcopy", "robocopy", "move", "ren", "rename",
    "del", "erase", "mkdir", "md", "rmdir", "rd",
    "attrib", "mklink", "icacls", "takeown", "compact",
    "cp", "mv", "rm", "touch", "ln",
    "chmod", "chown", "install", "tee", "sed", "awk", "truncate",
}

_ADB_TOOLS = {"adb", "fastboot"}

SAFE_EXECUTABLES = (
    _READONLY_TOOLS | _DEV_TOOLS | _FILE_MOD_TOOLS | _ADB_TOOLS
)

# NOTE: DENY_ARG_PATTERNS is a *heuristic*, not a security boundary.
# See SECURITY.md section "DENY_ARG_PATTERNS".
DENY_ARG_PATTERNS = (
    "--no-preserve-root", "if=/dev/zero", "if=/dev/random",
    "\\\\.\\physicaldrive", "//./physicaldrive",
    "format ", "diskpart", "fdisk", "mkfs",
    "shutdown", "logoff",
    "del /f /s /q c:\\", "del /f /s /q d:\\", "del /f /s /q e:\\",
    "del /f /s /q f:\\",
    "rd /s /q c:\\", "rd /s /q d:\\", "rd /s /q e:\\", "rd /s /q f:\\",
    "rmdir /s /q c:\\", "rmdir /s /q d:\\",
    "rm -rf /", "rm -rf /*",
    "reg delete hklm", "reg add hklm\\sam", "reg add hklm\\security",
    "reg add hklm\\system", "reg save hklm",
    "sc create", "sc delete", "schtasks /create", "schtasks /delete",
    "net user", "net localgroup",
    "ncat -l", "nc -l", "ssh-keygen",
    "set-mppreference", "disableantivirus", "disable-realtimemonitoring",
    "-encodedcommand", "-enc ", "-nop -w hidden",
    "certutil -urlcache", "bitsadmin /transfer",
    "runas", "sudo ", "gsudo",
    "start-process -verb runas", "start-process -verbrunas", "-verb runas",
    "psexec", "elevate.exe", "wmic process call create",
    "sc.exe start", "new-service",
    "--index-url", "--extra-index-url", "--trusted-host", "--find-links",
    "adb shell su", "adb root", "adb remount", "adb disable-verity",
)

SCRIPT_EXTENSIONS = {
    ".py", ".pyw", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".sh", ".bash", ".exe", ".com", ".scr",
}

_DESTRUCTIVE_FOR_ROOT = {
    "del", "erase", "rmdir", "rd", "rm", "rmtree", "format",
    "diskpart", "mkfs", "dd",
}
_DRIVE_ROOT_PATTERNS = (
    "c:\\", "d:\\", "e:\\", "f:\\", "g:\\", "h:\\", "i:\\", "j:\\",
    "\\\\.\\", "//./",
)

MAX_STDOUT = 8192
MAX_STDERR = 8192


# ------------------------------------------------------------ interpreters

_INTERPRETER_SHORT_DANGER = {
    "python":  frozenset({"c", "m"}),
    "python3": frozenset({"c", "m"}),
    "py":      frozenset({"c", "m"}),
    "node":    frozenset({"e", "p", "r"}),
    "nodejs":  frozenset({"e", "p", "r"}),
}

_INTERPRETER_LONG_DANGER = {
    "node":   frozenset({"--eval", "--print", "--require"}),
    "nodejs": frozenset({"--eval", "--print", "--require"}),
}

_INTERPRETER_VALUE_TAKERS = {
    "python":  frozenset({"w", "x"}),
    "python3": frozenset({"w", "x"}),
    "py":      frozenset({"w", "x"}),
}

_INLINE_CODE_FLAGS = {"-c", "-e", "-p", "--eval", "--print"}


def _interpreter_risky(argv: list) -> tuple:
    if not argv or not isinstance(argv[0], str):
        return False, ""
    exe = os.path.basename(argv[0]).lower()
    if exe.endswith(".exe"):
        exe = exe[:-4]

    short_danger = _INTERPRETER_SHORT_DANGER.get(exe)
    if short_danger is None:
        return False, ""
    long_danger = _INTERPRETER_LONG_DANGER.get(exe, frozenset())
    value_takers = _INTERPRETER_VALUE_TAKERS.get(exe, frozenset())

    i = 1
    first_positional_seen = False
    while i < len(argv):
        tok = argv[i]
        if not isinstance(tok, str):
            i += 1
            continue
        if tok == "-":
            return True, "interpreter reading program from stdin ('-')"
        if tok == "--":
            break
        if tok.startswith("--"):
            head = tok.split("=", 1)[0].lower()
            if head in long_danger:
                return True, f"interpreter inline flag {tok!r}"
            i += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            for ch in tok[1:]:
                if ch.lower() in short_danger:
                    return True, f"interpreter inline flag {tok!r}"
            if len(tok) == 2 and tok[1].lower() in value_takers:
                i += 2
            else:
                i += 1
            continue
        if not first_positional_seen:
            first_positional_seen = True
            clean = tok.strip('"').strip("'")
            ext = os.path.splitext(clean)[1].lower()
            if ext not in SCRIPT_EXTENSIONS:
                return True, (
                    f"interpreter invoked with extension-less script {tok!r}"
                )
        i += 1

    return False, ""


# ------------------------------------------------------------ path helpers

_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]|^\\\\|^/")


def _looks_like_path(tok: str) -> bool:
    if not tok or tok.startswith("-"):
        return False
    if _PATH_RE.match(tok):
        return True
    if ("/" in tok or "\\" in tok) and len(tok) > 1:
        if "://" in tok:
            return False
        return True
    return False


def _extract_paths(argv: list) -> list:
    out = []
    skip_next = False
    for i, tok in enumerate(argv):
        if i == 0:
            continue
        if not isinstance(tok, str):
            skip_next = False
            continue
        if skip_next:
            skip_next = False
            continue
        t = tok.strip('"').strip("'")
        if t in _INLINE_CODE_FLAGS:
            skip_next = True
            continue
        if _looks_like_path(t):
            out.append(t)
    return out


def _validate_paths_against_gate(paths: list) -> dict | None:
    try:
        from config import config
    except Exception as e:
        logger.error("[TERMINAL] config import failed; denying: %s", e)
        return {"denied": True, "reason": f"config import failed: {e}"}

    try:
        from security.protected_paths import is_inside_protected
        from security.sandbox import check_sandbox
    except Exception as e:
        logger.error("[TERMINAL] security module import failed: %s", e)
        return {"denied": True,
                "reason": f"security module import failed: {e}"}

    for raw in paths:
        try:
            check = is_inside_protected(raw, config.PROTECTED_FOLDER)
        except Exception as e:
            logger.error("[TERMINAL] protected check raised on %r: %s", raw, e)
            return {"denied": True,
                    "reason": f"protected-path check error: {e}",
                    "path": raw}
        if not check.allowed:
            logger.warning("[TERMINAL] Path blocked (protected): %r - %s",
                           raw, check.reason)
            return {"denied": True,
                    "reason": f"protected path: {check.reason}",
                    "path": raw}

        try:
            check = check_sandbox(
                raw, config.SANDBOX_ROOT, config.SANDBOX_ENABLED
            )
        except Exception as e:
            logger.error("[TERMINAL] sandbox check raised on %r: %s", raw, e)
            return {"denied": True,
                    "reason": f"sandbox check error: {e}",
                    "path": raw}
        if not check.allowed:
            logger.warning("[TERMINAL] Path blocked (sandbox): %r - %s",
                           raw, check.reason)
            return {"denied": True,
                    "reason": f"outside sandbox: {check.reason}",
                    "path": raw}

    return None


# ------------------------------------------------------------ validators

def _validate_argv(argv) -> tuple:
    if not isinstance(argv, list) or not argv:
        return "deny", "command must be a non-empty list of strings"
    for token in argv:
        if not isinstance(token, str):
            return "deny", "all command tokens must be strings"

    exe_full = argv[0]
    exe_name = os.path.basename(exe_full).lower()
    if exe_name.endswith(".exe"):
        exe_name = exe_name[:-4]

    if exe_name not in SAFE_EXECUTABLES:
        return "deny", f"executable not in allowlist: {exe_name!r}"

    joined = " ".join(argv).lower()
    for pat in DENY_ARG_PATTERNS:
        if pat in joined:
            return "deny", f"argument contains forbidden pattern: {pat!r}"

    if exe_name in _DESTRUCTIVE_FOR_ROOT:
        for pat in _DRIVE_ROOT_PATTERNS:
            if pat in joined:
                return "deny", (
                    f"destructive command {exe_name!r} aimed at a drive root"
                )

    return "allow", ""


def _needs_confirm(args: dict) -> tuple:
    argv = args.get("command")
    if not isinstance(argv, list) or not argv:
        return False, ""

    for i, token in enumerate(argv):
        if i == 0 or not isinstance(token, str) or token.startswith("-"):
            continue
        ext = os.path.splitext(token.strip('"').strip("'"))[1].lower()
        if ext in SCRIPT_EXTENSIONS:
            return True, (
                f"runs script file {token!r} "
                f"(unknown scripts require explicit approval)"
            )

    toks = [t.strip('"').strip("'").lower() if isinstance(t, str) else ""
            for t in argv]
    exe = toks[0]
    if exe.endswith(".exe"):
        exe = exe[:-4]

    if exe == "adb":
        sub = toks[1] if len(toks) > 1 else ""
        return True, f"runs adb {sub} ({' '.join(argv)}) - needs your approval"
    if exe == "fastboot":
        return True, f"runs fastboot ({' '.join(argv)}) - needs your approval"

    if exe in _FILE_MOD_TOOLS:
        return True, f"modifies files with {exe!r} ({' '.join(argv)})"

    if exe in ("pip", "pip3"):
        if len(toks) > 1 and toks[1] in ("install", "uninstall", "download"):
            return True, f"installs/removes Python packages ({' '.join(argv)})"
    if exe in ("python", "python3", "py") and len(toks) >= 4 \
       and toks[1] == "-m" and toks[2] == "pip" \
       and toks[3] in ("install", "uninstall", "download"):
        return True, f"installs/removes Python packages ({' '.join(argv)})"

    if exe == "uv" and len(toks) > 2 and toks[1] in ("pip", "tool") \
       and toks[2] in ("install", "uninstall", "remove"):
        return True, f"installs packages via uv ({' '.join(argv)})"
    if exe == "poetry" and len(toks) > 1 and toks[1] in ("add", "remove"):
        return True, f"modifies Python deps via poetry ({' '.join(argv)})"
    if exe == "pipenv" and len(toks) > 1 and toks[1] in ("install", "uninstall"):
        return True, f"installs Python packages via pipenv ({' '.join(argv)})"

    if exe in ("npm", "pnpm", "yarn") and len(toks) > 1:
        verb = toks[1]
        if verb in ("install", "i", "add", "ci"):
            scope = " (global)" if ("-g" in toks or "--global" in toks) else ""
            return True, f"downloads Node packages{scope} ({' '.join(argv)})"
        if verb in ("uninstall", "remove"):
            return True, f"removes Node packages ({' '.join(argv)})"

    if exe == "cargo" and len(toks) > 1 and toks[1] == "install":
        return True, f"installs Rust crates ({' '.join(argv)})"
    if exe == "go" and len(toks) > 1 and toks[1] == "install":
        return True, f"installs Go packages ({' '.join(argv)})"

    if exe == "git" and len(toks) > 1 and toks[1] == "clone":
        return True, f"downloads code from a remote git repo ({' '.join(argv)})"

    risky, why = _interpreter_risky(argv)
    if risky:
        return True, why

    return False, ""


TERMINAL_SPEC.confirm_if = _needs_confirm


def _is_currently_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ------------------------------------------------------------ executor

def _do_run(args: dict) -> dict:
    argv = args.get("command")
    cwd = args.get("cwd") or os.getcwd()
    timeout_s = int(args.get("timeout_s", 30))
    timeout_s = max(1, min(timeout_s, 300))

    if not guard.enabled:
        msg = "terminal is currently DISABLED (tray: Terminal -> toggle)"
        logger.warning("[TERMINAL] %s", msg)
        terminal_log.log_denied(msg, argv)
        return {"denied": True, "reason": msg, "command": argv}

    if guard.paused:
        msg = "all tools are PAUSED (tray: Tools -> toggle)"
        logger.warning("[TERMINAL] %s", msg)
        terminal_log.log_denied(msg, argv)
        return {"denied": True, "reason": msg, "command": argv}

    ok, why = guard.check_rate()
    if not ok:
        msg = f"rate guard: {why}"
        logger.warning("[TERMINAL] %s", msg)
        terminal_log.log_denied(msg, argv)
        bus.emit("terminal.rate_warning", reason=why)
        return {"denied": True, "reason": msg, "command": argv}

    if _is_currently_elevated():
        msg = ("Lumi is running as administrator. Terminal commands are "
               "disabled when elevated.")
        terminal_log.log_denied(msg, argv)
        return {"denied": True, "reason": msg, "command": argv}

    action, reason = _validate_argv(argv)
    if action == "deny":
        logger.warning("[TERMINAL] Denied: %s - argv=%r", reason, argv)
        terminal_log.log_denied(reason, argv)
        return {"denied": True, "reason": reason, "command": argv}

    extracted = _extract_paths(argv)
    if extracted:
        denial = _validate_paths_against_gate(extracted)
        if denial is not None:
            terminal_log.log_denied(denial.get("reason", "denied"), argv)
            return denial

    cwd_path = Path(cwd)
    if not cwd_path.exists() or not cwd_path.is_dir():
        return {"error": f"invalid cwd: {cwd}", "command": argv}

    if not os.path.isabs(argv[0]):
        if shutil.which(argv[0]) is None:
            return {"error": f"executable not found: {argv[0]!r}",
                    "command": argv}

    guard.record_command()
    terminal_log.log_command_start(argv, cwd=cwd_path)
    bus.emit("terminal.command_started", argv=list(argv),
             cwd=str(cwd_path))

    t0 = time.time()
    try:
        proc = subprocess.run(
            argv, cwd=str(cwd_path),
            capture_output=True, timeout=timeout_s,
            text=True, encoding="utf-8", errors="replace",
            shell=False,
        )
        dur = time.time() - t0
        out = (proc.stdout or "")[:MAX_STDOUT]
        err = (proc.stderr or "")[:MAX_STDERR]

        terminal_log.log_command_end(proc.returncode, dur, out, err)
        bus.emit("terminal.command_finished",
                 argv=list(argv), exit_code=proc.returncode,
                 duration_s=round(dur, 3))

        return {
            "exit_code": proc.returncode,
            "stdout": out,
            "stderr": err,
            "truncated_stdout": len(proc.stdout or "") > MAX_STDOUT,
            "truncated_stderr": len(proc.stderr or "") > MAX_STDERR,
            "duration_s": round(dur, 3),
            "command": argv, "cwd": str(cwd_path),
        }

    except subprocess.TimeoutExpired:
        dur = time.time() - t0
        terminal_log.log_command_end(-1, dur, "", "timed out")
        bus.emit("terminal.command_finished",
                 argv=list(argv), exit_code=-1,
                 duration_s=round(dur, 3))
        return {"exit_code": -1, "stderr": f"timed out after {timeout_s}s",
                "timed_out": True, "command": argv}

    except Exception as e:
        logger.exception("terminal.run failed")
        terminal_log.log_command_end(-1, time.time() - t0, "", str(e))
        bus.emit("terminal.command_finished",
                 argv=list(argv), exit_code=-1,
                 duration_s=round(time.time() - t0, 3))
        return {"error": str(e), "command": argv}


# ------------------------------------------------------------ admin (helper)

def _needs_admin_confirm(args: dict) -> tuple:
    task = args.get("task")
    return True, f"ADMIN: {task!r} (requires UAC elevation via helper)"


ADMIN_TERMINAL_SPEC.confirm_if = _needs_admin_confirm


def _do_run_admin_elevated(
    frozen_args: dict,
    descriptor,
    token_id: str,
    token_claims: dict,
) -> dict:
    """Elevated path. Dispatch a single request to the privileged helper
    over a restrictive named pipe. Returns a structured dict with
    `outcome` ∈ {success, denied, error, timeout, unknown}."""
    from config import config

    if not getattr(config, "ADMIN_TERMINAL_ENABLED", False):
        return {
            "outcome": "denied",
            "reason": ("admin terminal is disabled in config "
                       "(set LUMI_ADMIN_TERMINAL_ENABLED=true to enable)"),
            "operation_id": descriptor.operation_id,
        }

    if _is_currently_elevated():
        return {
            "outcome": "denied",
            "reason": ("Lumi itself is running elevated; refusing to "
                       "launch elevated helper"),
            "operation_id": descriptor.operation_id,
        }

    try:
        from security.privileged_client import invoke_privileged_helper
    except Exception as e:
        return {
            "outcome": "error",
            "reason": f"privileged client unavailable: {e}",
            "operation_id": descriptor.operation_id,
        }

    helper_cwd = str(Path(__file__).resolve().parent.parent)
    helper_python = sys.executable

    return invoke_privileged_helper(
        descriptor=descriptor,
        token_id=token_id,
        token_claims=token_claims,
        connect_timeout_s=int(
            getattr(config, "HELPER_CONNECT_TIMEOUT_SECONDS", 120)
        ),
        response_timeout_s=int(
            getattr(config, "HELPER_RESPONSE_TIMEOUT_SECONDS", 3600)
        ),
        helper_python=helper_python,
        helper_cwd=helper_cwd,
    )


# ------------------------------------------------------------ public

def register(gate: SecurityGate):
    gate.register_tool(TERMINAL_SPEC)
    gate.register_tool(ADMIN_TERMINAL_SPEC)


def run(command, gate, cwd=None, timeout_s=30,
        originating_source=Origin.AI_INTERNAL.value):
    args = {"command": command, "timeout_s": timeout_s}
    if cwd is not None:
        args["cwd"] = cwd
    return gate.execute(
        ToolRequest(TERMINAL_SPEC.name, args,
                    originating_source=originating_source),
        _do_run)


def run_admin(task, gate, timeout_s=120, cwd=None,
              originating_source=Origin.AI_INTERNAL.value):
    args = {"task": task, "timeout_s": timeout_s}
    if cwd is not None:
        args["cwd"] = cwd
    return gate.execute(
        ToolRequest(ADMIN_TERMINAL_SPEC.name, args,
                    originating_source=originating_source),
        executor=_do_run_admin_elevated,
        elevated_executor=_do_run_admin_elevated,
    )