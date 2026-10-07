"""Application install/search/list/launch via winget and installed-app metadata.

Security model:
  - search / list: SAFE; launch: NORMAL; install: DESTRUCTIVE.
  - launch never accepts shell syntax or arbitrary command lines.
  - launch resolves an installed application by Windows metadata, known
    per-user locations, or PATH.
"""
import logging
import os
import re
import shutil
import subprocess
import time
import winreg
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

LAUNCH_SPEC = ToolSpec(
    name="applications.launch",
    level=PermissionLevel.NORMAL,
    path_params=[],
    description=(
        "Launch an already-installed desktop application by name. "
        "Use this directly when the user says open, run, start, or launch "
        "an installed app. No shell commands, scripts, URLs, or arbitrary "
        "command lines. The application must resolve to a known installed "
        "executable."
    ),
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
    "keygen", "crack", "activator", "piracy", "warez",
    "cheatengine", "processhacker", "psexec", "mimikatz",
)

REMOTE_ACCESS_WARN = {
    "teamviewer.teamviewer", "anydesk.anydesk", "rustdesk.rustdesk",
    "logmein.logmein", "gotomypc", "screenconnect", "supremo", "dwservice",
}

# Common friendly names -> executable names/locations. These are fixed
# application identities, not paths supplied by the model.
KNOWN_APP_ALIASES = {
    "lunar": "lunar_client",
    "lunarclient": "lunar_client",
    "lunarclientlauncher": "lunar_client",
    "roblox": "roblox",
    "robloxplayer": "roblox",
    "robloxplayerbeta": "roblox",
    "vscodium": "vscodium",
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
    if any(ch in query for ch in "&;|$<>"):
        return {"error": "query contains disallowed characters"}

    result = _run_winget(
        ["search", "--query", query, "--accept-source-agreements",
         "--disable-interactivity"],
        timeout_s=60,
    )
    if "error" in result:
        return result
    return {
        "query": query,
        "exit_code": result["exit_code"],
        "raw_output": result["stdout"],
    }

def _do_list_installed(args: dict) -> dict:
    query = (args.get("query") or "").strip()
    winget_args = [
        "list", "--accept-source-agreements", "--disable-interactivity"
    ]
    if query:
        winget_args += ["--query", query]

    result = _run_winget(winget_args, timeout_s=60)
    if "error" in result:
        return result
    return {"exit_code": result["exit_code"], "raw_output": result["stdout"]}

def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())

def _existing_executable(candidate: Path) -> str | None:
    try:
        if candidate.is_file() and candidate.suffix.lower() == ".exe":
            return str(candidate.resolve())
    except OSError:
        pass
    return None

def _registry_applications():
    subkey = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    views = (0, getattr(winreg, "KEY_WOW64_64KEY", 0),
             getattr(winreg, "KEY_WOW64_32KEY", 0))
    seen = set()

    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in views:
            try:
                with winreg.OpenKey(root, subkey, 0,
                                    winreg.KEY_READ | view) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            child = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, child) as item:
                                name = winreg.QueryValueEx(item, "DisplayName")[0]
                                try:
                                    location = winreg.QueryValueEx(
                                        item, "InstallLocation"
                                    )[0]
                                except OSError:
                                    location = ""
                                if isinstance(name, str):
                                    marker = (name, str(location or "").lower())
                                    if marker not in seen:
                                        seen.add(marker)
                                        yield name, str(location or "")
                        except OSError:
                            continue
            except OSError:
                continue

def _registry_app_paths() -> list[tuple[str, str]]:
    """Return executable paths registered through Windows App Paths."""
    subkey = r"Software\Microsoft\Windows\CurrentVersion\App Paths"
    views = (0, getattr(winreg, "KEY_WOW64_64KEY", 0),
             getattr(winreg, "KEY_WOW64_32KEY", 0))
    results = []
    seen = set()

    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in views:
            try:
                with winreg.OpenKey(root, subkey, 0,
                                    winreg.KEY_READ | view) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            child = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, child) as item:
                                value = winreg.QueryValueEx(item, "")[0]
                                if not isinstance(value, str):
                                    continue
                                exe = Path(value.strip('"'))
                                if exe.suffix.lower() != ".exe":
                                    continue
                                marker = (child.lower(), str(exe).lower())
                                if marker not in seen:
                                    seen.add(marker)
                                    results.append((child, str(exe)))
                        except OSError:
                            continue
            except OSError:
                continue
    return results

def _known_application_candidates(alias: str) -> list[Path]:
    """Return only fixed, per-user locations for known launchers."""
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    appdata = Path(os.environ.get("APPDATA", ""))
    candidates: list[Path] = []

    if alias == "lunar_client":
        candidates += [
            local / "Programs" / "lunarclient" / "Lunar Client.exe",
            local / "Programs" / "Lunar Client" / "Lunar Client.exe",
            local / "LunarClient" / "Lunar Client.exe",
        ]

    elif alias == "roblox":
        # Roblox changes the version directory on updates. Only inspect the
        # fixed Roblox Versions directory; never recurse through arbitrary
        # user directories.
        versions = local / "Roblox" / "Versions"
        try:
            dirs = [p for p in versions.iterdir() if p.is_dir()]
            dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            for directory in dirs[:12]:
                candidates.append(directory / "RobloxPlayerBeta.exe")
                candidates.append(directory / "RobloxPlayerLauncher.exe")
        except OSError:
            pass

    elif alias == "vscodium":
        candidates += [
            local / "Programs" / "VSCodium" / "VSCodium.exe",
            appdata / "VSCodium" / "VSCodium.exe",
        ]

    return candidates

def _resolve_installed_app(name: str) -> tuple[str | None, str | None]:
    query = name.strip()
    if not query:
        return None, "application name must be non-empty"
    if len(query) > 100 or any(
        ch in query for ch in "/:;&|$<>\r\n"
    ):
        return None, "application name contains disallowed characters"

    normalized = _norm(query)
    alias = KNOWN_APP_ALIASES.get(normalized)

    # 1. PATH is still the fastest and most generic safe resolver.
    for candidate in (query, query + ".exe"):
        found = shutil.which(candidate)
        if found and Path(found).is_file():
            return str(Path(found).resolve()), None

    # 2. Fixed known locations handle per-user launchers such as Lunar/Roblox.
    if alias:
        for candidate in _known_application_candidates(alias):
            found = _existing_executable(candidate)
            if found:
                return found, None

    # 3. Windows App Paths handles applications that don't expose an
    # InstallLocation but do register their executable.
    for display_name, executable in _registry_app_paths():
        stem = _norm(Path(display_name).stem)
        if stem == normalized or normalized in stem:
            found = _existing_executable(Path(executable))
            if found:
                return found, None

    # 4. Standard uninstall metadata, including both registry views.
    for display_name, location in _registry_applications():
        display_norm = _norm(display_name)
        if display_norm != normalized and normalized not in display_norm:
            continue
        if not location:
            continue
        root = Path(location)
        if not root.is_dir():
            continue

        candidates = [
            root / f"{query}.exe",
            root / f"{display_name}.exe",
        ]
        if alias == "vscodium":
            candidates += [root / "VSCodium.exe", root / "codium.exe"]

        for candidate in candidates:
            found = _existing_executable(candidate)
            if found:
                return found, None

    return None, f"installed application not found: {query!r}"

def _do_launch(args: dict) -> dict:
    name = (args.get("name") or "").strip()
    executable, error = _resolve_installed_app(name)
    if error:
        return {"launched": False, "error": error}

    try:
        proc = subprocess.Popen(
            [executable],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
        )
    except Exception as e:
        logger.exception("Failed to launch application %r", name)
        return {"launched": False, "error": str(e), "executable": executable}

    logger.info("[APP] Launched %r -> %s (pid=%s)", name, executable, proc.pid)
    return {
        "launched": True,
        "name": name,
        "executable": executable,
        "pid": proc.pid,
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
    if any(ch in package_id for ch in "&;|$<>"):
        return {"installed": False, "error": "package_id contains invalid characters"}

    forbidden, reason = _check_id_forbidden(package_id)
    if forbidden:
        logger.warning("Blocked install of %r — %s", package_id, reason)
        return {"installed": False, "denied": True, "reason": reason,
                "package_id": package_id}

    result = _run_winget(
        ["install", "--id", package_id, "-e", "--silent",
         "--accept-package-agreements", "--accept-source-agreements",
         "--disable-interactivity"],
        timeout_s=600,
    )
    if "error" in result:
        return {"installed": False, **result}

    exit_code = result["exit_code"]
    success = _is_success(exit_code)
    return {
        "installed": success,
        "package_id": package_id,
        "exit_code": exit_code,
        "reboot_required": exit_code == 3010,
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
    gate.register_tool(LAUNCH_SPEC)
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

def launch(name: str, gate: SecurityGate,
           originating_source=Origin.AI_INTERNAL.value) -> ToolResult:
    return gate.execute(
        ToolRequest(LAUNCH_SPEC.name, {"name": name},
                    originating_source=originating_source),
        _do_launch,
    )

def install(package_id: str, gate: SecurityGate,
            originating_source=Origin.AI_INTERNAL.value) -> ToolResult:
    return gate.execute(
        ToolRequest(INSTALL_SPEC.name, {"package_id": package_id},
                    originating_source=originating_source),
        _do_install,
    )
