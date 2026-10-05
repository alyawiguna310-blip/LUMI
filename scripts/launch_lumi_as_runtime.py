"""
scripts/launch_lumi_as_runtime.py

Prototype launcher that starts a fixed Python entry point as the
dedicated LumiRuntime user via CreateProcessWithLogonW with
LOGON_WITH_PROFILE.

Callable entry points:

    launch()                           - launches the fixed Lumi entry
                                         point (main.py). Returns int
                                         (0 on success). Does not wait.
    launch_probe()                     - launches the fixed Phase 5F-C
                                         identity probe.
    launch_minimal_diagnostic()        - TEMPORARY: launches the fixed
                                         venv-Python minimal diagnostic
                                         (TEST A).
    launch_system_minimal_diagnostic() - TEMPORARY: launches the fixed
                                         system-Python minimal
                                         diagnostic (TEST B).
    launch_test2_diagnostic()          - TEMPORARY: launches the fixed
                                         venv-Python -c payload for
                                         Phase 5F-C Test 2.

All take no arguments. Only module-level constants are used as paths.
The module does not read sys.argv, does not import subprocess, does not
invoke cmd.exe or PowerShell, and does not accept user-supplied
executables or arguments.

The password is read from Windows Credential Manager (target
'LumiRuntime', generic credential) using CredReadW. It is never printed,
never written to disk, and never stored in any diagnostic field.

Diagnostic fields (LaunchResult) never contain credential material.

Note on child stdout/stderr: an earlier revision attempted
STARTF_USESTDHANDLES redirection, which caused CreateProcessWithLogonW
to fail with WinError 6 (ERROR_INVALID_HANDLE). That path was removed.

Run the normal Lumi entry point:
    python scripts/launch_lumi_as_runtime.py

Run the Phase 5F-C validation:
    python scripts/phase5fc_validate.py
"""
from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from dataclasses import dataclass
from typing import Optional


# ------------------------------------------------------------------ config
#
# NOTE: The actual venv path is D:\Lumi\.venv (with a leading dot).


RUNTIME_USERNAME = "LumiRuntime"
CRED_TARGET = "LumiRuntime"
PROJECT_ROOT = r"D:\Lumi"
VENV_PYTHON = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe")
ENTRY = os.path.join(PROJECT_ROOT, "main.py")
PROBE_ENTRY = os.path.join(PROJECT_ROOT, "scripts", "_phase5fc_probe.py")
# Temporary: venv-Python minimal diagnostic. Delete with
# scripts/_phase5fc_minimal.py after the investigation.
MINIMAL_ENTRY = os.path.join(
    PROJECT_ROOT, "scripts", "_phase5fc_minimal.py",
)
# Temporary: system-Python minimal diagnostic. Delete with
# scripts/_phase5fc_system_minimal.py after the investigation.
SYSTEM_MINIMAL_ENTRY = os.path.join(
    PROJECT_ROOT, "scripts", "_phase5fc_system_minimal.py",
)
# Temporary: Test 2 diagnostic output file. Delete with
# launch_test2_diagnostic() after the investigation.
TEST2_DIAG_PATH = os.path.join(PROJECT_ROOT, "diag.txt")


# ------------------------------------------------------------------ Win32


_adv32 = ctypes.WinDLL("advapi32", use_last_error=True)
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

CRED_TYPE_GENERIC = 1

LOGON_WITH_PROFILE = 0x00000001
CREATE_UNICODE_ENVIRONMENT = 0x00000400

WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT  = 0x00000102
WAIT_FAILED   = 0xFFFFFFFF


class CREDENTIAL_ATTRIBUTE(ctypes.Structure):
    _fields_ = [
        ("Keyword", wintypes.LPWSTR),
        ("Flags", wintypes.DWORD),
        ("ValueSize", wintypes.DWORD),
        ("Value", ctypes.POINTER(ctypes.c_byte)),
    ]


class CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.POINTER(CREDENTIAL_ATTRIBUTE)),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


PCREDENTIAL = ctypes.POINTER(CREDENTIAL)

_adv32.CredReadW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(PCREDENTIAL),
]
_adv32.CredReadW.restype = wintypes.BOOL

_adv32.CredFree.argtypes = [ctypes.c_void_p]
_adv32.CredFree.restype = None


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


_adv32.CreateProcessWithLogonW.argtypes = [
    wintypes.LPCWSTR,   # lpUsername
    wintypes.LPCWSTR,   # lpDomain
    wintypes.LPCWSTR,   # lpPassword
    wintypes.DWORD,     # dwLogonFlags
    wintypes.LPCWSTR,   # lpApplicationName
    wintypes.LPWSTR,    # lpCommandLine
    wintypes.DWORD,     # dwCreationFlags
    ctypes.c_void_p,    # lpEnvironment
    wintypes.LPCWSTR,   # lpCurrentDirectory
    ctypes.POINTER(STARTUPINFO),
    ctypes.POINTER(PROCESS_INFORMATION),
]
_adv32.CreateProcessWithLogonW.restype = wintypes.BOOL

_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CloseHandle.restype = wintypes.BOOL

_k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_k32.WaitForSingleObject.restype = wintypes.DWORD

_k32.GetExitCodeProcess.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.DWORD),
]
_k32.GetExitCodeProcess.restype = wintypes.BOOL


# ------------------------------------------------------------------ result


@dataclass(frozen=True)
class LaunchResult:
    """Structured result of a launch attempt. Contains no credentials."""
    label: str
    application_path: str
    command_line: str
    cwd: str
    logon_flags: int
    creation_flags: int
    wait_seconds: int

    create_ok: bool
    create_last_error: Optional[int]

    pid: int
    exit_code: Optional[int]
    timed_out: bool

    def render_diagnostics(self) -> str:
        """Human-readable, data-only summary. The exact markers used
        here ("CreateProcessWithLogonW", "Win32 error", "Child exit
        code") are the ones the validator relies on."""
        lines = []
        if self.create_ok:
            lines.append("CreateProcessWithLogonW: SUCCESS")
            lines.append(f"PID: {self.pid}")
            if self.timed_out:
                lines.append(
                    f"Child timed out after {self.wait_seconds}s "
                    f"(process may still be running)"
                )
            elif self.exit_code is None:
                lines.append("Child exit code: unknown")
            else:
                lines.append(f"Child exit code: {self.exit_code}")
        else:
            lines.append("CreateProcessWithLogonW: FAILED")
            lines.append(f"Win32 error: {self.create_last_error}")
        lines.append(f"Application: {self.application_path}")
        lines.append(f"Command line: {self.command_line}")
        lines.append(f"Current directory: {self.cwd}")
        lines.append(f"Logon flags: 0x{self.logon_flags:08x}")
        lines.append(f"Creation flags: 0x{self.creation_flags:08x}")
        return "\n".join(lines)


# ------------------------------------------------------------------ helpers


def read_credential_password(target: str) -> str:
    """Return the password stored in Windows Credential Manager for
    `target`. Raises RuntimeError on failure. Never logs the value."""
    cred_ptr = PCREDENTIAL()
    ok = _adv32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(cred_ptr))
    if not ok:
        err = ctypes.get_last_error()
        raise RuntimeError(
            f"CredReadW failed for target {target!r} (WinError {err}). "
            f"Store the credential first via "
            f"scripts/phase5f_b_setup.ps1 (native CredWriteW)."
        )
    try:
        c = cred_ptr.contents
        size = c.CredentialBlobSize
        raw = ctypes.string_at(c.CredentialBlob, size) if size else b""
        try:
            return raw.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            return raw.decode("utf-8", errors="replace")
    finally:
        _adv32.CredFree(cred_ptr)


def _check_prereqs(entry_path: str,
                   python_executable: str = VENV_PYTHON) -> None:
    if sys.platform != "win32":
        raise SystemExit("launcher is Windows-only")
    if not os.path.isfile(python_executable):
        if python_executable == VENV_PYTHON:
            raise SystemExit(
                f"venv python missing: {VENV_PYTHON}  "
                f"(expected at D:\\Lumi\\.venv\\Scripts\\python.exe)"
            )
        raise SystemExit(
            f"python interpreter missing: {python_executable}"
        )
    if not os.path.isfile(entry_path):
        raise SystemExit(f"entry point missing: {entry_path}")


def _resolve_system_python() -> Optional[str]:
    """TEMPORARY: locate a Python interpreter outside the Lumi project
    tree by walking PATH.

    This is the pure-Python equivalent of `where.exe python`, minus the
    subprocess call (the launcher is forbidden from importing
    subprocess). It returns the first `python.exe` found on PATH that
    is not inside PROJECT_ROOT (which excludes the venv at
    PROJECT_ROOT\\.venv\\), or None if no such interpreter is on PATH.

    Delete this function along with the rest of the system-Python
    diagnostic after the exit-code-103 investigation is closed.
    """
    proj_norm = os.path.normcase(os.path.normpath(PROJECT_ROOT))
    path_env = os.environ.get("PATH", "")
    candidates: list = []
    for raw_dir in path_env.split(os.pathsep):
        d = raw_dir.strip()
        if not d:
            continue
        if len(d) >= 2 and d[0] == '"' and d[-1] == '"':
            d = d[1:-1]
        try:
            exe = os.path.join(d, "python.exe")
        except Exception:
            continue
        if os.path.isfile(exe):
            candidates.append(exe)
    for c in candidates:
        try:
            c_norm = os.path.normcase(os.path.normpath(c))
        except Exception:
            continue
        if c_norm == proj_norm or c_norm.startswith(proj_norm + os.sep):
            continue
        return c
    # Fall back to the first match, even if it is inside PROJECT_ROOT.
    return candidates[0] if candidates else None


def _launch_with_entry(entry_path: str, *, label: str,
                       wait_seconds: int = 0) -> LaunchResult:
    """Internal: launch exactly one fixed (VENV_PYTHON, entry_path) pair
    under RUNTIME_USERNAME via CreateProcessWithLogonW.

    No child handle redirection is configured.

    The password is passed only as a transient argument to
    CreateProcessWithLogonW and is cleared from local scope in a finally
    block before any return path.
    """
    _check_prereqs(entry_path)

    domain = os.environ.get("COMPUTERNAME", "")
    user = RUNTIME_USERNAME
    password = read_credential_password(CRED_TARGET)

    command_line = f'"{VENV_PYTHON}" "{entry_path}"'
    cmd_buf = ctypes.create_unicode_buffer(command_line)

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()

    create_ok = False
    create_last_error: Optional[int] = None
    pid = 0
    exit_code: Optional[int] = None
    timed_out = False

    try:
        ok = _adv32.CreateProcessWithLogonW(
            user,
            domain,
            password,
            LOGON_WITH_PROFILE,
            VENV_PYTHON,
            cmd_buf,
            CREATE_UNICODE_ENVIRONMENT,
            None,
            PROJECT_ROOT,
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        if not ok:
            create_last_error = int(ctypes.get_last_error())
        else:
            create_ok = True
    finally:
        password = None  # noqa: F841

    if create_ok:
        pid = int(pi.dwProcessId)
        print(f"Launched {label} as {domain}\\{user}. PID={pid}")
        if wait_seconds > 0:
            wfso = _k32.WaitForSingleObject(pi.hProcess, wait_seconds * 1000)
            if wfso == WAIT_OBJECT_0:
                code_buf = wintypes.DWORD(0)
                if _k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code_buf)):
                    exit_code = int(code_buf.value)
                else:
                    exit_code = None
            elif wfso == WAIT_TIMEOUT:
                timed_out = True
            else:
                pass
        _k32.CloseHandle(pi.hThread)
        _k32.CloseHandle(pi.hProcess)
    else:
        print(
            f"CreateProcessWithLogonW failed for {label} "
            f"(WinError {create_last_error})."
        )

    return LaunchResult(
        label=label,
        application_path=VENV_PYTHON,
        command_line=command_line,
        cwd=PROJECT_ROOT,
        logon_flags=LOGON_WITH_PROFILE,
        creation_flags=CREATE_UNICODE_ENVIRONMENT,
        wait_seconds=wait_seconds,
        create_ok=create_ok,
        create_last_error=create_last_error,
        pid=pid,
        exit_code=exit_code,
        timed_out=timed_out,
    )


def _launch_system_python_with_entry(
    python_executable: str, entry_path: str, *,
    label: str, wait_seconds: int = 0,
) -> LaunchResult:
    """TEMPORARY: like _launch_with_entry, but uses an explicit Python
    interpreter path instead of VENV_PYTHON.

    Used only by launch_system_minimal_diagnostic() for TEST B. Uses
    the identical CreateProcessWithLogonW configuration; the only
    variable is the interpreter path.

    Delete with the rest of the system-Python diagnostic.
    """
    _check_prereqs(entry_path, python_executable=python_executable)

    domain = os.environ.get("COMPUTERNAME", "")
    user = RUNTIME_USERNAME
    password = read_credential_password(CRED_TARGET)

    command_line = f'"{python_executable}" "{entry_path}"'
    cmd_buf = ctypes.create_unicode_buffer(command_line)

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()

    create_ok = False
    create_last_error: Optional[int] = None
    pid = 0
    exit_code: Optional[int] = None
    timed_out = False

    try:
        ok = _adv32.CreateProcessWithLogonW(
            user,
            domain,
            password,
            LOGON_WITH_PROFILE,
            python_executable,
            cmd_buf,
            CREATE_UNICODE_ENVIRONMENT,
            None,
            PROJECT_ROOT,
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        if not ok:
            create_last_error = int(ctypes.get_last_error())
        else:
            create_ok = True
    finally:
        password = None  # noqa: F841

    if create_ok:
        pid = int(pi.dwProcessId)
        print(f"Launched {label} as {domain}\\{user}. PID={pid}")
        if wait_seconds > 0:
            wfso = _k32.WaitForSingleObject(pi.hProcess, wait_seconds * 1000)
            if wfso == WAIT_OBJECT_0:
                code_buf = wintypes.DWORD(0)
                if _k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code_buf)):
                    exit_code = int(code_buf.value)
                else:
                    exit_code = None
            elif wfso == WAIT_TIMEOUT:
                timed_out = True
            else:
                pass
        _k32.CloseHandle(pi.hThread)
        _k32.CloseHandle(pi.hProcess)
    else:
        print(
            f"CreateProcessWithLogonW failed for {label} "
            f"(WinError {create_last_error})."
        )

    return LaunchResult(
        label=label,
        application_path=python_executable,
        command_line=command_line,
        cwd=PROJECT_ROOT,
        logon_flags=LOGON_WITH_PROFILE,
        creation_flags=CREATE_UNICODE_ENVIRONMENT,
        wait_seconds=wait_seconds,
        create_ok=create_ok,
        create_last_error=create_last_error,
        pid=pid,
        exit_code=exit_code,
        timed_out=timed_out,
    )


# ------------------------------------------------------------------ public


def launch() -> int:
    """Launch the fixed Lumi entry point (D:\\Lumi\\main.py) under
    LumiRuntime.

    Takes no arguments. Does not wait for the child to exit. Returns 0
    on successful launch; raises SystemExit on failure.
    """
    result = _launch_with_entry(ENTRY, label="lumi")
    if not result.create_ok:
        raise SystemExit(
            f"CreateProcessWithLogonW failed (WinError "
            f"{result.create_last_error}) for lumi. "
            f"Application: {result.application_path}"
        )
    return 0


def launch_probe() -> LaunchResult:
    """Launch the fixed Phase 5F-C identity probe under LumiRuntime.

    Takes no arguments. Waits up to 30 seconds and returns a
    LaunchResult carrying the diagnostics of the attempt.
    """
    return _launch_with_entry(PROBE_ENTRY, label="probe", wait_seconds=30)


def launch_minimal_diagnostic() -> LaunchResult:
    """TEMPORARY: launch the fixed venv-Python minimal diagnostic
    (scripts/_phase5fc_minimal.py) under LumiRuntime (TEST A).

    Delete with the rest of the minimal diagnostic.
    """
    return _launch_with_entry(
        MINIMAL_ENTRY, label="minimal", wait_seconds=30,
    )


def launch_system_minimal_diagnostic() -> LaunchResult:
    """TEMPORARY: launch the fixed system-Python minimal diagnostic
    (scripts/_phase5fc_system_minimal.py) under LumiRuntime (TEST B).

    Uses the SAME CreateProcessWithLogonW configuration as every other
    entry point in this module. The only variable vs. TEST A is the
    Python interpreter path: this function uses a system Python
    resolved from PATH instead of VENV_PYTHON.

    Raises SystemExit if no system Python can be resolved.

    Delete with the rest of the system-Python diagnostic.
    """
    system_python = _resolve_system_python()
    if not system_python:
        raise SystemExit(
            "no system Python found on PATH outside PROJECT_ROOT; "
            "cannot run the system-Python diagnostic"
        )
    print(f"System Python resolved: {system_python}")
    return _launch_system_python_with_entry(
        system_python, SYSTEM_MINIMAL_ENTRY,
        label="sysminimal", wait_seconds=30,
    )


def launch_test2_diagnostic() -> LaunchResult:
    """TEMPORARY Test 2: launch the venv Python with a fixed -c payload
    under LumiRuntime via the SAME CreateProcessWithLogonW path used by
    launch_probe().

    Test target:  D:\\Lumi\\.venv\\Scripts\\python.exe
    Test command: -c "open(r'D:\\Lumi\\diag.txt','w').write('ok')"
    Working dir:  D:\\Lumi

    Same application path (VENV_PYTHON), credentials (CredReadW +
    LumiRuntime), logon flags (LOGON_WITH_PROFILE), creation flags
    (CREATE_UNICODE_ENVIRONMENT), and working directory (PROJECT_ROOT)
    as launch_probe(). Only the command line differs.

    After the child exits, checks TEST2_DIAG_PATH and prints its
    contents if present. Returns a LaunchResult with the same fields
    every other launcher entry point returns.

    Delete this function, its call site, and TEST2_DIAG_PATH after the
    exit-code-103 investigation is closed. Diagnostic code only.
    """
    diag_path = TEST2_DIAG_PATH

    # Remove any stale file so a hit can only mean this run wrote it.
    try:
        if os.path.exists(diag_path):
            os.remove(diag_path)
    except OSError as exc:
        print(f"[test2] could not remove stale {diag_path}: {exc}")

    if not os.path.isfile(VENV_PYTHON):
        raise SystemExit(f"venv python missing: {VENV_PYTHON}")

    domain = os.environ.get("COMPUTERNAME", "")
    user = RUNTIME_USERNAME
    password = read_credential_password(CRED_TARGET)

    # The -c payload is ONE argv element. Inside it, single quotes wrap
    # the raw-string path and the 'ok' literal, so the outer double
    # quotes around the payload are unambiguous to the C runtime's
    # CommandLineToArgvW parsing.
    code = "open(r'D:\\Lumi\\diag.txt','w').write('ok')"
    command_line = f'"{VENV_PYTHON}" -c "{code}"'
    cmd_buf = ctypes.create_unicode_buffer(command_line)

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()

    create_ok = False
    create_last_error: Optional[int] = None
    pid = 0
    exit_code: Optional[int] = None
    timed_out = False
    wait_seconds = 30

    try:
        ok = _adv32.CreateProcessWithLogonW(
            user,
            domain,
            password,
            LOGON_WITH_PROFILE,
            VENV_PYTHON,
            cmd_buf,
            CREATE_UNICODE_ENVIRONMENT,
            None,
            PROJECT_ROOT,
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        if not ok:
            create_last_error = int(ctypes.get_last_error())
        else:
            create_ok = True
    finally:
        password = None  # noqa: F841

    if create_ok:
        pid = int(pi.dwProcessId)
        print(f"Launched test2 as {domain}\\{user}. PID={pid}")
        wfso = _k32.WaitForSingleObject(pi.hProcess, wait_seconds * 1000)
        if wfso == WAIT_OBJECT_0:
            code_buf = wintypes.DWORD(0)
            if _k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code_buf)):
                exit_code = int(code_buf.value)
            else:
                exit_code = None
        elif wfso == WAIT_TIMEOUT:
            timed_out = True
        else:
            pass
        _k32.CloseHandle(pi.hThread)
        _k32.CloseHandle(pi.hProcess)
    else:
        print(
            f"CreateProcessWithLogonW failed for test2 "
            f"(WinError {create_last_error})."
        )

    diag_exists = os.path.exists(diag_path)
    diag_contents: Optional[str] = None
    if diag_exists:
        try:
            with open(diag_path, "r", encoding="utf-8") as f:
                diag_contents = f.read()
        except OSError as exc:
            diag_contents = f"<unreadable: {exc}>"

    print(
        "[test2] CreateProcessWithLogonW: "
        + ("SUCCESS" if create_ok else "FAILED")
    )
    if create_ok:
        print(f"[test2] PID: {pid}")
        if timed_out:
            print(f"[test2] Child timed out after {wait_seconds}s")
        elif exit_code is not None:
            print(f"[test2] Child exit code: {exit_code}")
        else:
            print("[test2] Child exit code: unknown")
    else:
        print(f"[test2] Win32 error: {create_last_error}")
    print(f"[test2] {diag_path} exists: {diag_exists}")
    if diag_exists:
        print(f"[test2] {diag_path} contents: {diag_contents!r}")

    return LaunchResult(
        label="test2",
        application_path=VENV_PYTHON,
        command_line=command_line,
        cwd=PROJECT_ROOT,
        logon_flags=LOGON_WITH_PROFILE,
        creation_flags=CREATE_UNICODE_ENVIRONMENT,
        wait_seconds=wait_seconds,
        create_ok=create_ok,
        create_last_error=create_last_error,
        pid=pid,
        exit_code=exit_code,
        timed_out=timed_out,
    )


if __name__ == "__main__":
    sys.exit(launch())