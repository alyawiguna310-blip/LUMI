"""Phase 5F-B OS ACL probe.

Runs under LumiRuntime and verifies that the Windows ACL blocks mutation of
the Lumi control plane while leaving the normal workspace writable.

This probe takes no arguments and uses only fixed paths.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
import subprocess

PROJECT_ROOT = r"D:\Lumi"
SECURITY_DIR = os.path.join(PROJECT_ROOT, "security")
MAIN_PATH = os.path.join(PROJECT_ROOT, "main.py")
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config.py")
ENV_PATH = os.path.join(PROJECT_ROOT, ".env")
WORKSPACE_DIR = os.path.join(PROJECT_ROOT, "workspace")
RESULT_PATH = os.path.join(WORKSPACE_DIR, "phase5fb_acl_result.json")
CREATE_TEST_PATH = os.path.join(SECURITY_DIR, "_phase5fb_acl_probe.tmp")

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_GENERIC_READ = 0x120089
FILE_GENERIC_WRITE = 0x120116
FILE_GENERIC_EXECUTE = 0x1200A0
FILE_ALL_ACCESS = 0x1F01FF
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
SECURITY_IMPERSONATION = 2
TOKEN_IMPERSONATION = 2
OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
ERROR_INSUFFICIENT_BUFFER = 122

class GENERIC_MAPPING(ctypes.Structure):
    _fields_ = [
        ("GenericRead", wintypes.DWORD),
        ("GenericWrite", wintypes.DWORD),
        ("GenericExecute", wintypes.DWORD),
        ("GenericAll", wintypes.DWORD),
    ]

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

_CreateFileW = _kernel32.CreateFileW
_CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
_CreateFileW.restype = wintypes.HANDLE

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL

_GetCurrentProcess = _kernel32.GetCurrentProcess
_GetCurrentProcess.argtypes = []
_GetCurrentProcess.restype = wintypes.HANDLE

_GetFileSecurityW = _advapi32.GetFileSecurityW
_GetFileSecurityW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
]
_GetFileSecurityW.restype = wintypes.BOOL

_OpenProcessToken = _advapi32.OpenProcessToken
_OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
]
_OpenProcessToken.restype = wintypes.BOOL

_DuplicateTokenEx = _advapi32.DuplicateTokenEx
_DuplicateTokenEx.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
]
_DuplicateTokenEx.restype = wintypes.BOOL

_AccessCheck = _advapi32.AccessCheck
_AccessCheck.argtypes = [
    wintypes.LPVOID, wintypes.HANDLE, wintypes.DWORD,
    ctypes.POINTER(GENERIC_MAPPING), wintypes.LPVOID,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.BOOL),
]
_AccessCheck.restype = wintypes.BOOL


def _write_result(result):
    os.makedirs(WORKSPACE_DIR, exist_ok=True)
    tmp = RESULT_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, RESULT_PATH)


def _test_directory_create():
    try:
        with open(CREATE_TEST_PATH, "x", encoding="utf-8") as f:
            f.write("ACL probe")
    except PermissionError:
        return True, "directory create denied"
    except OSError as exc:
        return False, f"directory create failed with unexpected error: {type(exc).__name__}: {exc}"
    else:
        try:
            os.remove(CREATE_TEST_PATH)
        except OSError:
            pass
        return False, "directory create was allowed"


def _current_identity():
    try:
        proc = subprocess.run(
            ["whoami", "/user", "/groups"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def _native_read_probe(path):
    ctypes.set_last_error(0)
    handle = _CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        return {
            "allowed": False,
            "winerror": error,
            "message": ctypes.FormatError(error),
        }
    _CloseHandle(handle)
    return {"allowed": True, "winerror": 0, "message": "CreateFileW read handle opened"}


def _access_check(path, desired_access):
    """Ask Windows AccessCheck for the current LumiRuntime token."""
    primary_token = wintypes.HANDLE()
    if not _OpenProcessToken(
        _GetCurrentProcess(),
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
        ctypes.byref(primary_token),
    ):
        error = ctypes.get_last_error()
        return {"ok": False, "error": error, "message": ctypes.FormatError(error)}

    impersonation_token = wintypes.HANDLE()
    try:
        if not _DuplicateTokenEx(
            primary_token,
            TOKEN_QUERY | TOKEN_IMPERSONATE,
            None,
            SECURITY_IMPERSONATION,
            TOKEN_IMPERSONATION,
            ctypes.byref(impersonation_token),
        ):
            error = ctypes.get_last_error()
            return {
                "ok": False,
                "error": error,
                "message": ctypes.FormatError(error),
            }

        needed = wintypes.DWORD()
        ctypes.set_last_error(0)
        _GetFileSecurityW(
            path,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            0,
            ctypes.byref(needed),
        )
        error = ctypes.get_last_error()
        if not needed.value or error != ERROR_INSUFFICIENT_BUFFER:
            return {
                "ok": False,
                "error": error,
                "message": ctypes.FormatError(error),
            }

        descriptor = ctypes.create_string_buffer(needed.value)
        returned = wintypes.DWORD()
        if not _GetFileSecurityW(
            path,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            descriptor,
            needed.value,
            ctypes.byref(returned),
        ):
            error = ctypes.get_last_error()
            return {"ok": False, "error": error, "message": ctypes.FormatError(error)}

        mapping = GENERIC_MAPPING(
            FILE_GENERIC_READ,
            FILE_GENERIC_WRITE,
            FILE_GENERIC_EXECUTE,
            FILE_ALL_ACCESS,
        )
        privilege_buffer = ctypes.create_string_buffer(4096)
        privilege_length = wintypes.DWORD(len(privilege_buffer))
        granted = wintypes.DWORD()
        access_status = wintypes.BOOL()

        ctypes.set_last_error(0)
        if not _AccessCheck(
            descriptor,
            impersonation_token,
            desired_access,
            ctypes.byref(mapping),
            privilege_buffer,
            ctypes.byref(privilege_length),
            ctypes.byref(granted),
            ctypes.byref(access_status),
        ):
            error = ctypes.get_last_error()
            return {"ok": False, "error": error, "message": ctypes.FormatError(error)}

        return {
            "ok": True,
            "desired_access": desired_access,
            "granted_access": granted.value,
            "access_allowed": bool(access_status.value),
        }
    finally:
        if impersonation_token.value:
            _CloseHandle(impersonation_token)
        _CloseHandle(primary_token)


def _test_file_read(path):
    native = _native_read_probe(path)
    effective = _access_check(path, FILE_GENERIC_READ)
    try:
        readable = os.access(path, os.R_OK)
        if os.path.isdir(path):
            os.listdir(path)
        else:
            with open(path, "rb") as f:
                f.read(1)
        return True, f"read permitted; os.access(R_OK)={readable}; native={json.dumps(native, sort_keys=True)}; effective={json.dumps(effective, sort_keys=True)}"
    except OSError as exc:
        detail = {
            "type": type(exc).__name__,
            "errno": exc.errno,
            "winerror": getattr(exc, "winerror", None),
            "strerror": exc.strerror,
            "filename": exc.filename,
            "access_r": os.access(path, os.R_OK),
            "native": native,
            "effective_read": effective,
        }
        return False, f"read failed: {json.dumps(detail, sort_keys=True)}"
    except Exception as exc:
        return False, f"read failed: {type(exc).__name__}: {exc}; native={json.dumps(native, sort_keys=True)}; effective={json.dumps(effective, sort_keys=True)}"


def _test_file_write_open(path):
    try:
        fd = os.open(path, os.O_WRONLY)
    except PermissionError:
        return True, "write-open denied"
    except OSError as exc:
        return False, f"write-open failed with unexpected error: {type(exc).__name__}: {exc}"
    else:
        os.close(fd)
        return False, "write-open was allowed"


def _test_workspace_write():
    path = os.path.join(WORKSPACE_DIR, "_phase5fb_workspace_probe.tmp")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("workspace ACL probe")
        os.remove(path)
        return True, "workspace write allowed"
    except Exception as exc:
        try:
            os.remove(path)
        except OSError:
            pass
        return False, f"workspace write failed: {type(exc).__name__}: {exc}"


def main():
    checks = {}

    checks["security_directory_create"] = _test_directory_create()

    for label, path in (
        ("main_py_read", MAIN_PATH),
        ("config_py_read", CONFIG_PATH),
        ("env_read", ENV_PATH),
        ("security_directory_read", SECURITY_DIR),
    ):
        checks[label] = _test_file_read(path) if os.path.isfile(path) else (
            True, "directory read/listing is permitted by normal path access"
        ) if os.path.isdir(path) else (False, "target does not exist")

    for label, path in (
        ("main_py_write_open", MAIN_PATH),
        ("config_py_write_open", CONFIG_PATH),
        ("env_write_open", ENV_PATH),
        ("tool_router_write_open", os.path.join(PROJECT_ROOT, "core", "tool_router.py")),
        ("admin_tasks_write_open", os.path.join(PROJECT_ROOT, "tools", "admin_tasks.py")),
        ("terminal_guard_write_open", os.path.join(PROJECT_ROOT, "tools", "terminal_guard.py")),
        ("audit_write_open", os.path.join(PROJECT_ROOT, "storage", "audit.py")),
    ):
        if not os.path.isfile(path):
            checks[label] = (False, "target file does not exist")
        else:
            checks[label] = _test_file_write_open(path)

    checks["workspace_write"] = _test_workspace_write()

    result = {
        "username": os.environ.get("USERNAME", ""),
        "identity": _current_identity(),
        "checks": {k: {"passed": v[0], "detail": v[1]} for k, v in checks.items()},
        "passed": all(v[0] for v in checks.values()),
    }

    try:
        _write_result(result)
    except Exception as exc:
        print(f"FAIL: could not write probe result: {type(exc).__name__}: {exc}")
        return 2

    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
