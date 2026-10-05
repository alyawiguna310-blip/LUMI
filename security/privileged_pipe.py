"""
Windows named-pipe transport for the privileged helper, with an explicit
restrictive security descriptor.

The DACL grants GENERIC_ALL to:
  - LocalSystem (SY)
  - Built-in Administrators (BA)
  - the current user's SID (from the process token)

No other principal is granted access. The pipe name is random and must
match [A-Za-z0-9_-]{1,256}. Callers construct the same name on both
sides via the invocation argv.

Windows-only. Non-Windows imports succeed but any operation raises
PrivilegedPipeUnavailable, so the caller can fail closed cleanly.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)


class PrivilegedPipeUnavailable(RuntimeError):
    pass


_IS_WINDOWS = (os.name == "nt")

if _IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    PIPE_ACCESS_DUPLEX = 0x00000003
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_READMODE_BYTE = 0x00000000
    PIPE_WAIT = 0x00000000
    PIPE_UNLIMITED_INSTANCES = 255

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3

    SDDL_REVISION_1 = 1

    ERROR_PIPE_CONNECTED = 535
    ERROR_PIPE_BUSY = 231

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Sid", ctypes.c_void_p),
            ("Attributes", wintypes.DWORD),
        ]

    class TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", SID_AND_ATTRIBUTES)]

    _k32.CreateNamedPipeW.argtypes = [
        ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p,
    ]
    _k32.CreateNamedPipeW.restype = wintypes.HANDLE

    _k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _k32.ConnectNamedPipe.restype = wintypes.BOOL

    _k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    _k32.DisconnectNamedPipe.restype = wintypes.BOOL

    _k32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    _k32.CreateFileW.restype = wintypes.HANDLE

    _k32.ReadFile.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    _k32.ReadFile.restype = wintypes.BOOL

    _k32.WriteFile.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    _k32.WriteFile.restype = wintypes.BOOL

    _k32.PeekNamedPipe.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _k32.PeekNamedPipe.restype = wintypes.BOOL

    _k32.WaitNamedPipeW.argtypes = [ctypes.c_wchar_p, wintypes.DWORD]
    _k32.WaitNamedPipeW.restype = wintypes.BOOL

    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL

    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.LocalFree.argtypes = [ctypes.c_void_p]
    _k32.LocalFree.restype = ctypes.c_void_p

    _adv32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
    ]
    _adv32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = \
        wintypes.BOOL

    _adv32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p),
    ]
    _adv32.ConvertSidToStringSidW.restype = wintypes.BOOL

    _adv32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
    ]
    _adv32.OpenProcessToken.restype = wintypes.BOOL

    _adv32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    _adv32.GetTokenInformation.restype = wintypes.BOOL

    TOKEN_QUERY = 0x0008
    TokenUser = 1


def _require_windows():
    if not _IS_WINDOWS:
        raise PrivilegedPipeUnavailable(
            "named pipe transport is Windows-only"
        )


def _validate_pipe_name(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("pipe name must be a string")
    if not (1 <= len(name) <= 256):
        raise ValueError("pipe name length out of range")
    for ch in name:
        if not (ch.isalnum() or ch in "_-"):
            raise ValueError(f"invalid character in pipe name: {ch!r}")
    return name


def _get_current_user_sid_string() -> str:
    _require_windows()
    proc = _k32.GetCurrentProcess()
    token = wintypes.HANDLE()
    if not _adv32.OpenProcessToken(proc, TOKEN_QUERY, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken")
    try:
        size = wintypes.DWORD(0)
        _adv32.GetTokenInformation(
            token, TokenUser, None, 0, ctypes.byref(size)
        )
        if size.value == 0:
            raise OSError(ctypes.get_last_error(), "GetTokenInformation size")
        buf = ctypes.create_string_buffer(size.value)
        if not _adv32.GetTokenInformation(
            token, TokenUser, buf, size.value, ctypes.byref(size)
        ):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation")
        user = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER)).contents
        sid_str = ctypes.c_wchar_p()
        if not _adv32.ConvertSidToStringSidW(
            user.User.Sid, ctypes.byref(sid_str)
        ):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW")
        try:
            return sid_str.value
        finally:
            _k32.LocalFree(sid_str)
    finally:
        _k32.CloseHandle(token)


def _build_sddl(user_sid_str: str) -> str:
    # DACL: GENERIC_ALL to SYSTEM, to Built-in Administrators, and to the
    # current user. No other principal receives any access.
    return (
        "D:"
        "(A;;GA;;;SY)"
        "(A;;GA;;;BA)"
        f"(A;;GA;;;{user_sid_str})"
    )


def _make_security_attributes():
    _require_windows()
    user_sid = _get_current_user_sid_string()
    sddl = _build_sddl(user_sid)
    sd_ptr = ctypes.c_void_p()
    if not _adv32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, ctypes.byref(sd_ptr), None,
    ):
        raise OSError(
            ctypes.get_last_error(),
            f"ConvertStringSecurityDescriptorToSecurityDescriptorW failed "
            f"for SDDL {sddl!r}",
        )
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.lpSecurityDescriptor = sd_ptr
    sa.bInheritHandle = 0
    return sa, sd_ptr


# ---------------------------------------------------------------- server


class PipeServer:
    """One-instance pipe server. Attach with `exchange_blocking()` in a
    worker thread and enforce the timeout at the caller."""

    def __init__(self, pipe_name: str):
        _require_windows()
        name = _validate_pipe_name(pipe_name)
        self._full_name = r"\\.\pipe\\" + name
        self._sa, self._sd_ptr = _make_security_attributes()
        self._handle = _k32.CreateNamedPipeW(
            self._full_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            64 * 1024,
            64 * 1024,
            0,
            ctypes.byref(self._sa),
        )
        if (self._handle is None
                or self._handle == _INVALID_HANDLE_VALUE
                or int(self._handle) == 0):
            err = ctypes.get_last_error()
            raise OSError(err, f"CreateNamedPipeW failed for {self._full_name}")

    def exchange_blocking(
        self,
        request: dict,
        *,
        max_response_bytes: int,
        response_timeout_s: float,
    ) -> dict:
        """Blocking: connect, write, read. Raises on any error."""
        from security.privileged_protocol import (
            encode_message, read_length_prefixed, ProtocolError,
        )
        # ConnectNamedPipe blocks until a client connects.
        if not _k32.ConnectNamedPipe(self._handle, None):
            err = ctypes.get_last_error()
            if err != ERROR_PIPE_CONNECTED:
                raise OSError(err, "ConnectNamedPipe")

        # Send the request.
        payload = encode_message(request, max_bytes=64 * 1024 * 1024)
        self._write_all(payload)

        deadline = time.monotonic() + float(response_timeout_s)
        return read_length_prefixed(
            lambda n: self._read_exactly(n, deadline),
            max_bytes=max_response_bytes,
        )

    def _write_all(self, data: bytes) -> None:
        buf = ctypes.create_string_buffer(data, len(data))
        written = wintypes.DWORD(0)
        offset = 0
        while offset < len(data):
            remaining = len(data) - offset
            base = ctypes.cast(ctypes.byref(buf, offset), ctypes.c_void_p)
            ok = _k32.WriteFile(
                self._handle, base, remaining,
                ctypes.byref(written), None,
            )
            if not ok:
                raise OSError(ctypes.get_last_error(), "WriteFile (server)")
            offset += written.value

    def _read_exactly(self, n: int, deadline: float) -> bytes:
        out = bytearray()
        while len(out) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("pipe read deadline exceeded")
            avail = wintypes.DWORD(0)
            if not _k32.PeekNamedPipe(
                self._handle, None, 0, None,
                ctypes.byref(avail), None,
            ):
                raise OSError(ctypes.get_last_error(), "PeekNamedPipe")
            if avail.value > 0:
                want = min(n - len(out), avail.value)
                buf = ctypes.create_string_buffer(want)
                read = wintypes.DWORD(0)
                if not _k32.ReadFile(
                    self._handle, buf, want,
                    ctypes.byref(read), None,
                ):
                    raise OSError(
                        ctypes.get_last_error(), "ReadFile (server)"
                    )
                out.extend(buf.raw[:read.value])
            else:
                time.sleep(0.02)
        return bytes(out)

    def close(self) -> None:
        if self._handle:
            try:
                _k32.DisconnectNamedPipe(self._handle)
            except Exception:
                pass
            try:
                _k32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None
        if self._sd_ptr:
            try:
                _k32.LocalFree(self._sd_ptr)
            except Exception:
                pass
            self._sd_ptr = None


# ---------------------------------------------------------------- client


class PipeClient:
    def __init__(self, handle):
        self._handle = handle

    @classmethod
    def connect(cls, pipe_name: str, timeout_s: float = 30.0) -> "PipeClient":
        _require_windows()
        name = _validate_pipe_name(pipe_name)
        full = r"\\.\pipe\\" + name
        deadline = time.monotonic() + float(timeout_s)
        while True:
            remaining_ms = int(max(0.0, deadline - time.monotonic()) * 1000)
            if remaining_ms <= 0:
                raise TimeoutError(
                    f"WaitNamedPipeW timeout for {full!r}"
                )
            _k32.WaitNamedPipeW(full, remaining_ms)
            handle = _k32.CreateFileW(
                full,
                GENERIC_READ | GENERIC_WRITE,
                0, None, OPEN_EXISTING, 0, None,
            )
            if (handle is not None
                    and handle != _INVALID_HANDLE_VALUE
                    and int(handle) != 0):
                return cls(handle)
            err = ctypes.get_last_error()
            if err == ERROR_PIPE_BUSY:
                time.sleep(0.05)
                continue
            raise OSError(err, f"CreateFileW failed for {full!r}")

    def read_message(
        self, *, max_bytes: int, timeout_s: float,
    ) -> dict:
        from security.privileged_protocol import read_length_prefixed
        deadline = time.monotonic() + float(timeout_s)
        return read_length_prefixed(
            lambda n: self._read_exactly(n, deadline),
            max_bytes=max_bytes,
        )

    def write_message(self, obj: dict, *, max_bytes: int) -> None:
        from security.privileged_protocol import encode_message
        self._write_all(encode_message(obj, max_bytes=max_bytes))

    def _write_all(self, data: bytes) -> None:
        buf = ctypes.create_string_buffer(data, len(data))
        written = wintypes.DWORD(0)
        offset = 0
        while offset < len(data):
            remaining = len(data) - offset
            base = ctypes.cast(ctypes.byref(buf, offset), ctypes.c_void_p)
            ok = _k32.WriteFile(
                self._handle, base, remaining,
                ctypes.byref(written), None,
            )
            if not ok:
                raise OSError(ctypes.get_last_error(), "WriteFile (client)")
            offset += written.value

    def _read_exactly(self, n: int, deadline: float) -> bytes:
        out = bytearray()
        while len(out) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("pipe read deadline exceeded")
            avail = wintypes.DWORD(0)
            if not _k32.PeekNamedPipe(
                self._handle, None, 0, None,
                ctypes.byref(avail), None,
            ):
                raise OSError(ctypes.get_last_error(), "PeekNamedPipe")
            if avail.value > 0:
                want = min(n - len(out), avail.value)
                buf = ctypes.create_string_buffer(want)
                read = wintypes.DWORD(0)
                if not _k32.ReadFile(
                    self._handle, buf, want,
                    ctypes.byref(read), None,
                ):
                    raise OSError(
                        ctypes.get_last_error(), "ReadFile (client)"
                    )
                out.extend(buf.raw[:read.value])
            else:
                time.sleep(0.02)
        return bytes(out)

    def close(self) -> None:
        if self._handle:
            try:
                _k32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None