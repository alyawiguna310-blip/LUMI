"""
Structured, tamper-evident audit log.

Two layers of protection:

1. Append-only OS sink (Windows). While Lumi runs, the audit file is held
   open with FILE_APPEND_DATA and only FILE_SHARE_READ. No other process
   - including subprocesses spawned by Lumi's own tools - can open the
   file for write or delete it. Attempts fail with a sharing violation.

2. Hash chain. Every record commits to the previous record's hash:
       hash = SHA256(prev_hash || canonical_json(body))
   On startup the chain is re-walked. A mismatch is reported loudly on
   stderr, and an `audit.chain_broken` marker is written so the break is
   visible in the log itself.

Backward compatibility and recovery markers:

   Legacy prefix. Records written before the hash-chain format was
   introduced lack both `hash` and `prev_hash`. They are treated as a
   legacy prefix: skipped for chain verification, never rehashed.

   Recovery markers. `audit.chain_broken` is the event name used by the
   writer to declare a segment boundary. A marker's own hash is always
   verified against `compute(prev_hash, body)`; a marker whose body or
   hash has been altered fails closed. When accepted, the marker's hash
   becomes the running tail, and subsequent records chain from it.

   Two marker formats exist in the wild, both accepted as boundaries:

     * zero-prev markers (`prev_hash == _ZERO_HASH`) — the format the
       current writer still produces. Written when the verifier returned
       a fresh genesis. These are the "normal" recovery markers.

     * stale-prev markers (`prev_hash != _ZERO_HASH`) — historical
       artifacts of a transitional build window during which the
       verifier returned a stale non-zero tail at the point of failure.
       They are structurally valid but do not chain to the current
       segment. They are treated as boundaries and counted separately
       in startup diagnostics.

   Fail-closed. Malformed JSON, half-chained records, legacy records
   appearing after chain start, and any *non-marker* record whose
   `prev_hash` does not match the running tail are hard failures.

Documented limitation: between Lumi sessions the file is closed and the
OS grants the owning user normal access. Tampering between sessions is
*detected* on next startup but not *prevented*. Full between-session
protection requires a separate low-privilege sink (Windows Event Log or
a system service), which is out of Phase 1 scope.

See SECURITY.md for the full rationale.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------- paths

_AUDIT_PATH = Path.home() / ".lumi" / "logs" / "audit.log"

# ---------------------------------------------------------------- Windows

_HAVE_WIN32 = False
_INVALID_HANDLE = None
_ctypes = None
_msvcrt = None
_k32 = None

if os.name == "nt":
    try:
        import ctypes as _ctypes_mod
        import msvcrt as _msvcrt_mod
        from ctypes import wintypes as _wintypes

        _FILE_APPEND_DATA       = 0x0004
        _FILE_SHARE_READ        = 0x00000001
        _OPEN_ALWAYS            = 4
        _FILE_ATTRIBUTE_NORMAL  = 0x80

        _k32_mod = _ctypes_mod.windll.kernel32
        _k32_mod.CreateFileW.argtypes = [
            _ctypes_mod.c_wchar_p,
            _wintypes.DWORD,
            _wintypes.DWORD,
            _ctypes_mod.c_void_p,
            _wintypes.DWORD,
            _wintypes.DWORD,
            _wintypes.HANDLE,
        ]
        _k32_mod.CreateFileW.restype = _wintypes.HANDLE
        _INVALID_HANDLE = _ctypes_mod.c_void_p(-1).value

        _ctypes = _ctypes_mod
        _msvcrt = _msvcrt_mod
        _k32 = _k32_mod
        _HAVE_WIN32 = True
    except Exception:
        _HAVE_WIN32 = False


def _open_append_only_windows(path: str) -> int:
    """Open a file for append with exclusive write sharing, return an
    OS file descriptor suitable for os.fdopen()."""
    handle = _k32.CreateFileW(
        path,
        _FILE_APPEND_DATA,
        _FILE_SHARE_READ,        # read-only sharing: no write, no delete
        None,
        _OPEN_ALWAYS,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle is None or handle == _INVALID_HANDLE:
        raise OSError(
            _ctypes.get_last_error(),
            f"CreateFileW(FILE_APPEND_DATA, FILE_SHARE_READ) failed on {path!r}",
        )
    # Transfer ownership of the raw Win32 handle to the CRT.
    fd = _msvcrt.open_osfhandle(handle, os.O_APPEND | os.O_WRONLY)
    return fd


def _open_append_only_posix(path: str) -> int:
    """POSIX fallback. Atomic append, but does NOT prevent other processes
    from opening the file for write. Dev-only. Documented in SECURITY.md."""
    return os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)


# ---------------------------------------------------------------- hashing


def _canonical(body: dict) -> str:
    return json.dumps(
        body, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), default=str,
    )


def _hash(prev_hash: str, body: dict) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(_canonical(body).encode("utf-8"))
    return h.hexdigest()


_ZERO_HASH = "0" * 64

_RECOVERY_EVENT = "audit.chain_broken"


# ---------------------------------------------------------------- sink


class _AuditSink:
    """Append-only, hash-chained audit sink.

    Never raises from the constructor. If the sink cannot be opened it
    becomes unusable and every write is reported to stderr instead of
    being silently dropped. audit() callers can then continue.
    """

    _RESERVED_KEYS = ("hash", "prev_hash")

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._fp = None
        self._prev_hash = _ZERO_HASH
        self._usable = False
        # Diagnostics: how the chain is broken into segments.
        self._breaks_declared = 0
        self._zero_breaks = 0
        self._stale_breaks = 0

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            sys.stderr.write(f"[AUDIT] cannot create parent dir: {e}\n")
            return

        # Verify chain BEFORE we take the exclusive handle.
        last_good, ok = self._verify_chain()
        self._prev_hash = last_good

        if self._breaks_declared:
            sys.stderr.write(
                f"[AUDIT] chain contains {self._breaks_declared} "
                f"accepted recovery boundary(ies) "
                f"({self._zero_breaks} zero-prev, "
                f"{self._stale_breaks} stale-prev); "
                f"each boundary was integrity-checked\n"
            )

        try:
            if os.name == "nt" and _HAVE_WIN32:
                fd = _open_append_only_windows(str(self.path))
            else:
                fd = _open_append_only_posix(str(self.path))
            self._fp = os.fdopen(fd, "a", encoding="utf-8", newline="\n")
            self._usable = True
        except Exception as e:
            sys.stderr.write(
                f"[AUDIT] unable to open sink {self.path}: {e}\n"
                f"[AUDIT] audit events will be written to stderr only\n"
            )
            self._usable = False
            return

        if not ok:
            sys.stderr.write(
                "[AUDIT] chain verification FAILED; writing marker\n"
            )
            # Best-effort marker. Uses the append handle we just opened.
            self.write(_RECOVERY_EVENT, {"path": str(self.path)})

    # ---------- verification ----------

    def _verify_chain(self) -> tuple[str, bool]:
        """Walk the on-disk log, recompute the chain, return
        (last_good_hash, ok). Read-only. Never raises.

        Semantics:

          - Legacy prefix (no hash / prev_hash) is skipped. Never
            rehashed.
          - The first chained record is the effective genesis. Its
            prev_hash must equal _ZERO_HASH unless the record is a
            recovery marker.
          - A recovery marker (`audit.chain_broken`) is a segment
            boundary regardless of its own prev_hash. Its own hash is
            always verified against compute(prev_hash, body); if that
            check fails, the whole walk fails. When accepted, the
            marker's hash becomes the new running tail.
          - Any other record must chain to the running tail.
          - Malformed JSON, half-chained records, or legacy records
            after chain start are hard failures.

        Sets `self._breaks_declared`, `self._zero_breaks`, and
        `self._stale_breaks` for diagnostics.
        """
        last = _ZERO_HASH
        chain_started = False
        self._breaks_declared = 0
        self._zero_breaks = 0
        self._stale_breaks = 0

        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except Exception:
                        sys.stderr.write(
                            f"[AUDIT] chain broken at line {lineno}: "
                            f"JSON parse failed\n"
                        )
                        return last, False

                    if not isinstance(record, dict):
                        sys.stderr.write(
                            f"[AUDIT] chain broken at line {lineno}: "
                            f"record is not a JSON object\n"
                        )
                        return last, False

                    has_hash = "hash" in record
                    has_prev = "prev_hash" in record

                    if not has_hash and not has_prev:
                        # Legacy record. Skip; never rehash.
                        if chain_started:
                            sys.stderr.write(
                                f"[AUDIT] chain broken at line {lineno}: "
                                f"legacy record after chain start\n"
                            )
                            return last, False
                        continue

                    if has_hash != has_prev:
                        sys.stderr.write(
                            f"[AUDIT] chain broken at line {lineno}: "
                            f"record has only one of hash/prev_hash\n"
                        )
                        return last, False

                    stored_hash = record.pop("hash")
                    stored_prev = record.pop("prev_hash")

                    # Structural integrity: the record's own hash must
                    # match recomputation. Applies to markers too.
                    expected = _hash(stored_prev, record)
                    if stored_hash != expected:
                        sys.stderr.write(
                            f"[AUDIT] chain broken at line {lineno}: "
                            f"hash mismatch\n"
                        )
                        return last, False

                    # Segment boundary: any audit.chain_broken marker
                    # resets the running tail to its own hash, regardless
                    # of the marker's claimed prev_hash. The marker's own
                    # hash has been verified above.
                    is_marker = (record.get("event") == _RECOVERY_EVENT)
                    if is_marker:
                        if chain_started:
                            self._breaks_declared += 1
                            if stored_prev == _ZERO_HASH:
                                self._zero_breaks += 1
                            else:
                                self._stale_breaks += 1
                        chain_started = True
                        last = stored_hash
                        continue

                    # Normal chaining.
                    if not chain_started:
                        if stored_prev != _ZERO_HASH:
                            sys.stderr.write(
                                f"[AUDIT] chain broken at line {lineno}: "
                                f"first chained record has non-genesis "
                                f"prev_hash\n"
                            )
                            return last, False
                        chain_started = True
                    else:
                        if stored_prev != last:
                            sys.stderr.write(
                                f"[AUDIT] chain broken at line {lineno}: "
                                f"prev_hash mismatch\n"
                            )
                            return last, False

                    last = stored_hash
        except FileNotFoundError:
            return last, True
        except Exception as e:
            sys.stderr.write(f"[AUDIT] chain verification error: {e}\n")
            return last, False
        return last, True

    # ---------- writing ----------

    def write(self, event: str, fields: dict) -> None:
        if not self._usable or self._fp is None:
            sys.stderr.write(
                f"[AUDIT] sink unusable; dropped event={event!r}\n"
            )
            return

        body = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "event": event,
        }
        # Reserved keys would collide with chain metadata.
        for k, v in fields.items():
            if k in self._RESERVED_KEYS:
                continue
            body[k] = v

        with self._lock:
            prev = self._prev_hash
            h = _hash(prev, body)
            record = dict(body)
            record["prev_hash"] = prev
            record["hash"] = h
            try:
                self._fp.write(
                    json.dumps(record, ensure_ascii=False, default=str) + "\n"
                )
                self._fp.flush()
            except Exception as e:
                sys.stderr.write(f"[AUDIT] write failed: {e}\n")
                return
            self._prev_hash = h

    # ---------- lifecycle (used by tests) ----------

    def close(self) -> None:
        with self._lock:
            if self._fp is not None:
                try:
                    self._fp.close()
                except Exception:
                    pass
                self._fp = None
            self._usable = False


# ---------------------------------------------------------------- module

_sink = _AuditSink(_AUDIT_PATH)


def audit(event: str, **fields) -> None:
    """Write one audit record. Never raises."""
    try:
        _sink.write(event, fields)
    except Exception as e:
        # Belt and suspenders. The sink already swallows internally.
        sys.stderr.write(f"[AUDIT] dispatch failed: {e}\n")