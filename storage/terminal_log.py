"""
Human-readable terminal activity log.
Separate from audit.log (JSON) — this one is for you to tail / open.
"""
import logging
import threading
from datetime import datetime
from pathlib import Path

_log_path = Path.home() / ".lumi" / "logs" / "terminal.log"
_log_path.parent.mkdir(parents=True, exist_ok=True)

_lock = threading.Lock()


def _write(line: str):
    ts = datetime.now().strftime("%H:%M:%S")
    try:
        with _lock:
            with open(_log_path, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] {line}\n")
    except Exception:
        pass


def log_command_start(argv: list[str], cwd: str | None = None,
                      confirmed: bool = False):
    cmd = " ".join(argv) if isinstance(argv, list) else str(argv)
    tag = " [confirmed]" if confirmed else ""
    location = f"  (cwd={cwd})" if cwd else ""
    _write(f"$ {cmd}{tag}{location}")


def log_command_end(exit_code: int, duration_s: float,
                    stdout: str = "", stderr: str = ""):
    _write(f"  → exit={exit_code} ({duration_s:.2f}s)")
    if stdout:
        first = stdout.strip().splitlines()[:3]
        for line in first:
            _write(f"    | {line[:140]}")
    if stderr:
        first = stderr.strip().splitlines()[:3]
        for line in first:
            _write(f"    ! {line[:140]}")


def log_denied(reason: str, argv: list[str] | None = None):
    cmd = " ".join(argv) if argv else "?"
    _write(f"  ✗ DENIED: {cmd}  — {reason}")


def log_state_change(enabled: bool, paused: bool):
    _write(f"  * terminal enabled={enabled}  paused={paused}")


def get_log_path() -> Path:
    return _log_path