"""Fixed Phase 5F-C runtime-identity probe.

This probe accepts no caller input, writes only to the fixed workspace
validation paths, and then holds the process briefly so an operator can
inspect the launched identity on Windows.
"""
from __future__ import annotations
import ctypes
import json
import os
import time

OUTPUT_DIR = r"D:\Lumi\workspace"
OUTPUT_PATH = r"D:\Lumi\workspace\phase5fc_identity.json"
DIAG_PATH = r"D:\Lumi\workspace\phase5fc_probe_error.txt"
PROBE_HOLD_SECONDS = 20


def _remove_file_quietly(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def collect():
    username = os.environ.get("USERNAME", "")
    userdomain = os.environ.get("USERDOMAIN", "")
    computername = os.environ.get("COMPUTERNAME", "")
    is_elevated = False
    if os.name == "nt":
        try:
            is_elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_elevated = False
    return {
        "username": username,
        "userdomain": userdomain,
        "computername": computername,
        "sid": "",
        "is_elevated": is_elevated,
        "is_admin_member": is_elevated,
        "pid": os.getpid(),
    }


def _write_diagnostic(exc):
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(DIAG_PATH, "w", encoding="utf-8") as f:
            f.write(type(exc).__name__ + ": " + str(exc))
    except Exception:
        pass


def _write_identity(info):
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        _remove_file_quietly(DIAG_PATH)
        tmp = OUTPUT_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(info, f, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, OUTPUT_PATH)
    except Exception as exc:
        _write_diagnostic(exc)
        try:
            _remove_file_quietly(OUTPUT_PATH + ".tmp")
        except Exception:
            pass
        _write_diagnostic(exc)


def main():
    info = collect()
    _write_identity(info)
    print(json.dumps(info, sort_keys=True), flush=True)
    time.sleep(PROBE_HOLD_SECONDS)


if __name__ == "__main__":
    main()
