"""Phase 5F-B OS ACL probe.

Runs under LumiRuntime and verifies that the Windows ACL blocks mutation of
the Lumi control plane while leaving the normal workspace writable.

This probe takes no arguments and uses only fixed paths.
"""
from __future__ import annotations

import json
import os
import sys

PROJECT_ROOT = r"D:\Lumi"
SECURITY_DIR = os.path.join(PROJECT_ROOT, "security")
MAIN_PATH = os.path.join(PROJECT_ROOT, "main.py")
ENV_PATH = os.path.join(PROJECT_ROOT, ".env")
WORKSPACE_DIR = os.path.join(PROJECT_ROOT, "workspace")
RESULT_PATH = os.path.join(WORKSPACE_DIR, "phase5fb_acl_result.json")
CREATE_TEST_PATH = os.path.join(SECURITY_DIR, "_phase5fb_acl_probe.tmp")


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
        ("main_py_write_open", MAIN_PATH),
        ("env_write_open", ENV_PATH),
    ):
        if not os.path.isfile(path):
            checks[label] = (False, "target file does not exist")
        else:
            checks[label] = _test_file_write_open(path)

    checks["workspace_write"] = _test_workspace_write()

    result = {
        "username": os.environ.get("USERNAME", ""),
        "checks": {k: {"passed": v[0], "detail": v[1]} for k, v in checks.items()},
        "passed": all(v[0] for v in checks.values()),
    }

    try:
        _write_result(result)
    except Exception as exc:
        print(f"FAIL: could not write probe result: {type(exc).__name__}: {exc}")
        return 2

    print(json.dumps(result, sort_keys=True))
    sys.stdout.flush()
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
