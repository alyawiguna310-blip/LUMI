"""Phase 5F-C validation for the fixed LumiRuntime launcher.

The validator accepts no operational parameters. It is a Windows-only
validation helper and never changes accounts, ACLs, or security policy.
"""
from __future__ import annotations

import json
import os
import sys

import launch_lumi_as_runtime

OUTPUT_PATH = r"D:\Lumi\workspace\phase5fc_identity.json"
MINIMAL_OUTPUT_PATH = r"D:\Lumi\workspace\phase5fc_minimal.txt"
SYSTEM_MINIMAL_OUTPUT_PATH = r"D:\Lumi\workspace\phase5fc_system_minimal.txt"


def _remove_previous():
    for path in (OUTPUT_PATH, MINIMAL_OUTPUT_PATH, SYSTEM_MINIMAL_OUTPUT_PATH):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            print("WARN: could not remove previous file:", path, exc)


def _read_identity():
    with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _report_result(label, result):
    print(label + ":")
    print("  CreateProcessWithLogonW:", "SUCCESS" if result.create_ok else "FAILED")
    if not result.create_ok:
        print("  Win32 error:", result.create_last_error)
    elif result.timed_out:
        print("  Child timed out after", result.wait_seconds, "seconds")
    else:
        print("  Child exit code:", result.exit_code)


def main():
    if len(sys.argv) > 1:
        print("This validator accepts no arguments.")
        return 2
    if sys.platform != "win32":
        print("Phase 5F-C requires Windows.")
        return 3

    _remove_previous()

    probe = launch_lumi_as_runtime.launch_probe()
    _report_result("Probe", probe)
    if probe.timed_out:
        print("Probe timed out; validation cannot continue.")
        return 1
    if not probe.create_ok:
        print("Probe failed to launch. Win32 error:", probe.create_last_error)
        return 1
    if probe.exit_code not in (0,):
        print("Probe exited non-zero:", probe.exit_code)
        return 1
    if not os.path.isfile(OUTPUT_PATH):
        print("Probe did not write", OUTPUT_PATH, "exit code:", probe.exit_code)
        return 1

    try:
        info = _read_identity()
    except Exception as exc:
        print("Could not read identity:", exc)
        return 1

    print("Identity:", json.dumps(info, sort_keys=True))
    if info.get("username") != launch_lumi_as_runtime.RUNTIME_USERNAME:
        print("FAIL: unexpected runtime username")
        return 1
    if info.get("is_elevated"):
        print("FAIL: LumiRuntime is elevated")
        return 1
    if info.get("is_admin_member"):
        print("FAIL: LumiRuntime is an Administrators member")
        return 1

    minimal = launch_lumi_as_runtime.launch_minimal_diagnostic()
    _report_result("Minimal diagnostic", minimal)
    if minimal.timed_out or not minimal.create_ok or minimal.exit_code != 0:
        return 1
    if not os.path.isfile(MINIMAL_OUTPUT_PATH):
        print("Minimal diagnostic did not write", MINIMAL_OUTPUT_PATH,
              "exit code:", minimal.exit_code)
        return 1

    system_minimal = launch_lumi_as_runtime.launch_system_minimal_diagnostic()
    _report_result("System-Python diagnostic", system_minimal)
    if (system_minimal.timed_out or not system_minimal.create_ok
            or system_minimal.exit_code != 0):
        return 1
    if not os.path.isfile(SYSTEM_MINIMAL_OUTPUT_PATH):
        print("System-Python diagnostic did not write",
              SYSTEM_MINIMAL_OUTPUT_PATH,
              "exit code:", system_minimal.exit_code)
        return 1

    print("Phase 5F-C validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
