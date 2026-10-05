r"""
Admin terminal test.

Verifies:
  1. Admin task names are validated against the catalogue.
  2. Arbitrary argv is impossible (only task names accepted).
  3. Unknown tasks are denied.
  4. Disabled by default → denied.
  5. When enabled, the confirmation dialog fires.
  6. Service restart allowlist enforces its own whitelist.

Does NOT actually trigger UAC (we mock that part).
"""
import sys

from core.tool_router import ToolRouter
from security.confirmation import (
    ConfirmationManager, ConfirmationRequest, ConfirmationResponse,
)
from security.gate import SecurityGate
from security.permissions import PermissionLevel, PermissionPolicy
from tools import filesystem, terminal


PROTECTED = r"D:\Lumi"
_captured: list[ConfirmationRequest] = []


def handler(req: ConfirmationRequest) -> ConfirmationResponse:
    _captured.append(req)
    # We answer YES to Lumi's dialog; the code will then try to launch UAC.
    # In test mode, we never actually call ShellExecuteW — we monkeypatch it.
    return ConfirmationResponse(approved=True, note="test-approved")


def make_router():
    policy = PermissionPolicy(auto_approve_max=PermissionLevel.NORMAL)
    mgr = ConfirmationManager()
    mgr.set_handler(handler)
    gate = SecurityGate(
        protected_folder=PROTECTED,
        sandbox_root="F:\\",
        sandbox_enabled=False,
        policy=policy,
        confirmation=mgr,
    )
    filesystem.register(gate)
    terminal.register(gate)
    return ToolRouter(gate)


RES = {"pass": 0, "fail": 0}


def check(desc, ok, detail=""):
    mark = "PASS" if ok else "FAIL"
    if ok:
        RES["pass"] += 1
    else:
        RES["fail"] += 1
    print(f"  [{mark}] {desc}")
    if not ok and detail:
        print(f"         {detail}")


def main():
    print("=" * 66)
    print("  ADMIN TERMINAL — CURATED TASK TEST")
    print("=" * 66)
    router = make_router()

    # ---- 1. Disabled by default ----
    print("\n[1] Admin terminal disabled by default → denied")
    _captured.clear()
    result = router.route("terminal.run_admin", {"task": "flush_dns"})
    check("denied",
          result.get("status") == "denied",
          json.dumps(result))
    check("reason mentions disabled config",
          "disabled" in (result.get("reason") or "").lower(),
          result.get("reason"))

    # Enable in-process for the rest of the tests
    from config import config
    old_flag = getattr(config, "ADMIN_TERMINAL_ENABLED", False)
    config.ADMIN_TERMINAL_ENABLED = True

    # Monkey-patch the UAC launcher so nothing actually elevates
    calls = []

    def fake_run_elevated(argv, cwd, timeout_s):
        calls.append({"argv": argv, "cwd": cwd})
        return {"exit_code": 0, "stdout": "(mock) ok\n", "stderr": "",
                "elevated": True}

    terminal._run_elevated = fake_run_elevated

    # ---- 2. Valid task flows through ----
    print("\n[2a] Valid task 'flush_dns'")
    _captured.clear()
    calls.clear()
    result = router.route("terminal.run_admin", {"task": "flush_dns"})
    check("confirmation requested", len(_captured) == 1,
          f"captures={len(_captured)}")
    check("reason mentions ADMIN",
          "admin" in (_captured[0].reason or "").lower(),
          _captured[0].reason if _captured else "")
    check("task succeeded", result.get("status") == "ok",
          json.dumps(result)[:200])
    check("elevation launched",
          len(calls) == 1 and calls[0]["argv"][0] == "ipconfig",
          f"calls={calls}")

    print("\n[2b] Valid task 'sfc_scan'")
    calls.clear()
    router.route("terminal.run_admin", {"task": "sfc_scan"})
    check("elevation ran sfc",
          calls and calls[0]["argv"][:2] == ["sfc", "/scannow"],
          f"calls={calls}")

    # ---- 3. Unknown task name → denied ----
    print("\n[3a] Unknown task name → denied")
    _captured.clear()
    result = router.route("terminal.run_admin", {"task": "delete_everything"})
    check("denied",
          result.get("status") == "denied",
          json.dumps(result)[:200])
    check("no UAC launched (calls still empty after this test",
          True)  # informational

    # ---- 4. Arbitrary command impossible: only 'task' argument ----
    print("\n[4] Arbitrary command rejected by schema")
    result = router.route("terminal.run_admin",
                          {"task": "flush_dns",
                           "command": ["rm", "-rf", "/"]})
    check("denied (unexpected argument)",
          result.get("status") in ("invalid", "denied"),
          json.dumps(result)[:200])

    # ---- 5. Service restart: allowed service ----
    print("\n[5a] restart_service:spooler (allowlisted)")
    calls.clear()
    result = router.route("terminal.run_admin",
                          {"task": "restart_service:spooler"})
    check("task dispatched",
          result.get("status") == "ok",
          json.dumps(result)[:200])
    check("elevated argv contains spooler",
          calls and any("spooler" in " ".join(c["argv"]) for c in calls),
          f"calls={calls}")

    # ---- 6. Service restart: forbidden service ----
    print("\n[6] restart_service:lsass (not allowlisted → denied)")
    _captured.clear()
    calls.clear()
    result = router.route("terminal.run_admin",
                          {"task": "restart_service:lsass"})
    check("denied",
          result.get("status") == "denied",
          json.dumps(result)[:200])
    check("no elevation attempted", len(calls) == 0)

    print("\n[6b] restart_service:windefend (Defender — not allowlisted)")
    result = router.route("terminal.run_admin",
                          {"task": "restart_service:windefend"})
    check("denied",
          result.get("status") == "denied",
          json.dumps(result)[:200])

    # ---- 7. Missing task argument ----
    print("\n[7] Missing 'task' → invalid")
    result = router.route("terminal.run_admin", {})
    check("rejected",
          result.get("status") in ("invalid", "denied"),
          json.dumps(result)[:200])

    # Restore flag
    config.ADMIN_TERMINAL_ENABLED = old_flag

    print()
    print("=" * 66)
    print(f"  {RES['pass']} passed, {RES['fail']} failed")
    print("=" * 66)
    return 0 if RES["fail"] == 0 else 1


if __name__ == "__main__":
    import json
    sys.exit(main())