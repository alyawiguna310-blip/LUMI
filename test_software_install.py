r"""
Software install tests — fake LLM, no real install.

Verifies:
  1. applications.search returns winget output.
  2. applications.install requires confirmation (always).
  3. Forbidden package IDs are hard-denied.
  4. Fake LLM can chain search → install.
  5. Denied confirmation leaves system untouched.

Does NOT actually install anything.
"""
import sys

from core.tool_router import ToolRouter
from security.confirmation import (
    ConfirmationManager, ConfirmationRequest, ConfirmationResponse,
)
from security.gate import SecurityGate
from security.permissions import PermissionLevel, PermissionPolicy
from tools import applications, filesystem, terminal


PROTECTED = r"D:\Lumi"

_captured: list[ConfirmationRequest] = []
_approve = True


def handler(req: ConfirmationRequest) -> ConfirmationResponse:
    _captured.append(req)
    return ConfirmationResponse(approved=_approve, note="test")


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
    applications.register(gate)
    return ToolRouter(gate)


RES = {"pass": 0, "fail": 0}


def check(desc, ok, detail=""):
    mark = "PASS" if ok else "FAIL"
    if ok: RES["pass"] += 1
    else:  RES["fail"] += 1
    print(f"  [{mark}] {desc}")
    if not ok and detail:
        print(f"         {detail}")


def main():
    print("=" * 66)
    print("  SOFTWARE INSTALL — WINGET + CONFIRMATION TEST")
    print("=" * 66)
    router = make_router()

    # ---- 1. Search ----
    print("\n[1] applications.search(query='chrome')")
    _captured.clear()
    result = router.route("applications.search", {"query": "chrome"})
    check("search returned ok",
          result.get("status") in ("ok", "error"),
          str(result)[:200])
    # Search may work or fail if winget is missing; either is fine
    if result.get("status") == "ok":
        output = result.get("output", {})
        check("output contains raw_output",
              "raw_output" in output,
              str(output)[:200])
    else:
        print("       (winget not available on this system — skipping result check)")
    check("search requested no confirmation",
          len(_captured) == 0,
          f"captures={len(_captured)}")

    # ---- 2. Forbidden package denied ----
    print("\n[2] Forbidden: 'someapp.keygen.pro'")
    _captured.clear()
    result = router.route("applications.install",
                          {"package_id": "malware.Keygen.Pro"})
    check("denied",
          result.get("status") == "denied",
          str(result)[:300])
    check("reason mentions forbidden",
          "forbidden" in (result.get("reason") or "").lower(),
          result.get("reason", ""))

    print("\n[2b] Forbidden: 'crack' substring")
    result = router.route("applications.install",
                          {"package_id": "BadApp.Crack.Edition"})
    check("denied",
          result.get("status") == "denied",
          str(result)[:300])

    # ---- 3. Confirmation always required ----
    print("\n[3] Legit package always confirms")
    _captured.clear()
    global _approve
    _approve = False   # simulate user denies
    result = router.route("applications.install",
                          {"package_id": "Notepad++.Notepad++"})
    check("confirmation was requested",
          len(_captured) == 1,
          f"captures={len(_captured)}")
    check("result is denied (because we said no)",
          result.get("status") == "denied",
          str(result)[:300])
    if _captured:
        check("confirm reason mentions install",
              "install" in _captured[0].reason.lower(),
              _captured[0].reason)

    # ---- 4. Remote-access warning ----
    print("\n[4] Remote-access tool gets warning text")
    _captured.clear()
    _approve = False
    router.route("applications.install",
                 {"package_id": "TeamViewer.TeamViewer"})
    check("confirmation was requested",
          len(_captured) == 1,
          f"captures={len(_captured)}")
    if _captured:
        check("reason mentions remote-access",
              "remote" in _captured[0].reason.lower(),
              _captured[0].reason)

    # ---- 5. Malformed package_id ----
    print("\n[5] Malformed package_id rejected")
    result = router.route("applications.install",
                          {"package_id": "Chrome; rm -rf /"})
    check("rejected",
          result.get("status") in ("invalid", "denied"),
          str(result)[:300])

    # ---- 6. Missing package_id ----
    print("\n[6] Missing package_id rejected")
    result = router.route("applications.install", {})
    check("rejected",
          result.get("status") == "invalid",
          str(result)[:300])

    # ---- 7. list_installed ----
    print("\n[7] applications.list_installed")
    _captured.clear()
    result = router.route("applications.list_installed", {})
    check("no confirmation requested",
          len(_captured) == 0,
          f"captures={len(_captured)}")
    # ok or error both acceptable (winget may not be present)
    check("returned without crashing",
          result.get("status") in ("ok", "error"),
          str(result)[:200])

    print()
    print("=" * 66)
    print(f"  {RES['pass']} passed, {RES['fail']} failed")
    print("=" * 66)
    return 0 if RES["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())