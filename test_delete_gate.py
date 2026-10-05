r"""
Security Gate test against REAL files on F:\.

By default runs in DRY-RUN mode — nothing is actually deleted.
Pass --live to actually delete files the gate approves.

Usage:
    python test_delete_gate.py            # dry-run (safe, default)
    python test_delete_gate.py --live     # actually delete approved files
    python test_delete_gate.py --all      # more aggressive discovery
"""
import argparse
import os
import sys
from pathlib import Path

from security.confirmation import (
    ConfirmationManager, ConfirmationRequest, ConfirmationResponse,
)
from security.gate import SecurityGate, ToolRequest
from security.permissions import PermissionLevel, PermissionPolicy
from tools import filesystem


# -------- settings --------

SANDBOX_ROOT = "F:\\"
PROTECTED_FOLDER = "D:\\"

# Folders to scan for test targets (in priority order)
DISCOVERY_ROOTS = [
    r"F:\TestProject",
    r"F:\ImportantFiles",
    r"F:\FakeWindows",
    r"F:\FakeViruses",
    r"F:\BrokenPython",
    r"F:\Windows",
]

# Skip files bigger than this (don't test 500MB files)
MAX_FILE_SIZE = 50 * 1024 * 1024   # 50 MB

# Files that we never target even in --live mode (safety net in the script)
# The gate will still be the final authority, but this avoids accidents.
SKIP_NAMES = {
    "bootmgr", "bootnxt", "bcd",
    "pagefile.sys", "hiberfil.sys", "swapfile.sys",
}


# -------- confirmation UI --------

def console_confirm(req: ConfirmationRequest) -> ConfirmationResponse:
    print()
    print("  ┌── CONFIRMATION REQUESTED ─────────────────────────")
    print(f"  │ Tool:   {req.tool_name}")
    print(f"  │ Path:   {req.arguments.get('path')}")
    print(f"  │ Level:  {req.level_name}")
    print(f"  │ Reason: {req.reason}")
    print("  └───────────────────────────────────────────────────")
    try:
        ans = input("  Allow? [y/N]: ").strip().lower()
    except EOFError:
        ans = "n"
    return ConfirmationResponse(approved=(ans == "y"))


# -------- dry-run executor --------

class DryRunExecutor:
    """
    Wraps the real delete and, in dry-run mode, returns a fake result
    without touching disk. In live mode, calls the real deleter.
    """
    def __init__(self, live: bool):
        self.live = live
        self.deleted: list[str] = []

    def __call__(self, args: dict) -> dict:
        path = args["path"]
        if not self.live:
            return {"deleted": False, "dry_run": True, "would_delete": path}
        # live
        result = filesystem._do_delete(args)
        if result.get("deleted"):
            self.deleted.append(path)
        return result


# -------- discovery --------

def discover_targets() -> dict[str, list[str]]:
    """
    Walk the discovery roots and return a categorized dict of paths.
    Categories:
      workspace         — TestProject
      system_looking    — FakeWindows, Windows, system-looking extensions
      suspicious        — FakeViruses
      important         — ImportantFiles
      source            — BrokenPython (py files)
    """
    buckets = {
        "workspace": [],
        "system_looking": [],
        "suspicious": [],
        "important": [],
        "source": [],
    }

    for root_str in DISCOVERY_ROOTS:
        root = Path(root_str)
        if not root.exists():
            continue

        for p in root.rglob("*"):
            if not p.is_file():
                continue
            try:
                size = p.stat().st_size
            except Exception:
                continue
            if size > MAX_FILE_SIZE:
                continue
            if p.name.lower() in SKIP_NAMES:
                continue

            path_str = str(p)
            r = root_str.lower()
            low = path_str.lower()

            if "testproject" in r:
                buckets["workspace"].append(path_str)
            elif "importantfiles" in r:
                buckets["important"].append(path_str)
            elif "fakeviruses" in r:
                buckets["suspicious"].append(path_str)
            elif "brokenpython" in r:
                buckets["source"].append(path_str)
            elif "fakewindows" in r or low.startswith(r"f:\windows"):
                buckets["system_looking"].append(path_str)
            else:
                # Generic fallback — treat as system-looking if it has a
                # system extension, otherwise skip.
                if p.suffix.lower() in (".dll", ".sys", ".exe", ".scr", ".msi"):
                    buckets["system_looking"].append(path_str)

    return buckets


# -------- test scenarios --------

def build_scenarios(buckets: dict[str, list[str]], max_per_bucket: int = 4):
    """
    Produce a list of (description, path, expected) test cases.
    Real files come first, plus hardcoded outside-sandbox and traversal tests.
    """
    scenarios: list[tuple[str, str, str]] = []

    # --- Real files inside sandbox ---
    for path in buckets["workspace"][:max_per_bucket]:
        scenarios.append((
            f"[TestProject] {Path(path).name}",
            path,
            "allow (no confirmation)",
        ))
    for path in buckets["system_looking"][:max_per_bucket]:
        scenarios.append((
            f"[Windows/system-looking] {Path(path).name}",
            path,
            "confirm",
        ))
    for path in buckets["suspicious"][:max_per_bucket]:
        scenarios.append((
            f"[FakeViruses] {Path(path).name}",
            path,
            "confirm",
        ))
    for path in buckets["important"][:max_per_bucket]:
        scenarios.append((
            f"[ImportantFiles] {Path(path).name}",
            path,
            "confirm",
        ))
    for path in buckets["source"][:max_per_bucket]:
        scenarios.append((
            f"[BrokenPython] {Path(path).name}",
            path,
            "confirm",
        ))

    # --- Drive root ---
    scenarios.append((
        "[F:\\] drive root",
        "F:\\",
        "deny (path rule)",
    ))

    # --- OUTSIDE SANDBOX (critical) ---
    scenarios.extend([
        ("[C:\\] Windows System32",
         r"C:\Windows\System32\kernel32.dll",
         "DENY — outside sandbox, NO prompt"),
        ("[C:\\] Windows whole folder",
         r"C:\Windows",
         "DENY — outside sandbox, NO prompt"),
        ("[C:\\] Users",
         r"C:\Users",
         "DENY — outside sandbox, NO prompt"),
        ("[C:\\] Program Files",
         r"C:\Program Files",
         "DENY — outside sandbox, NO prompt"),
        ("[D:\\] Lumi source",
         r"D:\Lumi\main.py",
         "DENY — outside sandbox, NO prompt"),
        ("[D:\\] whole drive",
         "D:\\",
         "DENY — outside sandbox, NO prompt"),
        ("[UNC] network share",
         r"\\server\share\file.txt",
         "DENY — outside sandbox, NO prompt"),
    ])

    # --- Traversal ---
    scenarios.extend([
        ("[traversal] F:\\..\\Windows",
         r"F:\..\Windows\notepad.exe",
         "resolves to F:\\Windows — confirm"),
        ("[traversal] relative ..\\..\\",
         r"..\..\Windows\notepad.exe",
         "DENY — resolves outside F:\\"),
        ("[traversal] null byte attempt",
         "F:\\TestProject\\..\\..\\Windows\\notepad.exe",
         "resolves to F:\\Windows — confirm"),
    ])

    return scenarios


# -------- main --------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="actually delete approved files (default: dry-run)")
    ap.add_argument("--all", action="store_true",
                    help="scan more files per bucket")
    args = ap.parse_args()

    live = args.live
    per_bucket = 10 if args.all else 4

    print("=" * 64)
    print("  LUMI SECURITY GATE — REAL-FILE TEST")
    print("=" * 64)
    print(f"  Mode:     {'LIVE — files WILL be deleted' if live else 'DRY-RUN — files will NOT be deleted'}")
    print(f"  Sandbox:  {SANDBOX_ROOT}")
    print(f"  Protected:{PROTECTED_FOLDER}")
    print()

    # Build gate
    policy = PermissionPolicy(auto_approve_max=PermissionLevel.NORMAL)
    confirmation = ConfirmationManager()
    confirmation.set_handler(console_confirm)

    gate = SecurityGate(
        protected_folder=PROTECTED_FOLDER,
        sandbox_root=SANDBOX_ROOT,
        sandbox_enabled=True,
        policy=policy,
        confirmation=confirmation,
    )
    filesystem.register(gate)

    # Discover real files
    print("Discovering files on F:\\...")
    buckets = discover_targets()
    total_found = sum(len(v) for v in buckets.values())
    for name, files in buckets.items():
        print(f"  {name:16s}: {len(files)} file(s)")
    print(f"  {'TOTAL':16s}: {total_found}")
    print()

    if total_found == 0:
        print("No files found. Did F:\\ get emptied? Aborting.")
        sys.exit(1)

    # Build scenarios
    scenarios = build_scenarios(buckets, max_per_bucket=per_bucket)

    print(f"Running {len(scenarios)} scenarios...")
    print("─" * 64)

    executor = DryRunExecutor(live=live)
    counters = {"executed": 0, "denied": 0, "failed": 0}

    for i, (desc, path, expected) in enumerate(scenarios, 1):
        print(f"\n[{i}/{len(scenarios)}] {desc}")
        print(f"     path:   {path}")
        print(f"     expect: {expected}")

        result = filesystem.delete_file(path, gate) if False else gate.execute(
            ToolRequest(tool_name="filesystem.delete", arguments={"path": path}),
            executor=executor,
        )

        if result.denied:
            counters["denied"] += 1
            print(f"     → DENIED:   {result.denial_reason}")
        elif result.success:
            counters["executed"] += 1
            if live:
                print(f"     → EXECUTED: {result.output}")
            else:
                print(f"     → DRY-RUN:  would have deleted {path}")
        else:
            counters["failed"] += 1
            print(f"     → FAILED:   {result.error}")

    print()
    print("─" * 64)
    print(f"Summary: {counters['executed']} executed/approved, "
          f"{counters['denied']} denied, {counters['failed']} failed")
    if not live:
        print()
        print("⚠  This was a DRY-RUN. No files were deleted.")
        print("   Re-run with --live to actually execute approved deletions.")
    print()
    print(f"Audit log: %USERPROFILE%\\.lumi\\logs\\audit.log")
    print(f"View last 60 lines:  Get-Content $env:USERPROFILE\\.lumi\\logs\\audit.log -Tail 60")
    print()


if __name__ == "__main__":
    sys.exit(main())