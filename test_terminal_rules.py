"""Quick sanity check for terminal confirm/deny rules. No real commands run."""
from tools import terminal


def show(label, argv, needs, reason):
    want = label == "confirm" or label == "deny"
    got_confirm = bool(needs)
    if label == "confirm":
        ok = got_confirm
    elif label == "safe":
        ok = not got_confirm
    else:
        ok = got_confirm   # for deny we just want it to be caught
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {label:8s} | {' '.join(argv)}")
    if reason:
        print(f"         {reason[:80]}")


def main():
    print("=" * 70)
    print("  TEST 1 — every ADB/fastboot command requires confirmation")
    print("=" * 70)
    adb_cases = [
        ["adb", "devices"],
        ["adb", "version"],
        ["adb", "start-server"],
        ["adb", "install", "app.apk"],
        ["adb", "push", "F:/x", "/sdcard/"],
        ["adb", "pull", "/sdcard/y", "F:/"],
        ["adb", "shell", "ls"],
        ["adb", "reboot"],
        ["fastboot", "devices"],
        ["fastboot", "flash", "boot", "img"],
    ]
    allpass = True
    for argv in adb_cases:
        needs, reason = terminal._needs_confirm({"command": argv})
        if not needs:
            allpass = False
        show("confirm", argv, needs, reason)
    print()
    print("  =>", "ALL CONFIRM" if allpass else "SOME AUTO-RAN (BUG)")
    print()

    print("=" * 70)
    print("  TEST 2 — dangerous adb subcommands are hard-denied")
    print("=" * 70)
    deny_cases = [
        ["adb", "root"],
        ["adb", "shell", "su"],
        ["adb", "remount"],
        ["adb", "disable-verity"],
    ]
    allpass = True
    for argv in deny_cases:
        action, reason = terminal._validate_argv(argv)
        ok = (action == "deny")
        if not ok:
            allpass = False
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {' '.join(argv)}")
        print(f"         {reason[:80]}")
    print()
    print("  =>", "ALL DENIED" if allpass else "SOME ALLOWED (BUG)")
    print()

    print("=" * 70)
    print("  TEST 3 — safe read-only dev tools auto-approve")
    print("=" * 70)
    safe_cases = [
        ["git", "status"],
        ["python", "--version"],
        ["pip", "list"],
        ["dir"],
        ["ls"],
        ["cargo", "--version"],
    ]
    allpass = True
    for argv in safe_cases:
        needs, reason = terminal._needs_confirm({"command": argv})
        if needs:
            allpass = False
        mark = "PASS" if not needs else "FAIL"
        print(f"  [{mark}] {' '.join(argv)}")
    print()
    print("  =>", "ALL AUTO-APPROVE" if allpass else "SOME NEEDLESSLY CONFIRMED (BUG)")
    print()


if __name__ == "__main__":
    main()