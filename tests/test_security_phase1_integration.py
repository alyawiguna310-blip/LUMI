"""
Phase 1 runtime integration tests.

Exercise the real flow: SecurityGate / ToolRouter -> confirmation ->
executor. Executors are spies; no real subprocess is launched, except
in `test_h5_denial_reaches_toolrouter`, which stubs the elevated-token
guard to guarantee determinism regardless of how pytest was launched.
"""
import json
import sys
from pathlib import Path

import pytest

from security.confirmation import (
    ConfirmationManager, ConfirmationRequest, ConfirmationResponse,
)
from security.descriptor import Origin
from security.gate import SecurityGate, ToolRequest, ToolSpec
from security.permissions import PermissionLevel, PermissionPolicy
from security.path_rules import PathRule


class SpyExecutor:
    def __init__(self, return_value=None):
        self.calls = []
        self._return = return_value if return_value is not None else {"ok": True}

    def __call__(self, args):
        self.calls.append(dict(args))
        return dict(self._return)


def make_gate(tmp_path, protected_dir=None):
    if protected_dir is None:
        protected_dir = tmp_path / "protected_for_tests"
        protected_dir.mkdir(exist_ok=True)
    return SecurityGate(
        protected_folder=str(protected_dir),
        sandbox_root="",
        sandbox_enabled=False,
        policy=PermissionPolicy(
            auto_approve_max=PermissionLevel.NORMAL,
        ),
    )


def register_terminal(gate):
    from tools import terminal as term
    term.register(gate)
    return term


def register_filesystem(gate):
    from tools import filesystem as fs
    fs.register(gate)
    return fs


def deny_handler(req):
    return ConfirmationResponse(approved=False, note="integration-deny")


def approve_handler(req):
    return ConfirmationResponse(approved=True, note="integration-approve")


def _isolate_config(monkeypatch, tmp_path):
    import config as config_module

    protected = tmp_path / "config_protected"
    protected.mkdir(exist_ok=True)
    monkeypatch.setattr(
        config_module.config, "PROTECTED_FOLDER", str(protected)
    )
    monkeypatch.setattr(config_module.config, "SANDBOX_ENABLED", False)
    monkeypatch.setattr(config_module.config, "SANDBOX_ROOT", "")
    return protected


# ============================================================ C1


C1_RISKY_COMMANDS = [
    pytest.param(["python", "-c", "print(1)"], id="python-c"),
    pytest.param(["python", "-m", "http.server"], id="python-m"),
    pytest.param(["py", "-3", "-c", "print(1)"], id="py-3-c"),
    pytest.param(["python", "-"], id="python-stdin"),
    pytest.param(["node", "-e", "console.log(1)"], id="node-e"),
    pytest.param(["python", "myscript"], id="python-extensionless"),
    pytest.param(["python", "-ic", "print(1)"], id="python-combined-ic"),
    pytest.param(["python", "-W", "ignore", "-c", "print(1)"],
                 id="python-value-flag-then-c"),
    pytest.param(["node", "--eval=console.log(1)"], id="node-eval-equals"),
]


@pytest.mark.parametrize("command", C1_RISKY_COMMANDS)
def test_c1_risky_interpreter_denied_through_gate(tmp_path, command):
    gate = make_gate(tmp_path)
    register_terminal(gate)
    spy = SpyExecutor()

    gate.confirmation.set_handler(deny_handler)

    result = gate.execute(
        ToolRequest(
            "terminal.run",
            {"command": list(command), "timeout_s": 5},
            originating_source=Origin.LOCAL_USER.value,
        ),
        spy,
    )

    assert result.denied, f"expected denial for {command}"
    assert result.confirmation_needed is True, (
        f"denial for {command} must come from the confirmation step"
    )
    assert len(spy.calls) == 0, f"executor must not be called for {command}"


def test_c1_harmless_version_auto_approves(tmp_path):
    gate = make_gate(tmp_path)
    register_terminal(gate)
    spy = SpyExecutor(return_value={"exit_code": 0, "stdout": "ok"})

    gate.confirmation.set_handler(deny_handler)

    result = gate.execute(
        ToolRequest(
            "terminal.run",
            {"command": ["python", "--version"], "timeout_s": 5},
            originating_source=Origin.LOCAL_USER.value,
        ),
        spy,
    )

    assert not result.denied
    assert result.success is True
    assert len(spy.calls) == 1


def test_c1_toolrouter_python_c_denied(tmp_path, monkeypatch):
    _isolate_config(monkeypatch, tmp_path)

    from core.tool_router import ToolRouter
    from tools import terminal as term

    gate = SecurityGate(
        protected_folder=str(tmp_path / "config_protected"),
        sandbox_enabled=False,
    )
    term.register(gate)
    gate.confirmation.set_handler(deny_handler)

    router = ToolRouter(gate)
    spy = SpyExecutor()
    router._executors["terminal.run"] = spy

    result = router.route(
        "terminal.run",
        {"command": ["python", "-c", "print(1)"], "timeout_s": 5},
    )

    assert result["ok"] is False
    assert result["status"] == "denied"
    assert len(spy.calls) == 0


# ============================================================ C2


C2_MATRIX = [
    pytest.param("allow", "confirm", "confirm", id="allow+confirm"),
    pytest.param("confirm", "allow", "confirm", id="confirm+allow"),
    pytest.param("deny", "allow", "deny", id="deny+allow"),
    pytest.param("allow", "deny", "deny", id="allow+deny"),
    pytest.param("deny", "confirm", "deny", id="deny+confirm"),
    pytest.param("confirm", "deny", "deny", id="confirm+deny"),
]


@pytest.mark.parametrize("src_action,dest_action,expected", C2_MATRIX)
def test_c2_matrix(tmp_path, monkeypatch, src_action, dest_action, expected):
    from security import path_rules as pr

    src_dir = tmp_path / "src_dir"
    dest_dir = tmp_path / "dest_dir"
    src_dir.mkdir()
    dest_dir.mkdir()

    monkeypatch.setattr(
        pr, "PATH_RULES",
        [
            PathRule(str(src_dir), src_action, "src rule"),
            PathRule(str(dest_dir), dest_action, "dest rule"),
        ],
        raising=True,
    )

    gate = make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.move",
        level=PermissionLevel.DISRUPTIVE,
        path_params=["src", "dest"],
        description="two-path tool for C2 matrix",
    ))

    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=False, note="matrix deny")

    gate.confirmation.set_handler(handler)
    spy = SpyExecutor()

    result = gate.execute(
        ToolRequest("fake.move", {
            "src": str(src_dir / "a"),
            "dest": str(dest_dir / "b"),
        }, originating_source=Origin.LOCAL_USER.value),
        spy,
    )

    if expected == "deny":
        assert result.denied
        assert len(spy.calls) == 0
        assert len(calls) == 0
    elif expected == "confirm":
        assert result.denied
        assert result.confirmation_needed is True
        assert len(spy.calls) == 0
        assert len(calls) == 1


# ============================================================ C3


def test_c3_ordinary_forceable_auto_approves(tmp_path):
    gate = make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=[],
        description="normal forceable operation",
    ))
    gate.confirmation.enable_force(seconds=10, reason="test")

    called = []

    def handler(req):
        called.append(req)
        return ConfirmationResponse(approved=True, note="never reached")

    gate.confirmation.set_handler(handler)

    spy = SpyExecutor()
    result = gate.execute(
        ToolRequest("fake.write", {},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )

    assert not result.denied
    assert len(spy.calls) == 1
    assert len(called) == 0


def test_c3_normal_path_write_is_forceable(tmp_path):
    gate = make_gate(tmp_path)
    register_filesystem(gate)
    gate.confirmation.enable_force(seconds=10, reason="test")

    called = []

    def handler(req):
        called.append(req)
        return ConfirmationResponse(approved=False, note="denied")

    gate.confirmation.set_handler(handler)

    spy = SpyExecutor()
    result = gate.execute(
        ToolRequest("filesystem.write", {
            "path": "C:\\lumi_test_normal\\file.txt",
            "content": "hi",
        }, originating_source=Origin.LOCAL_USER.value),
        spy,
    )

    assert not result.denied
    assert len(spy.calls) == 1
    assert len(called) == 0


def test_c3_confirm_if_blocks_force(tmp_path):
    gate = make_gate(tmp_path)
    register_terminal(gate)
    gate.confirmation.enable_force(seconds=10, reason="test")

    called = []

    def handler(req):
        called.append(req)
        return ConfirmationResponse(approved=False, note="denied")

    gate.confirmation.set_handler(handler)

    spy = SpyExecutor()
    result = gate.execute(
        ToolRequest(
            "terminal.run",
            {"command": ["adb", "devices"], "timeout_s": 5},
            originating_source=Origin.LOCAL_USER.value,
        ),
        spy,
    )

    assert result.denied
    assert result.confirmation_needed is True
    assert len(spy.calls) == 0
    assert len(called) == 1
    assert called[0].forceable is False


def test_c3_system_looking_blocks_force(tmp_path):
    gate = make_gate(tmp_path)
    register_filesystem(gate)
    gate.confirmation.enable_force(seconds=10, reason="test")

    called = []

    def handler(req):
        called.append(req)
        return ConfirmationResponse(approved=False, note="denied")

    gate.confirmation.set_handler(handler)

    spy = SpyExecutor()
    result = gate.execute(
        ToolRequest("filesystem.write", {
            "path": "C:\\lumi_test\\System32\\file.txt",
            "content": "hi",
        }, originating_source=Origin.LOCAL_USER.value),
        spy,
    )

    assert result.denied
    assert len(spy.calls) == 0
    assert len(called) == 1
    assert called[0].forceable is False


def test_c3_path_rule_confirm_blocks_force(tmp_path, monkeypatch):
    from security import path_rules as pr

    confirm_dir = tmp_path / "confirmzone"
    confirm_dir.mkdir()

    monkeypatch.setattr(
        pr, "PATH_RULES",
        [PathRule(str(confirm_dir), "confirm", "test confirm rule")],
        raising=True,
    )

    gate = make_gate(tmp_path)
    gate.register_tool(ToolSpec(
        name="fake.write",
        level=PermissionLevel.DISRUPTIVE,
        path_params=["path"],
        description="path-rule test",
    ))
    gate.confirmation.enable_force(seconds=10, reason="test")

    called = []

    def handler(req):
        called.append(req)
        return ConfirmationResponse(approved=False, note="denied")

    gate.confirmation.set_handler(handler)

    spy = SpyExecutor()
    result = gate.execute(
        ToolRequest("fake.write", {"path": str(confirm_dir / "x.txt")},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )

    assert result.denied
    assert len(spy.calls) == 0
    assert len(called) == 1
    assert called[0].forceable is False


def test_c3_never_force_blocks_force(tmp_path):
    gate = make_gate(tmp_path)
    register_filesystem(gate)
    gate.confirmation.enable_force(seconds=10, reason="test")

    called = []

    def handler(req):
        called.append(req)
        return ConfirmationResponse(approved=False, note="denied")

    gate.confirmation.set_handler(handler)

    spy = SpyExecutor()
    result = gate.execute(
        ToolRequest("filesystem.delete",
                    {"path": "C:\\lumi_test_normal\\unused.txt"},
                    originating_source=Origin.LOCAL_USER.value),
        spy,
    )

    assert result.denied
    assert len(spy.calls) == 0
    assert len(called) == 1


# ============================================================ C4


def _write_lines(path: Path, lines):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_c4_tamper_body_only(tmp_path):
    from storage.audit import _AuditSink
    p = tmp_path / "a.log"
    s = _AuditSink(p)
    assert s._usable
    s.write("test.one", {"k": 1})
    s.write("test.two", {"k": 2})
    s.close()

    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["k"] = 999
    lines[0] = json.dumps(rec)
    _write_lines(p, lines)

    s2 = _AuditSink(p)
    try:
        _, ok = s2._verify_chain()
        assert ok is False
    finally:
        s2.close()


def test_c4_tamper_hash_only(tmp_path):
    from storage.audit import _AuditSink
    p = tmp_path / "b.log"
    s = _AuditSink(p)
    s.write("test.one", {"k": 1})
    s.close()
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["hash"] = "f" * 64
    lines[0] = json.dumps(rec)
    _write_lines(p, lines)
    s2 = _AuditSink(p)
    try:
        _, ok = s2._verify_chain()
        assert ok is False
    finally:
        s2.close()


def test_c4_tamper_prev_hash_only(tmp_path):
    from storage.audit import _AuditSink
    p = tmp_path / "c.log"
    s = _AuditSink(p)
    s.write("test.one", {"k": 1})
    s.close()
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["prev_hash"] = "f" * 64
    lines[0] = json.dumps(rec)
    _write_lines(p, lines)
    s2 = _AuditSink(p)
    try:
        _, ok = s2._verify_chain()
        assert ok is False
    finally:
        s2.close()


def test_c4_truncated_record(tmp_path):
    from storage.audit import _AuditSink
    p = tmp_path / "d.log"
    s = _AuditSink(p)
    s.write("test.one", {"k": 1})
    s.write("test.two", {"k": 2})
    s.close()
    content = p.read_text(encoding="utf-8")
    lines = content.splitlines(keepends=True)
    lines[1] = lines[1][: len(lines[1]) // 2]
    p.write_text("".join(lines), encoding="utf-8")
    s2 = _AuditSink(p)
    try:
        _, ok = s2._verify_chain()
        assert ok is False
    finally:
        s2.close()


def test_c4_malformed_json_line(tmp_path):
    from storage.audit import _AuditSink
    p = tmp_path / "e.log"
    s = _AuditSink(p)
    s.write("test.one", {"k": 1})
    s.close()
    with open(p, "a", encoding="utf-8") as f:
        f.write("this is not valid json\n")
    s2 = _AuditSink(p)
    try:
        _, ok = s2._verify_chain()
        assert ok is False
    finally:
        s2.close()


def test_c4_restart_accepts_intact_chain(tmp_path):
    from storage.audit import _AuditSink
    p = tmp_path / "f.log"
    s = _AuditSink(p)
    s.write("test.one", {"k": 1})
    s.write("test.two", {"k": 2})
    s.write("test.three", {"k": 3})
    last_hash = s._prev_hash
    s.close()

    s2 = _AuditSink(p)
    try:
        last2, ok = s2._verify_chain()
        assert ok is True
        assert last2 == last_hash
        s2.write("test.four", {"k": 4})
    finally:
        s2.close()

    s3 = _AuditSink(p)
    try:
        _, ok = s3._verify_chain()
        assert ok is True
    finally:
        s3.close()


# ============================================================ C4 Windows sharing


def _ctypes_create_file_w():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    return ctypes, wintypes, k32


def _try_open_for_write_win(path: str) -> bool:
    ctypes, wintypes, k32 = _ctypes_create_file_w()
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    INVALID = ctypes.c_void_p(-1).value
    h = k32.CreateFileW(str(path), GENERIC_WRITE, 0, None,
                        OPEN_EXISTING, 0, None)
    if h == INVALID or not h:
        return False
    k32.CloseHandle(h)
    return True


def _try_open_for_delete_win(path: str) -> bool:
    ctypes, wintypes, k32 = _ctypes_create_file_w()
    DELETE = 0x00010000
    OPEN_EXISTING = 3
    INVALID = ctypes.c_void_p(-1).value
    h = k32.CreateFileW(str(path), DELETE, 0, None, OPEN_EXISTING, 0, None)
    if h == INVALID or not h:
        return False
    k32.CloseHandle(h)
    return True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
def test_c4_windows_sharing_violation(tmp_path):
    from storage.audit import _AuditSink
    p = tmp_path / "sharing.log"
    sink = _AuditSink(p)
    assert sink._usable

    try:
        sink.write("test.sharing", {"k": 1})
        assert p.exists()

        write_allowed = _try_open_for_write_win(str(p))
        delete_allowed = _try_open_for_delete_win(str(p))

        assert write_allowed is False, "external write must be rejected"
        assert delete_allowed is False, "external delete must be rejected"

        try:
            with open(p, "w") as f:
                f.write("tamper")
            plain_write_blocked = False
        except OSError:
            plain_write_blocked = True
        assert plain_write_blocked

        try:
            import os as _os
            _os.remove(str(p))
            plain_remove_blocked = False
        except OSError:
            plain_remove_blocked = True
        assert plain_remove_blocked

        assert p.exists()
    finally:
        sink.close()

    import os as _os
    _os.remove(str(p))
    assert not p.exists()


# ============================================================ H5


def test_h5_protected_module_import_failure_denies(monkeypatch):
    import types
    fake = types.ModuleType("security.protected_paths")
    monkeypatch.setitem(sys.modules, "security.protected_paths", fake)
    from tools import terminal as t
    result = t._validate_paths_against_gate(["F:\\some\\path.txt"])
    assert result is not None
    assert result.get("denied") is True


def test_h5_sandbox_module_import_failure_denies(monkeypatch):
    import types
    fake = types.ModuleType("security.sandbox")
    monkeypatch.setitem(sys.modules, "security.sandbox", fake)
    from tools import terminal as t
    result = t._validate_paths_against_gate(["F:\\some\\path.txt"])
    assert result is not None
    assert result.get("denied") is True


def test_h5_denial_reaches_toolrouter(tmp_path, monkeypatch):
    """A terminal command whose argv contains a path inside the
    protected folder must be denied, and that denial must propagate all
    the way through ToolRouter.route.

    The elevated-token guard in tools/terminal.py would normally refuse
    any terminal command when the caller is running as Administrator.
    That guard is orthogonal to what this test exercises, so it is
    stubbed to False for the duration of this test. The production
    guard itself is unchanged and remains exercised by the runtime
    path.
    """
    _isolate_config(monkeypatch, tmp_path)

    import config as config_module
    from core.tool_router import ToolRouter
    from tools import terminal as term

    # Pin the elevated-token precondition so the code path reaches the
    # protected-path check regardless of how pytest was launched.
    monkeypatch.setattr(
        term, "_is_currently_elevated", lambda: False, raising=True,
    )

    protected = Path(config_module.config.PROTECTED_FOLDER)
    inside = protected / "script.py"

    gate = SecurityGate(
        protected_folder=str(protected),
        sandbox_enabled=False,
    )
    term.register(gate)
    gate.confirmation.set_handler(approve_handler)

    router = ToolRouter(gate)

    result = router.route("terminal.run", {
        "command": ["python", str(inside)],
        "timeout_s": 5,
    })

    assert result["ok"] is False
    assert result["status"] == "denied"
    reason = (result.get("reason") or "").lower()
    assert "protected" in reason or "sandbox" in reason


# ============================================================ H


def test_h_invariant_ai_cannot_self_authorize(tmp_path):
    gate = make_gate(tmp_path)
    register_terminal(gate)
    gate.confirmation.set_handler(deny_handler)

    spy = SpyExecutor(
        return_value={"exit_code": 0, "stdout": "must not run"}
    )

    result = gate.execute(
        ToolRequest(
            "terminal.run",
            {"command": ["python", "-c", "print('side effect')"],
             "timeout_s": 5},
            originating_source=Origin.LOCAL_USER.value,
        ),
        spy,
    )

    assert result.denied is True
    assert result.confirmation_needed is True
    assert len(spy.calls) == 0


def test_h_invariant_toolrouter_denial_chain(tmp_path, monkeypatch):
    _isolate_config(monkeypatch, tmp_path)

    from core.tool_router import ToolRouter
    from tools import terminal as term

    gate = SecurityGate(
        protected_folder=str(tmp_path / "config_protected"),
        sandbox_enabled=False,
    )
    term.register(gate)
    gate.confirmation.set_handler(deny_handler)

    router = ToolRouter(gate)
    spy = SpyExecutor()
    router._executors["terminal.run"] = spy

    result = router.route("terminal.run", {
        "command": ["python", "-c", "print(1)"],
        "timeout_s": 5,
    })

    assert result["ok"] is False
    assert result["status"] == "denied"
    assert result.get("confirmation_needed") is True
    assert len(spy.calls) == 0


def test_h_invariant_force_is_not_universal_bypass(tmp_path):
    gate = make_gate(tmp_path)
    register_filesystem(gate)
    gate.confirmation.enable_force(seconds=10, reason="invariant-test")
    gate.confirmation.set_handler(deny_handler)

    spy = SpyExecutor()
    result = gate.execute(
        ToolRequest("filesystem.write", {
            "path": "C:\\lumi_test\\System32\\bootstrap.txt",
            "content": "irrelevant",
        }, originating_source=Origin.LOCAL_USER.value),
        spy,
    )

    assert result.denied is True
    assert len(spy.calls) == 0