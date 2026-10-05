"""Regression tests for Phase 1 security fixes (C1, C2, C3, C4, H5).

These tests are pure unit tests. They do not launch the GUI, do not
touch the network, and do not depend on any AI provider.
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
from security.permissions import PermissionLevel
from security.path_rules import PathRule


# ============================================================ C1


def test_c1_python_dash_c_confirms():
    from tools.terminal import _needs_confirm
    ok, why = _needs_confirm({"command": ["python", "-c", "print(1)"]})
    assert ok is True and why


def test_c1_python_dash_m_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm({"command": ["python", "-m", "http.server"]})
    assert ok is True


def test_c1_python3_dash_c_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm({"command": ["python3", "-c", "print(1)"]})
    assert ok is True


def test_c1_py_dash_3_dash_c_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm({"command": ["py", "-3", "-c", "print(1)"]})
    assert ok is True


def test_c1_python_W_ignore_dash_c_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm(
        {"command": ["python", "-W", "ignore", "-c", "print(1)"]}
    )
    assert ok is True


def test_c1_python_combined_ic_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm({"command": ["python", "-ic", "print(1)"]})
    assert ok is True


def test_c1_python_combined_mc_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm({"command": ["python", "-mc", "code"]})
    assert ok is True


def test_c1_python_dash_stdin_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm({"command": ["python", "-"]})
    assert ok is True


def test_c1_python_extensionless_script_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm({"command": ["python", "myscript"]})
    assert ok is True


def test_c1_node_dash_e_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm({"command": ["node", "-e", "console.log(1)"]})
    assert ok is True


def test_c1_node_long_eval_with_equals_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm(
        {"command": ["node", "--eval=console.log(1)"]}
    )
    assert ok is True


def test_c1_node_long_require_with_equals_confirms():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm(
        {"command": ["node", "--require=./x.js"]}
    )
    assert ok is True


def test_c1_python_version_does_not_confirm():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm({"command": ["python", "--version"]})
    assert ok is False


def test_c1_python_script_with_extension_still_confirms_via_extension_rule():
    from tools.terminal import _needs_confirm
    ok, _ = _needs_confirm({"command": ["python", "script.py"]})
    assert ok is True


# ============================================================ C2


def _register_two_path_tool(gate):
    gate.register_tool(ToolSpec(
        name="fake.move",
        level=PermissionLevel.DISRUPTIVE,
        path_params=["src", "dest"],
        description="test two-path tool",
    ))


def _make_gate(tmp_path, monkeypatch, rules):
    import security.path_rules as pr
    monkeypatch.setattr(pr, "PATH_RULES", rules, raising=True)
    gate = SecurityGate(
        protected_folder=str(tmp_path / "protected"),
        sandbox_enabled=False,
    )
    _register_two_path_tool(gate)
    return gate


def test_c2_allow_then_confirm_still_confirms(tmp_path, monkeypatch):
    allow_dir = tmp_path / "allowed"
    confirm_dir = tmp_path / "confirmzone"
    allow_dir.mkdir()
    confirm_dir.mkdir()

    rules = [
        PathRule(str(allow_dir), "allow", "test allowed"),
        PathRule(str(confirm_dir), "confirm", "test confirm"),
    ]
    gate = _make_gate(tmp_path, monkeypatch, rules)

    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=False, note="test deny")

    gate.confirmation.set_handler(handler)

    result = gate.execute(
        ToolRequest("fake.move", {
            "src": str(allow_dir / "a"),
            "dest": str(confirm_dir / "b"),
        }, originating_source=Origin.LOCAL_USER.value),
        lambda args: {"moved": True},
    )
    assert result.denied, (
        "confirm-rule on dest must not be masked by allow on src"
    )
    assert len(calls) == 1


def test_c2_confirm_then_allow_still_confirms(tmp_path, monkeypatch):
    allow_dir = tmp_path / "allowed"
    confirm_dir = tmp_path / "confirmzone"
    allow_dir.mkdir()
    confirm_dir.mkdir()

    rules = [
        PathRule(str(allow_dir), "allow", "test allowed"),
        PathRule(str(confirm_dir), "confirm", "test confirm"),
    ]
    gate = _make_gate(tmp_path, monkeypatch, rules)

    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=False, note="deny")

    gate.confirmation.set_handler(handler)

    result = gate.execute(
        ToolRequest("fake.move", {
            "src": str(confirm_dir / "a"),
            "dest": str(allow_dir / "b"),
        }, originating_source=Origin.LOCAL_USER.value),
        lambda args: {"moved": True},
    )
    assert result.denied
    assert len(calls) == 1


# ============================================================ C3


def _make_mgr():
    mgr = ConfirmationManager(timeout_seconds=5)
    calls = []

    def handler(req):
        calls.append(req)
        return ConfirmationResponse(approved=False, note="handler")

    mgr.set_handler(handler)
    return mgr, calls


def test_c3_force_does_not_bypass_non_forceable():
    mgr, calls = _make_mgr()
    mgr.enable_force(seconds=10, reason="test")
    req = ConfirmationRequest(
        tool_name="terminal.run",
        arguments={"command": ["adb", "devices"]},
        level_name="normal",
        reason="adb requires confirmation",
        forceable=False,
    )
    resp = mgr.request(req)
    assert resp.approved is False
    assert len(calls) == 1


def test_c3_force_does_not_bypass_never_force_tool():
    mgr, calls = _make_mgr()
    mgr.enable_force(seconds=10, reason="test")
    req = ConfirmationRequest(
        tool_name="filesystem.delete",
        arguments={"path": "F:\\x"},
        level_name="destructive",
        reason="delete",
        forceable=True,
    )
    resp = mgr.request(req)
    assert resp.approved is False
    assert len(calls) == 1


def test_c3_force_short_circuits_ordinary_forceable():
    mgr, calls = _make_mgr()
    mgr.enable_force(seconds=10, reason="test")
    req = ConfirmationRequest(
        tool_name="filesystem.write",
        arguments={"path": "F:\\TestProject\\x"},
        level_name="disruptive",
        reason="write",
        forceable=True,
    )
    resp = mgr.request(req)
    assert resp.approved is True
    assert len(calls) == 0


# ============================================================ C4


def test_c4_fresh_chain_writes_and_verifies(tmp_path):
    from storage.audit import _AuditSink
    sink = _AuditSink(tmp_path / "a.log")
    assert sink._usable
    sink.write("test.one", {"k": 1})
    sink.write("test.two", {"k": 2})
    sink.close()

    sink2 = _AuditSink(tmp_path / "a.log")
    last, ok = sink2._verify_chain()
    assert ok is True
    assert last != "0" * 64
    sink2.close()


def test_c4_chain_links_records(tmp_path):
    from storage.audit import _AuditSink
    sink = _AuditSink(tmp_path / "b.log")
    sink.write("test.one", {"k": 1})
    h1 = sink._prev_hash
    sink.write("test.two", {"k": 2})
    h2 = sink._prev_hash
    sink.close()

    assert h1 != h2

    with open(tmp_path / "b.log", "r", encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    assert len(lines) == 2
    assert lines[1]["prev_hash"] == lines[0]["hash"]


def test_c4_tamper_is_detected(tmp_path):
    from storage.audit import _AuditSink
    p = tmp_path / "c.log"
    sink = _AuditSink(p)
    sink.write("test.one", {"k": 1})
    sink.write("test.two", {"k": 2})
    sink.close()

    with open(p, "r", encoding="utf-8") as f:
        lines = f.readlines()
    rec = json.loads(lines[0])
    rec["k"] = 999
    lines[0] = json.dumps(rec) + "\n"
    with open(p, "w", encoding="utf-8") as f:
        f.writelines(lines)

    sink2 = _AuditSink(p)
    _, ok = sink2._verify_chain()
    assert ok is False
    sink2.close()


# ============================================================ H5


def test_h5_protected_check_raise_denies(tmp_path, monkeypatch):
    import security.protected_paths as pp
    from tools import terminal as t

    def boom(*a, **kw):
        raise RuntimeError("simulated")

    monkeypatch.setattr(pp, "is_inside_protected", boom, raising=True)

    result = t._validate_paths_against_gate(["F:\\some\\path.txt"])
    assert result is not None
    assert result.get("denied") is True


def test_h5_sandbox_check_raise_denies(tmp_path, monkeypatch):
    import security.sandbox as sb
    from tools import terminal as t

    def boom(*a, **kw):
        raise RuntimeError("simulated")

    monkeypatch.setattr(sb, "check_sandbox", boom, raising=True)

    result = t._validate_paths_against_gate(["F:\\some\\path.txt"])
    assert result is not None
    assert result.get("denied") is True


def test_h5_config_import_failure_denies(monkeypatch):
    from tools import terminal as t

    class _Raiser:
        def __getattr__(self, name):
            raise RuntimeError("config unavailable")

    monkeypatch.setitem(sys.modules, "config", _Raiser())

    result = t._validate_paths_against_gate(["F:\\some\\path.txt"])
    assert result is not None
    assert result.get("denied") is True