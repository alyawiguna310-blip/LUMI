"""Phase 5F-D static tests for the protected production runtime boundary."""

import ast
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
LAUNCHER = SCRIPTS / "launch_lumi_as_runtime.py"
RUNTIME_CHECK = SCRIPTS / "phase5f_d_runtime_check.ps1"


def read(p):
    return p.read_text(encoding="utf-8")


def test_production_runtime_is_outside_project_tree():
    src = read(LAUNCHER)
    tree = ast.parse(src)
    assignments = {
        target.id: node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    assert "RUNTIME_ROOT" in assignments
    assert "RUNTIME_PYTHON" in assignments
    assert "C:\\Program Files\\LumiRuntime" in src
    assert "D:\\Lumi\\.venv" not in src.split("RUNTIME_PYTHON", 1)[1].split("ENTRY", 1)[0]


def test_production_launcher_uses_runtime_python():
    src = read(LAUNCHER)
    marker = "def _launch_with_entry"
    body = src.split(marker, 1)[1].split("def _launch_system_python_with_entry", 1)[0]
    assert "RUNTIME_PYTHON" in body
    assert 'CreateProcessWithLogonW' in body
    assert "VENV_PYTHON" not in body


def test_legacy_venv_is_diagnostic_only():
    src = read(LAUNCHER)
    assert "VENV_PYTHON" in src
    assert "Temporary: the project venv is retained only for human-side diagnostics." in src


def test_runtime_preflight_is_read_only():
    src = read(RUNTIME_CHECK).lower()
    assert "does not modify accounts, acl" in src
    assert "icacls.exe" in src
    assert "remove-" not in src
    assert "new-localuser" not in src
    assert "set-acl" not in src


def test_runtime_preflight_requires_exact_protected_path():
    src = read(RUNTIME_CHECK)
    assert r"C:\Program Files\LumiRuntime\Python312\python.exe" in src
