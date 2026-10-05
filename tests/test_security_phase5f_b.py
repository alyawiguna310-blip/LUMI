"""
Phase 5F-B tests: parsing and validation for the LumiRuntime setup.

These tests do not create, modify, or delete Windows accounts. They do
not touch the filesystem or the registry. They only exercise the pure
logic in security/runtime_identity.py plus a set of read-only
hardening checks on the Phase 5F-B launcher and setup scripts.

Module loading note: the launcher (scripts/launch_lumi_as_runtime.py)
uses `from __future__ import annotations`, so its @dataclass fields
carry string annotations. The dataclasses decorator resolves those
strings by looking up cls.__module__ in sys.modules during class
creation. The helper below registers the module in sys.modules before
exec_module, which is the correct pattern for importlib module loading
and avoids the 'NoneType has no attribute __dict__' failure that
occurs when the module is not registered.
"""
import ast
import importlib.util
import re as _re
import sys
from pathlib import Path

import pytest

from security import runtime_identity as ri


# =====================================================================
# SID parsing
# =====================================================================


def test_valid_sid():
    ok, _ = ri.parse_sid("S-1-5-21-1111111111-2222222222-3333333333-1002")
    assert ok is True


def test_valid_sid_builtin():
    ok, _ = ri.parse_sid("S-1-5-32-544")  # BUILTIN\Administrators
    assert ok is True


def test_invalid_sid_empty():
    ok, reason = ri.parse_sid("")
    assert ok is False and reason


def test_invalid_sid_none():
    ok, reason = ri.parse_sid(None)
    assert ok is False and reason


def test_invalid_sid_structure():
    ok, _ = ri.parse_sid("not-a-sid")
    assert ok is False
    ok, _ = ri.parse_sid("S-1-")
    assert ok is False
    ok, _ = ri.parse_sid("S-2-5-1")
    assert ok is False


# =====================================================================
# Local user CSV parsing
# =====================================================================


def test_parse_local_user_valid():
    rec = ri.parse_local_user_csv_line(
        '"LumiRuntime","S-1-5-21-1111111111-2222222222-3333333333-1002","True"'
    )
    assert rec.name == "LumiRuntime"
    assert rec.sid == "S-1-5-21-1111111111-2222222222-3333333333-1002"
    assert rec.enabled is True
    assert rec.error == ""


def test_parse_local_user_disabled():
    rec = ri.parse_local_user_csv_line(
        '"LumiRuntime","S-1-5-21-1111111111-2222222222-3333333333-1002","False"'
    )
    assert rec.enabled is False


def test_parse_local_user_empty_line():
    rec = ri.parse_local_user_csv_line("")
    assert rec.error


def test_parse_local_user_malformed_fields():
    rec = ri.parse_local_user_csv_line('"only-one-field"')
    assert rec.error


def test_parse_local_user_bad_sid():
    rec = ri.parse_local_user_csv_line('"Name","not-a-sid","True"')
    assert rec.error


def test_parse_local_user_none():
    rec = ri.parse_local_user_csv_line(None)
    assert rec.error


# =====================================================================
# Administrator membership
# =====================================================================


def test_admin_membership_detects_sid():
    lines = [
        "DESKTOP\\sulta",
        "S-1-5-21-1111111111-2222222222-3333333333-1002",
        "DESKTOP\\other",
    ]
    check = ri.parse_admin_membership(
        lines,
        runtime_sid="S-1-5-21-1111111111-2222222222-3333333333-1002",
    )
    assert check.is_member is True


def test_admin_membership_detects_name():
    lines = ["DESKTOP\\sulta", "DESKTOP\\LumiRuntime"]
    check = ri.parse_admin_membership(
        lines,
        runtime_sid="S-1-5-21-1111111111-2222222222-3333333333-1002",
        runtime_name="DESKTOP\\LumiRuntime",
    )
    assert check.is_member is True


def test_admin_membership_absent():
    lines = ["DESKTOP\\sulta", "DESKTOP\\other"]
    check = ri.parse_admin_membership(
        lines,
        runtime_sid="S-1-5-21-1111111111-2222222222-3333333333-1002",
        runtime_name="DESKTOP\\LumiRuntime",
    )
    assert check.is_member is False


def test_admin_membership_invalid_sid():
    check = ri.parse_admin_membership([], runtime_sid="bad-sid")
    assert check.is_member is False
    assert check.error


def test_admin_membership_name_match_requires_prefix_if_specified():
    lines = ["OTHERPC\\LumiRuntime"]
    check = ri.parse_admin_membership(
        lines,
        runtime_sid="S-1-5-21-1111111111-2222222222-3333333333-1002",
        runtime_name="DESKTOP\\LumiRuntime",
    )
    assert check.is_member is False


# =====================================================================
# is_runtime_identity_safe
# =====================================================================


def test_identity_safe_when_absent_from_admins():
    ok, reason = ri.is_runtime_identity_safe(
        runtime_name="DESKTOP\\LumiRuntime",
        runtime_sid="S-1-5-21-1111111111-2222222222-3333333333-1002",
        admin_lines=["DESKTOP\\sulta"],
    )
    assert ok is True
    assert reason == ""


def test_identity_unsafe_when_in_admins():
    ok, reason = ri.is_runtime_identity_safe(
        runtime_name="DESKTOP\\LumiRuntime",
        runtime_sid="S-1-5-21-1111111111-2222222222-3333333333-1002",
        admin_lines=["DESKTOP\\LumiRuntime"],
    )
    assert ok is False
    assert "Administrators" in reason


def test_identity_unsafe_on_bad_sid():
    ok, reason = ri.is_runtime_identity_safe(
        runtime_name="DESKTOP\\LumiRuntime",
        runtime_sid="bad",
        admin_lines=[],
    )
    assert ok is False


def test_identity_unsafe_on_empty_name():
    ok, reason = ri.is_runtime_identity_safe(
        runtime_name="",
        runtime_sid="S-1-5-21-1111111111-2222222222-3333333333-1002",
        admin_lines=[],
    )
    assert ok is False


def test_identity_unsafe_for_builtin_administrator():
    ok, reason = ri.is_runtime_identity_safe(
        runtime_name="DESKTOP\\Administrator",
        runtime_sid="S-1-5-21-1111111111-2222222222-3333333333-500",
        admin_lines=[],
    )
    assert ok is False
    assert "Administrator" in reason


# =====================================================================
# Module safety invariants (runtime_identity)
# =====================================================================


def test_module_does_not_import_subprocess():
    import inspect as _inspect
    src = _inspect.getsource(ri)
    assert "import subprocess" not in src


def test_module_does_not_reference_user_creation_apis():
    import inspect as _inspect
    src = _inspect.getsource(ri)
    for token in ("New-LocalUser", "net user", "Add-LocalGroupMember",
                  "Set-LocalUser"):
        assert token not in src


def test_module_does_not_reference_credentials():
    import inspect as _inspect
    src = _inspect.getsource(ri).lower()
    for token in ("cmdkey", "credread", "credwrite", "password"):
        assert token not in src, f"unexpected token {token!r} in module source"


# =====================================================================
# Phase 5F-B hardening: launcher and setup script invariants
#
# These tests read the launcher and setup scripts as text files, or
# load the launcher via a registered importlib module. They do not
# execute the launcher's runtime behaviour.
# =====================================================================


SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
LAUNCHER_PATH = SCRIPTS_DIR / "launch_lumi_as_runtime.py"
SETUP_PATH = SCRIPTS_DIR / "phase5f_b_setup.ps1"
INSPECT_PATH = SCRIPTS_DIR / "phase5f_b_inspect.ps1"
TEARDOWN_PATH = SCRIPTS_DIR / "phase5f_b_teardown.ps1"


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_launcher_module(name: str):
    """Load scripts/launch_lumi_as_runtime.py as a module under `name`.

    Registers the module in sys.modules before exec_module so that
    @dataclass(frozen=True) on LaunchResult can resolve string
    annotations produced by the launcher's
    `from __future__ import annotations`.
    """
    spec = importlib.util.spec_from_file_location(name, LAUNCHER_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return mod


def _find_sys_argv_access(source: str):
    """Return a list of human-readable findings for any executable
    access to sys.argv in `source`. Empty list means none.

    Docstrings, comments, and string literals are NOT flagged; only
    real code paths that read the process's own argv are reported.
    """
    tree = ast.parse(source)

    sys_module_names = set()
    from_import_argv_aliases = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sys":
                    sys_module_names.add(alias.asname or "sys")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "sys":
                for alias in node.names:
                    if alias.name == "argv":
                        from_import_argv_aliases.append(
                            alias.asname or "argv"
                        )

    findings = []
    for name in from_import_argv_aliases:
        findings.append(f"from sys import argv as {name!r}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "argv":
            v = node.value
            if isinstance(v, ast.Name) and v.id in sys_module_names:
                findings.append(f"{v.id}.argv attribute access")
        elif isinstance(node, ast.Call):
            fn = node.func
            if (
                isinstance(fn, ast.Name)
                and fn.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in sys_module_names
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "argv"
            ):
                findings.append(
                    f"getattr({node.args[0].id}, 'argv') call"
                )

    return findings


# --- venv path --------------------------------------------------------------


def test_h01_launcher_source_no_old_venv_path():
    src = _read_text(LAUNCHER_PATH)
    assert r"D:\Lumi\venv" not in src, (
        "launcher references D:\\Lumi\\venv; must be D:\\Lumi\\.venv"
    )
    assert ".venv" in src, "launcher must reference .venv"


def test_h02_inspect_source_no_old_venv_path():
    src = _read_text(INSPECT_PATH)
    assert r"D:\Lumi\venv" not in src, (
        "inspect script references D:\\Lumi\\venv; must be D:\\Lumi\\.venv"
    )
    assert r"D:\Lumi\.venv" in src, "inspect script must reference .venv"


def test_h03_no_bare_venv_path_segment_in_launcher_or_inspect():
    """Every path segment that reads `venv\\` or `venv/` must be
    preceded by `.`. This catches regressions where a new reference to
    the old (wrong) venv directory is introduced."""
    for p in (LAUNCHER_PATH, INSPECT_PATH):
        src = _read_text(p)
        for m in _re.finditer(r"venv[\\/]", src):
            start = m.start()
            if start > 0 and src[start - 1] == ".":
                continue
            ctx = src[max(0, start - 40):start + 40]
            raise AssertionError(
                f"bare 'venv' path segment in {p.name}: ...{ctx}..."
            )


# --- setup script: no cmdkey with password ---------------------------------


def test_h04_setup_does_not_pass_password_via_slash_pass():
    src = _read_text(SETUP_PATH)
    assert "/pass:" not in src, (
        "setup must not pass password via a /pass: argument"
    )


def test_h05_setup_does_not_invoke_cmdkey():
    """cmdkey must not be invoked. Mentions in comments are allowed; the
    test looks for an actual invocation as a command name."""
    src = _read_text(SETUP_PATH)
    for m in _re.finditer(r"(?m)^\s*(&\s*)?cmdkey", src):
        raise AssertionError(f"setup invokes cmdkey: {m.group(0)!r}")


def test_h06_setup_uses_credwritew():
    src = _read_text(SETUP_PATH)
    assert "CredWriteW" in src, "setup must use native CredWriteW"


def test_h07_teardown_uses_creddeletew():
    src = _read_text(TEARDOWN_PATH)
    assert "CredDeleteW" in src, "teardown must use CredDeleteW"


# --- setup script: fail-closed ----------------------------------------------


def test_h08_setup_requires_confirm():
    src = _read_text(SETUP_PATH)
    assert "[switch]$Confirm" in src
    assert "if (-not $Confirm)" in src


def test_h09_setup_refuses_if_account_exists():
    src = _read_text(SETUP_PATH)
    assert "Get-LocalUser" in src
    assert "already exists" in src.lower()


def test_h10_setup_verifies_not_administrator():
    src = _read_text(SETUP_PATH)
    assert "Administrators" in src
    assert "Remove-LocalGroupMember" in src


def test_h11_setup_rolls_back_on_credential_failure():
    src = _read_text(SETUP_PATH)
    assert "Remove-LocalUser" in src, "setup must roll back via Remove-LocalUser"
    fail_idx = src.find("PROVISIONING ROLLED BACK")
    assert fail_idx > 0, "setup must have explicit failure branch"
    tail = src[fail_idx:fail_idx + 800]
    assert "exit 1" in tail, "failure branch must exit non-zero"


def test_h12_setup_does_not_print_password_variable():
    src = _read_text(SETUP_PATH)
    for m in _re.finditer(r"Write-(Output|Host)\s+.*\$pwPlain", src):
        raise AssertionError(f"setup prints $pwPlain: {m.group(0)!r}")
    for m in _re.finditer(r"Write-(Output|Host)\s+.*\$secure", src):
        raise AssertionError(f"setup prints $secure: {m.group(0)!r}")


def test_h13_setup_only_prints_setup_complete_on_success():
    """The success summary must appear only after the credentialStored
    check; the failure branch must terminate before it."""
    src = _read_text(SETUP_PATH)
    idx_fail = src.find("PROVISIONING ROLLED BACK")
    idx_success = src.find("Setup complete.")
    assert idx_fail > 0 and idx_success > 0
    assert idx_fail < idx_success, (
        "the failure branch must precede the success message in the source"
    )


# --- launcher: fixed configuration -----------------------------------------


def test_h14_launcher_project_root_fixed():
    src = _read_text(LAUNCHER_PATH)
    assert r'PROJECT_ROOT = r"D:\Lumi"' in src


def test_h15_launcher_venv_subdir_is_dot_venv():
    src = _read_text(LAUNCHER_PATH)
    # The subdir string literal ".venv" must appear.
    assert '".venv"' in src or "'.venv'" in src


def test_h16_launcher_runtime_username_fixed():
    src = _read_text(LAUNCHER_PATH)
    assert 'RUNTIME_USERNAME = "LumiRuntime"' in src


def test_h17_launcher_cred_target_fixed():
    src = _read_text(LAUNCHER_PATH)
    assert 'CRED_TARGET = "LumiRuntime"' in src


def test_h18_launcher_entry_point_uses_project_root():
    src = _read_text(LAUNCHER_PATH)
    # The entry point is constructed from PROJECT_ROOT and "main.py".
    assert '"main.py"' in src


# --- launcher: no arbitrary input ------------------------------------------


def test_h19_launcher_does_not_read_sys_argv():
    """AST-based: reject executable access to sys.argv. Docstrings,
    comments, and string literals are not rejected, because they are
    not code paths that read the process's argv."""
    src = _read_text(LAUNCHER_PATH)
    findings = _find_sys_argv_access(src)
    assert findings == [], (
        f"launcher must not read sys.argv; found: {findings}"
    )


def test_h19b_ast_checker_detects_sys_argv():
    """Positive test: the AST checker used by test_h19 must detect
    real executable sys.argv access. This proves the check is not
    vacuous."""
    sample = (
        "import sys\n"
        "def f():\n"
        "    return sys.argv[1]\n"
    )
    findings = _find_sys_argv_access(sample)
    assert findings, "AST checker failed to detect sys.argv access"


def test_h19c_ast_checker_ignores_docstring_and_comments():
    """Negative test: the AST checker must ignore sys.argv mentions
    inside a docstring, a comment, or a string literal."""
    sample = (
        '"""Docstring mentions sys.argv but does not use it."""\n'
        "# Also a comment: sys.argv[0]\n"
        'MESSAGE = "the launcher does not read sys.argv"\n'
        "x = 1\n"
    )
    findings = _find_sys_argv_access(sample)
    assert findings == [], (
        f"AST checker incorrectly flagged non-executable mentions: "
        f"{findings}"
    )


def test_h20_launcher_does_not_accept_user_input():
    src = _read_text(LAUNCHER_PATH)
    for token in ("input(", "getpass.getpass("):
        assert token not in src, f"launcher must not use {token}"


def _find_function(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _command_line_assignment(fdef):
    """Return the ast.Assign node for `command_line = ...` inside fdef."""
    for node in ast.walk(fdef):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "command_line":
                    return node
    return None


def _first_positional_call_arg(funcdef, callee_name):
    """Return the id/attribute-name string of the first positional
    argument in the first call to `callee_name` inside funcdef."""
    for node in ast.walk(funcdef):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == callee_name:
                assert node.args, (
                    f"call to {callee_name!r} has no positional arguments"
                )
                arg = node.args[0]
                if isinstance(arg, ast.Name):
                    return arg.id
                if isinstance(arg, ast.Attribute):
                    base = arg
                    parts = []
                    while isinstance(base, ast.Attribute):
                        parts.append(base.attr)
                        base = base.value
                    if isinstance(base, ast.Name):
                        parts.append(base.id)
                    return ".".join(reversed(parts))
                raise AssertionError(
                    f"non-name argument passed to {callee_name!r}: "
                    f"{ast.dump(arg)}"
                )
    return None


def test_h21_launcher_command_line_uses_fixed_constants():
    """AST/semantic check.

    Requirements:
      * _launch_with_entry builds its command line from VENV_PYTHON and
        its single entry_path parameter, and from nothing else.
      * launch() passes the fixed ENTRY constant.
      * launch_probe() passes the fixed PROBE_ENTRY constant.
      * No module-level access to sys.argv.
    """
    src = _read_text(LAUNCHER_PATH)
    tree = ast.parse(src)

    fdef = _find_function(tree, "_launch_with_entry")
    assert fdef is not None, "_launch_with_entry function not found"

    assign = _command_line_assignment(fdef)
    assert assign is not None, (
        "command_line assignment not found inside _launch_with_entry"
    )

    referenced_names = set()
    for n in ast.walk(assign.value):
        if isinstance(n, ast.Name):
            referenced_names.add(n.id)

    assert "VENV_PYTHON" in referenced_names, (
        f"command_line must reference VENV_PYTHON; saw "
        f"{sorted(referenced_names)}"
    )
    assert "entry_path" in referenced_names, (
        f"command_line must reference the entry_path parameter; saw "
        f"{sorted(referenced_names)}"
    )
    for forbidden in ("argv", "input", "getpass"):
        assert forbidden not in referenced_names, (
            f"command_line must not reference {forbidden!r}; saw "
            f"{sorted(referenced_names)}"
        )

    launch_fn = _find_function(tree, "launch")
    assert launch_fn is not None, "launch() function not found"
    assert _first_positional_call_arg(launch_fn, "_launch_with_entry") == "ENTRY", (
        "launch() must pass the fixed ENTRY constant to _launch_with_entry"
    )

    probe_fn = _find_function(tree, "launch_probe")
    assert probe_fn is not None, "launch_probe() function not found"
    assert _first_positional_call_arg(
        probe_fn, "_launch_with_entry"
    ) == "PROBE_ENTRY", (
        "launch_probe() must pass the fixed PROBE_ENTRY constant to "
        "_launch_with_entry"
    )

    findings = _find_sys_argv_access(src)
    assert findings == [], (
        f"launcher must not read sys.argv; found: {findings}"
    )


def test_h21b_ast_checker_rejects_dynamic_command_line():
    """Positive test: the AST helper used by test_h21 must reject a
    command_line built from a caller-supplied dynamic value."""
    bad_src = (
        "import os\n"
        "def _launch_with_entry(entry_path):\n"
        "    command_line = os.environ['PATH']\n"
        "    return command_line\n"
    )
    tree = ast.parse(bad_src)
    fdef = _find_function(tree, "_launch_with_entry")
    assign = _command_line_assignment(fdef)
    assert assign is not None
    names = {n.id for n in ast.walk(assign.value) if isinstance(n, ast.Name)}
    assert "VENV_PYTHON" not in names, (
        "AST helper incorrectly considered PATH as VENV_PYTHON"
    )


@pytest.mark.skipif(sys.platform != "win32",
                    reason="launcher requires ctypes.WinDLL (Windows-only)")
def test_h22_launcher_launch_takes_no_arguments():
    mod = _load_launcher_module("_lumi_launcher_for_tests")

    import inspect as _inspect
    sig = _inspect.signature(mod.launch)
    assert len(sig.parameters) == 0, (
        f"launch() must take no arguments; has {list(sig.parameters)}"
    )


@pytest.mark.skipif(sys.platform != "win32",
                    reason="launcher requires ctypes.WinDLL (Windows-only)")
def test_h23_launcher_constants_match_design():
    mod = _load_launcher_module("_lumi_launcher_for_tests2")

    assert mod.RUNTIME_USERNAME == "LumiRuntime"
    assert mod.CRED_TARGET == "LumiRuntime"
    assert mod.PROJECT_ROOT == r"D:\Lumi"
    p = mod.VENV_PYTHON.replace("/", "\\")
    assert p.endswith(r".venv\Scripts\python.exe"), p
    assert mod.ENTRY == r"D:\Lumi\main.py"


# --- teardown script: no secret-handling -----------------------------------


def test_h24_teardown_does_not_use_cmdkey_for_delete():
    src = _read_text(TEARDOWN_PATH)
    for m in _re.finditer(r"(?m)^\s*(&\s*)?cmdkey", src):
        raise AssertionError(f"teardown invokes cmdkey: {m.group(0)!r}")