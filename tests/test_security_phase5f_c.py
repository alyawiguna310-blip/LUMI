"""
Phase 5F-C tests: static validation of the launcher and probe.

These tests do not launch any process, do not create accounts, do not
touch ACLs. They read the launcher and probe sources as text and apply
AST-based checks, and they load the launcher module through a helper
that registers it in sys.modules before exec_module.

The sys.modules registration is required because the launcher uses
`from __future__ import annotations` together with
@dataclass(frozen=True). During class creation, the dataclasses
decorator resolves string annotations by looking up cls.__module__ in
sys.modules. If the test loader does not register the module first,
that lookup returns None and dataclasses raises AttributeError.

Redirection note: an earlier revision attempted stdout/stderr
redirection via STARTF_USESTDHANDLES, which caused
CreateProcessWithLogonW to fail with WinError 6 (ERROR_INVALID_HANDLE).
That path was removed and is guarded by negative tests.

Temporary diagnostic note: scripts/_phase5fc_minimal.py and
scripts/_phase5fc_system_minimal.py, plus the launcher functions
launch_minimal_diagnostic / launch_system_minimal_diagnostic and the
validator's corresponding calls, exist only for the exit-code-103
investigation. When the investigation is closed, all of these are
removed and the corresponding tests are removed.
"""
import ast
import importlib.util
import inspect as _inspect
import re
import sys
from pathlib import Path

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
LAUNCHER_PATH = SCRIPTS_DIR / "launch_lumi_as_runtime.py"
PROBE_PATH = SCRIPTS_DIR / "_phase5fc_probe.py"
VALIDATE_PATH = SCRIPTS_DIR / "phase5fc_validate.py"
# Temporary venv-Python diagnostic entry point.
MINIMAL_PATH = SCRIPTS_DIR / "_phase5fc_minimal.py"
# Temporary system-Python diagnostic entry point.
SYSTEM_MINIMAL_PATH = SCRIPTS_DIR / "_phase5fc_system_minimal.py"

EXPECTED_OUTPUT_PATH = r"D:\Lumi\workspace\phase5fc_identity.json"
EXPECTED_OUTPUT_DIR = r"D:\Lumi\workspace"
EXPECTED_DIAG_PATH = r"D:\Lumi\workspace\phase5fc_probe_error.txt"
EXPECTED_MINIMAL_OUTPUT_PATH = r"D:\Lumi\workspace\phase5fc_minimal.txt"
EXPECTED_SYSTEM_MINIMAL_OUTPUT_PATH = (
    r"D:\Lumi\workspace\phase5fc_system_minimal.txt"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _module_has_no_import(tree, forbidden_name: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == forbidden_name:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module == forbidden_name:
                return False
    return True


def _find_function(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _find_module_constant(tree, name):
    """Return (assign_node, value_node) for a top-level `name = <value>`."""
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    return node, node.value
    return None, None


# =====================================================================
# Launcher: constants
# =====================================================================


def test_launcher_has_probe_entry_constant():
    src = _read(LAUNCHER_PATH)
    assert "PROBE_ENTRY" in src
    assert "_phase5fc_probe.py" in src


def test_launcher_probe_entry_is_fixed():
    src = _read(LAUNCHER_PATH)
    m = re.search(r"^PROBE_ENTRY\s*=\s*(.+)$", src, flags=re.MULTILINE)
    assert m, "PROBE_ENTRY definition missing"
    line = m.group(1)
    assert "PROJECT_ROOT" in line
    assert "_phase5fc_probe.py" in line


def test_launcher_runtime_username_still_fixed():
    src = _read(LAUNCHER_PATH)
    assert 'RUNTIME_USERNAME = "LumiRuntime"' in src


def test_launcher_cred_target_still_fixed():
    src = _read(LAUNCHER_PATH)
    assert 'CRED_TARGET = "LumiRuntime"' in src


def test_launcher_project_root_still_fixed():
    src = _read(LAUNCHER_PATH)
    assert r'PROJECT_ROOT = r"D:\Lumi"' in src


def test_launcher_venv_still_dot_venv():
    src = _read(LAUNCHER_PATH)
    assert '".venv"' in src or "'.venv'" in src
    assert r"D:\Lumi\venv" not in src


# =====================================================================
# Launcher: callable surfaces
# =====================================================================


def _load_launcher_module():
    """Load scripts/launch_lumi_as_runtime.py as a module.

    Registers the module in sys.modules BEFORE exec_module so that
    @dataclass(frozen=True) on LaunchResult can resolve the string
    annotations the launcher produces via
    `from __future__ import annotations`.
    """
    name = "_lumi_launcher_5fc_test"
    spec = importlib.util.spec_from_file_location(name, LAUNCHER_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return mod


def test_launcher_launch_takes_no_arguments():
    mod = _load_launcher_module()
    sig = _inspect.signature(mod.launch)
    assert len(sig.parameters) == 0


def test_launcher_launch_probe_takes_no_arguments():
    mod = _load_launcher_module()
    sig = _inspect.signature(mod.launch_probe)
    assert len(sig.parameters) == 0


def test_launcher_probe_uses_fixed_probe_entry():
    mod = _load_launcher_module()
    assert mod.PROBE_ENTRY.endswith("_phase5fc_probe.py")
    assert mod.PROBE_ENTRY.startswith(mod.PROJECT_ROOT)


def test_launcher_venv_path_correct():
    mod = _load_launcher_module()
    p = mod.VENV_PYTHON.replace("/", "\\")
    assert p.endswith(r".venv\Scripts\python.exe"), p


# =====================================================================
# Launcher: minimal diagnostic entry points (TEMPORARY)
# =====================================================================


def test_launcher_has_minimal_entry_constant():
    src = _read(LAUNCHER_PATH)
    assert "MINIMAL_ENTRY" in src
    assert "_phase5fc_minimal.py" in src


def test_launcher_minimal_entry_is_fixed():
    """MINIMAL_ENTRY must be a module-level constant built from
    PROJECT_ROOT. It must not be derived from os.environ or sys.argv."""
    tree = ast.parse(_read(LAUNCHER_PATH))
    assign, value = _find_module_constant(tree, "MINIMAL_ENTRY")
    assert assign is not None, "MINIMAL_ENTRY must be defined"
    for node in ast.walk(value):
        if isinstance(node, ast.Attribute) and node.attr in (
            "environ", "argv",
        ):
            raise AssertionError(
                f"MINIMAL_ENTRY must not read {node.attr}"
            )
    names = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
    assert "PROJECT_ROOT" in names
    consts = [n.value for n in ast.walk(value)
              if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert any("_phase5fc_minimal.py" in c for c in consts), (
        "MINIMAL_ENTRY must reference _phase5fc_minimal.py"
    )


def test_launcher_launch_minimal_diagnostic_takes_no_arguments():
    mod = _load_launcher_module()
    sig = _inspect.signature(mod.launch_minimal_diagnostic)
    assert len(sig.parameters) == 0


def test_launcher_launch_minimal_diagnostic_uses_fixed_entry():
    mod = _load_launcher_module()
    assert mod.MINIMAL_ENTRY.endswith("_phase5fc_minimal.py")
    assert mod.MINIMAL_ENTRY.startswith(mod.PROJECT_ROOT)


def test_launcher_launch_minimal_diagnostic_calls_launch_with_entry():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "launch_minimal_diagnostic")
    assert fn is not None

    invokes = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            if (
                isinstance(f, ast.Name)
                and f.id == "_launch_with_entry"
            ):
                invokes = True
    assert invokes, (
        "launch_minimal_diagnostic must invoke _launch_with_entry"
    )


def test_launcher_launch_minimal_diagnostic_does_not_raise():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "launch_minimal_diagnostic")
    assert fn is not None
    for node in ast.walk(fn):
        if isinstance(node, ast.Raise):
            raise AssertionError(
                f"launch_minimal_diagnostic must not raise; found at "
                f"line {node.lineno}"
            )


# =====================================================================
# Launcher: system-Python diagnostic (TEMPORARY)
# =====================================================================


def test_launcher_has_system_minimal_entry_constant():
    src = _read(LAUNCHER_PATH)
    assert "SYSTEM_MINIMAL_ENTRY" in src
    assert "_phase5fc_system_minimal.py" in src


def test_launcher_system_minimal_entry_is_fixed():
    """SYSTEM_MINIMAL_ENTRY must be a module-level constant built from
    PROJECT_ROOT. It must not be derived from os.environ or sys.argv."""
    tree = ast.parse(_read(LAUNCHER_PATH))
    assign, value = _find_module_constant(tree, "SYSTEM_MINIMAL_ENTRY")
    assert assign is not None, "SYSTEM_MINIMAL_ENTRY must be defined"
    for node in ast.walk(value):
        if isinstance(node, ast.Attribute) and node.attr in (
            "environ", "argv",
        ):
            raise AssertionError(
                f"SYSTEM_MINIMAL_ENTRY must not read {node.attr}"
            )
    names = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
    assert "PROJECT_ROOT" in names
    consts = [n.value for n in ast.walk(value)
              if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert any("_phase5fc_system_minimal.py" in c for c in consts), (
        "SYSTEM_MINIMAL_ENTRY must reference _phase5fc_system_minimal.py"
    )


def test_launcher_has_resolve_system_python_function():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_resolve_system_python")
    assert fn is not None, (
        "launcher must define _resolve_system_python for TEST B"
    )


def test_launcher_resolve_system_python_takes_no_arguments():
    mod = _load_launcher_module()
    sig = _inspect.signature(mod._resolve_system_python)
    assert len(sig.parameters) == 0


def test_launcher_resolve_system_python_uses_path_walking():
    """The resolver must walk PATH to locate python.exe. It must not
    import subprocess, must not call where.exe directly, and must not
    read a user-supplied path from anywhere."""
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_resolve_system_python")
    assert fn is not None

    # No subprocess import anywhere (covered by another test too).
    assert _module_has_no_import(tree, "subprocess")
    # No hardcoded python path inside the resolver.
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            if node.value == '"':
                continue
            assert "python.exe" in low or "path" in low or \
                "environment" in low or not low, (
                    f"_resolve_system_python contains unexpected string "
                    f"{node.value!r}"
                )


def test_launcher_resolve_system_python_filters_project_root():
    """The resolver must reference PROJECT_ROOT so it can exclude the
    venv from the candidate list."""
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_resolve_system_python")
    assert fn is not None
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "PROJECT_ROOT" in names, (
        "_resolve_system_python must reference PROJECT_ROOT to filter "
        "out the venv"
    )


def test_launcher_launch_system_minimal_diagnostic_takes_no_arguments():
    mod = _load_launcher_module()
    sig = _inspect.signature(mod.launch_system_minimal_diagnostic)
    assert len(sig.parameters) == 0


def test_launcher_launch_system_minimal_diagnostic_calls_resolver():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "launch_system_minimal_diagnostic")
    assert fn is not None

    calls_resolver = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            if (
                isinstance(f, ast.Name)
                and f.id == "_resolve_system_python"
            ):
                calls_resolver = True
    assert calls_resolver, (
        "launch_system_minimal_diagnostic must call "
        "_resolve_system_python"
    )


def test_launcher_launch_system_minimal_diagnostic_calls_launcher():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "launch_system_minimal_diagnostic")
    assert fn is not None

    calls_launcher = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            if (
                isinstance(f, ast.Name)
                and f.id == "_launch_system_python_with_entry"
            ):
                calls_launcher = True
    assert calls_launcher, (
        "launch_system_minimal_diagnostic must call "
        "_launch_system_python_with_entry"
    )


def test_launcher_system_python_launcher_exists():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_system_python_with_entry")
    assert fn is not None


def test_launcher_system_python_launcher_uses_same_cpwl_config():
    """The system-Python launcher must use the same CreateProcessWithLogonW
    call shape as the venv launcher: LOGON_WITH_PROFILE,
    CREATE_UNICODE_ENVIRONMENT, PROJECT_ROOT cwd."""
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_system_python_with_entry")
    assert fn is not None

    uses_cpwl = False
    uses_logon_with_profile = False
    uses_unicode_env = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute):
            if node.attr == "CreateProcessWithLogonW":
                uses_cpwl = True
        if isinstance(node, ast.Name):
            if node.id == "LOGON_WITH_PROFILE":
                uses_logon_with_profile = True
            if node.id == "CREATE_UNICODE_ENVIRONMENT":
                uses_unicode_env = True
    assert uses_cpwl
    assert uses_logon_with_profile
    assert uses_unicode_env


def test_launcher_system_python_launcher_does_not_set_dw_flags():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_system_python_with_entry")
    assert fn is not None
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute) and tgt.attr == "dwFlags":
                    raise AssertionError(
                        "system-Python launcher must not assign si.dwFlags"
                    )


def test_launcher_system_python_launcher_does_not_set_h_std_handles():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_system_python_with_entry")
    assert fn is not None
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute) and tgt.attr in (
                    "hStdInput", "hStdOutput", "hStdError",
                ):
                    raise AssertionError(
                        f"system-Python launcher must not assign "
                        f"si.{tgt.attr}"
                    )


# =====================================================================
# Launcher: no shell / no subprocess / no argv
# =====================================================================


def test_launcher_does_not_import_subprocess():
    tree = ast.parse(_read(LAUNCHER_PATH))
    assert _module_has_no_import(tree, "subprocess"), (
        "launcher must not import subprocess"
    )


def test_launcher_does_not_use_shell_true():
    src = _read(LAUNCHER_PATH)
    assert "shell=True" not in src
    assert "shell = True" not in src


def test_launcher_does_not_use_os_system_or_popen():
    tree = ast.parse(_read(LAUNCHER_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os":
                assert node.attr not in (
                    "system", "popen", "spawnl", "spawnv",
                    "spawnve", "exec", "execl", "execv", "execvp",
                ), f"launcher uses os.{node.attr}"


def test_launcher_does_not_read_sys_argv():
    tree = ast.parse(_read(LAUNCHER_PATH))

    sys_module_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sys":
                    sys_module_names.add(alias.asname or "sys")

    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "argv":
            v = node.value
            if isinstance(v, ast.Name) and v.id in sys_module_names:
                findings.append(f"{v.id}.argv attribute access")
        elif isinstance(node, ast.ImportFrom) and node.module == "sys":
            for alias in node.names:
                if alias.name == "argv":
                    findings.append("from sys import argv")

    assert findings == [], f"launcher reads sys.argv: {findings}"


def test_launcher_command_line_only_uses_fixed_constants():
    src = _read(LAUNCHER_PATH)
    m = re.search(r"command_line\s*=\s*(.+)", src)
    assert m, "command_line definition missing"
    line = m.group(1)
    assert "VENV_PYTHON" in line
    assert "entry_path" in line
    for forbidden in ("argv", "input(", "getpass", "os.environ.get(\"PATH\")"):
        assert forbidden not in line, (
            f"command_line must not reference {forbidden}"
        )


def test_launcher_uses_create_process_with_logon_w():
    src = _read(LAUNCHER_PATH)
    assert "CreateProcessWithLogonW" in src


# =====================================================================
# Launcher: GetExitCodeProcess binding + LaunchResult
# =====================================================================


def test_launcher_defines_get_exit_code_process_binding():
    tree = ast.parse(_read(LAUNCHER_PATH))
    found_argtypes = False
    found_restype = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute):
                    if tgt.attr == "argtypes":
                        v = tgt.value
                        if (
                            isinstance(v, ast.Attribute)
                            and v.attr == "GetExitCodeProcess"
                        ):
                            found_argtypes = True
                    elif tgt.attr == "restype":
                        v = tgt.value
                        if (
                            isinstance(v, ast.Attribute)
                            and v.attr == "GetExitCodeProcess"
                        ):
                            found_restype = True
    assert found_argtypes
    assert found_restype


def test_launcher_defines_launch_result_class():
    tree = ast.parse(_read(LAUNCHER_PATH))
    has_class = any(
        isinstance(n, ast.ClassDef) and n.name == "LaunchResult"
        for n in tree.body
    )
    assert has_class
    src = _read(LAUNCHER_PATH)
    for field in ("pid", "exit_code", "timed_out", "wait_seconds"):
        assert field in src


def test_launcher_defines_wait_constants():
    tree = ast.parse(_read(LAUNCHER_PATH))
    for name in ("WAIT_OBJECT_0", "WAIT_TIMEOUT"):
        assign, value = _find_module_constant(tree, name)
        assert assign is not None
        assert isinstance(value, ast.Constant)
        assert isinstance(value.value, int)


def test_launcher_launch_with_entry_calls_wait_and_get_exit_code():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_with_entry")
    assert fn is not None

    has_wait = False
    has_get_exit = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute):
                if f.attr == "WaitForSingleObject":
                    has_wait = True
                if f.attr == "GetExitCodeProcess":
                    has_get_exit = True
    assert has_wait
    assert has_get_exit


def test_launcher_launch_with_entry_compares_wait_return_against_timeout():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_with_entry")
    assert fn is not None

    compared_timeout = False
    compared_object_0 = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare):
            for comp in node.comparators:
                if isinstance(comp, ast.Name):
                    if comp.id == "WAIT_TIMEOUT":
                        compared_timeout = True
                    if comp.id == "WAIT_OBJECT_0":
                        compared_object_0 = True
    assert compared_timeout
    assert compared_object_0


def test_launcher_launch_with_entry_sets_timed_out_flag():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_with_entry")
    assert fn is not None
    found = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "timed_out":
                    found = True
    assert found


def test_launcher_launch_probe_returns_launch_with_entry_result():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "launch_probe")
    assert fn is not None

    invokes = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            if (
                isinstance(f, ast.Name)
                and f.id == "_launch_with_entry"
            ):
                invokes = True
    assert invokes


def test_launcher_launch_still_returns_int_zero():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "launch")
    assert fn is not None
    has_return_zero = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and node.value is not None:
            v = node.value
            if isinstance(v, ast.Constant) and v.value == 0:
                has_return_zero = True
    assert has_return_zero


# =====================================================================
# Launcher: redirection must NOT be present (WinError 6 regression)
# =====================================================================


def test_launcher_does_not_define_startf_use_std_handles_constant():
    tree = ast.parse(_read(LAUNCHER_PATH))
    assign, _ = _find_module_constant(tree, "STARTF_USESTDHANDLES")
    assert assign is None


def test_launcher_does_not_define_create_file_w_binding():
    tree = ast.parse(_read(LAUNCHER_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute) and tgt.attr in (
                    "argtypes", "restype",
                ):
                    v = tgt.value
                    if (
                        isinstance(v, ast.Attribute)
                        and v.attr == "CreateFileW"
                    ):
                        raise AssertionError(
                            "CreateFileW binding must be removed"
                        )


def test_launcher_does_not_define_security_attributes_struct():
    tree = ast.parse(_read(LAUNCHER_PATH))
    has_class = any(
        isinstance(n, ast.ClassDef) and n.name == "SECURITY_ATTRIBUTES"
        for n in tree.body
    )
    assert not has_class


def test_launcher_does_not_define_create_file_w_constants():
    tree = ast.parse(_read(LAUNCHER_PATH))
    for name in ("GENERIC_WRITE", "FILE_SHARE_READ",
                 "FILE_SHARE_WRITE", "CREATE_ALWAYS",
                 "FILE_ATTRIBUTE_NORMAL", "_INVALID_HANDLE_VALUE"):
        assign, _ = _find_module_constant(tree, name)
        assert assign is None, f"{name} must not be defined"


def test_launcher_does_not_open_runtime_output_handle_function():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_open_runtime_output_handle")
    assert fn is None


def test_launcher_does_not_read_runtime_output_function():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_read_runtime_output")
    assert fn is None


def test_launcher_does_not_set_dw_flags():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_with_entry")
    assert fn is not None
    for node in ast.walk(fn):
        if isinstance(node, ast.AugAssign):
            tgt = node.target
            if isinstance(tgt, ast.Attribute) and tgt.attr == "dwFlags":
                raise AssertionError(
                    "_launch_with_entry must not modify si.dwFlags"
                )
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute) and tgt.attr == "dwFlags":
                    raise AssertionError(
                        "_launch_with_entry must not assign to si.dwFlags"
                    )


def test_launcher_does_not_set_h_std_handles():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_with_entry")
    assert fn is not None
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute) and tgt.attr in (
                    "hStdInput", "hStdOutput", "hStdError",
                ):
                    raise AssertionError(
                        f"_launch_with_entry must not assign si.{tgt.attr}"
                    )


def test_launcher_does_not_have_redirect_output_parameter():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_with_entry")
    assert fn is not None
    for arg in fn.args.args:
        assert arg.arg != "redirect_output"
    for kw in fn.args.kwonlyargs:
        assert kw.arg != "redirect_output"


def test_launcher_runtime_output_path_constant_removed():
    tree = ast.parse(_read(LAUNCHER_PATH))
    assign, _ = _find_module_constant(tree, "RUNTIME_OUTPUT_PATH")
    assert assign is None


def test_launcher_launch_result_has_no_runtime_output_fields():
    tree = ast.parse(_read(LAUNCHER_PATH))
    result_cls = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "LaunchResult":
            result_cls = node
    assert result_cls is not None
    for node in result_cls.body:
        if isinstance(node, ast.AnnAssign):
            name = node.target.id if isinstance(node.target, ast.Name) else ""
            assert name not in ("runtime_output_path", "runtime_output")


def test_launcher_render_diagnostics_no_runtime_output_section():
    tree = ast.parse(_read(LAUNCHER_PATH))
    result_cls = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "LaunchResult":
            result_cls = node
    assert result_cls is not None
    render_fn = None
    for item in result_cls.body:
        if (
            isinstance(item, ast.FunctionDef)
            and item.name == "render_diagnostics"
        ):
            render_fn = item
    assert render_fn is not None
    for node in ast.walk(render_fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert "runtime output" not in node.value.lower()


def test_launcher_launch_probe_does_not_request_redirect():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "launch_probe")
    assert fn is not None
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                assert kw.arg != "redirect_output"


# =====================================================================
# Launcher: diagnostics
# =====================================================================


def test_launcher_launch_result_includes_diagnostic_fields():
    src = _read(LAUNCHER_PATH)
    for field in (
        "application_path", "command_line", "cwd",
        "logon_flags", "creation_flags",
        "create_ok", "create_last_error",
        "pid", "exit_code", "timed_out", "wait_seconds",
    ):
        assert field in src


def test_launcher_captures_get_last_error_on_failure():
    src = _read(LAUNCHER_PATH)
    assert "ctypes.get_last_error()" in src
    assert "create_last_error" in src


def test_launcher_records_create_ok_flag():
    src = _read(LAUNCHER_PATH)
    assert "create_ok" in src


def test_launcher_launch_result_has_no_secret_field_names():
    tree = ast.parse(_read(LAUNCHER_PATH))
    result_cls = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "LaunchResult":
            result_cls = node
    assert result_cls is not None
    for node in result_cls.body:
        if isinstance(node, ast.AnnAssign):
            name = node.target.id if isinstance(node.target, ast.Name) else ""
            low = name.lower()
            for bad in ("password", "secret", "credential", "token"):
                assert bad not in low


def test_launcher_render_diagnostics_avoids_secret_terms():
    tree = ast.parse(_read(LAUNCHER_PATH))
    result_cls = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "LaunchResult":
            result_cls = node
    assert result_cls is not None
    render_fn = None
    for item in result_cls.body:
        if (
            isinstance(item, ast.FunctionDef)
            and item.name == "render_diagnostics"
        ):
            render_fn = item
    assert render_fn is not None
    for node in ast.walk(render_fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            for bad in ("password", "secret"):
                assert bad not in low


def test_launcher_render_diagnostics_has_expected_markers():
    src = _read(LAUNCHER_PATH)
    assert "CreateProcessWithLogonW" in src
    assert "Win32 error" in src
    assert "Child exit code" in src


def test_launcher_probe_does_not_raise_directly():
    tree = ast.parse(_read(LAUNCHER_PATH))
    probe_fn = _find_function(tree, "launch_probe")
    assert probe_fn is not None
    for node in ast.walk(probe_fn):
        if isinstance(node, ast.Raise):
            raise AssertionError(
                f"launch_probe must not raise; found at line "
                f"{node.lineno}"
            )


def test_launcher_cpwl_call_inside_try_finally():
    tree = ast.parse(_read(LAUNCHER_PATH))
    fn = _find_function(tree, "_launch_with_entry")
    assert fn is not None
    has_try = any(isinstance(n, ast.Try) for n in ast.walk(fn))
    assert has_try


# =====================================================================
# Venv minimal script (TEMPORARY)
# =====================================================================


def test_minimal_script_exists():
    assert MINIMAL_PATH.is_file()


def test_minimal_script_only_imports_os():
    tree = ast.parse(_read(MINIMAL_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name == "os"
        elif isinstance(node, ast.ImportFrom):
            raise AssertionError(
                f"minimal script must not use from-imports"
            )


def test_minimal_script_no_subprocess():
    tree = ast.parse(_read(MINIMAL_PATH))
    assert _module_has_no_import(tree, "subprocess")


def test_minimal_script_no_ctypes():
    tree = ast.parse(_read(MINIMAL_PATH))
    assert _module_has_no_import(tree, "ctypes")


def test_minimal_script_no_shell():
    tree = ast.parse(_read(MINIMAL_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os":
                assert node.attr not in (
                    "system", "popen", "spawnl", "spawnv",
                    "spawnve", "exec", "execl", "execv", "execvp",
                )


def test_minimal_script_does_not_read_sys_argv():
    tree = ast.parse(_read(MINIMAL_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "argv":
            raise AssertionError("minimal script must not read argv")


def test_minimal_script_writes_fixed_output_path():
    src = _read(MINIMAL_PATH)
    assert "phase5fc_minimal.txt" in src
    tree = ast.parse(src)
    has_open = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == "open":
                has_open = True
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(
                        arg.value, str,
                    ):
                        assert arg.value == EXPECTED_MINIMAL_OUTPUT_PATH
    assert has_open


def test_minimal_script_path_not_from_env():
    """The minimal script's open() call must not use os.environ to
    build the output path. Reading USERNAME etc. for printing is
    allowed."""
    tree = ast.parse(_read(MINIMAL_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == "open":
                all_args = list(node.args) + [
                    kw.value for kw in node.keywords
                ]
                for arg in all_args:
                    for inner in ast.walk(arg):
                        if (
                            isinstance(inner, ast.Attribute)
                            and inner.attr == "environ"
                        ):
                            raise AssertionError(
                                "minimal script must not use os.environ "
                                "to build its output path"
                            )


def test_minimal_script_has_no_arguments():
    mod = importlib.util.spec_from_file_location(
        "_minimal_for_tests", MINIMAL_PATH
    )
    m = importlib.util.module_from_spec(mod)
    sys.modules["_minimal_for_tests"] = m
    try:
        mod.loader.exec_module(m)
    except BaseException:
        sys.modules.pop("_minimal_for_tests", None)
        raise
    if hasattr(m, "main"):
        sig = _inspect.signature(m.main)
        assert len(sig.parameters) == 0


# =====================================================================
# System-Python minimal script (TEMPORARY)
# =====================================================================


def test_system_minimal_script_exists():
    assert SYSTEM_MINIMAL_PATH.is_file(), (
        "scripts/_phase5fc_system_minimal.py must exist for TEST B"
    )


def test_system_minimal_script_only_imports_os():
    tree = ast.parse(_read(SYSTEM_MINIMAL_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name == "os", (
                    f"system minimal script imports {alias.name!r}"
                )
        elif isinstance(node, ast.ImportFrom):
            raise AssertionError(
                "system minimal script must not use from-imports"
            )


def test_system_minimal_script_no_subprocess():
    tree = ast.parse(_read(SYSTEM_MINIMAL_PATH))
    assert _module_has_no_import(tree, "subprocess")


def test_system_minimal_script_no_ctypes():
    tree = ast.parse(_read(SYSTEM_MINIMAL_PATH))
    assert _module_has_no_import(tree, "ctypes")


def test_system_minimal_script_no_shell():
    tree = ast.parse(_read(SYSTEM_MINIMAL_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os":
                assert node.attr not in (
                    "system", "popen", "spawnl", "spawnv",
                    "spawnve", "exec", "execl", "execv", "execvp",
                )


def test_system_minimal_script_does_not_read_sys_argv():
    tree = ast.parse(_read(SYSTEM_MINIMAL_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "argv":
            raise AssertionError(
                "system minimal script must not read argv"
            )


def test_system_minimal_script_writes_fixed_output_path():
    src = _read(SYSTEM_MINIMAL_PATH)
    assert "phase5fc_system_minimal.txt" in src
    tree = ast.parse(src)
    has_open = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == "open":
                has_open = True
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(
                        arg.value, str,
                    ):
                        assert arg.value == EXPECTED_SYSTEM_MINIMAL_OUTPUT_PATH
    assert has_open


def test_system_minimal_script_writes_username_and_pid():
    """The script must write USERNAME= and PID= lines."""
    src = _read(SYSTEM_MINIMAL_PATH)
    assert "USERNAME=" in src
    assert "PID=" in src
    assert "os.getpid()" in src


def test_system_minimal_script_path_not_from_env():
    tree = ast.parse(_read(SYSTEM_MINIMAL_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == "open":
                all_args = list(node.args) + [
                    kw.value for kw in node.keywords
                ]
                for arg in all_args:
                    for inner in ast.walk(arg):
                        if (
                            isinstance(inner, ast.Attribute)
                            and inner.attr == "environ"
                        ):
                            raise AssertionError(
                                "system minimal script must not use "
                                "os.environ to build its output path"
                            )


def test_system_minimal_script_has_no_arguments():
    mod = importlib.util.spec_from_file_location(
        "_system_minimal_for_tests", SYSTEM_MINIMAL_PATH
    )
    m = importlib.util.module_from_spec(mod)
    sys.modules["_system_minimal_for_tests"] = m
    try:
        mod.loader.exec_module(m)
    except BaseException:
        sys.modules.pop("_system_minimal_for_tests", None)
        raise
    if hasattr(m, "main"):
        sig = _inspect.signature(m.main)
        assert len(sig.parameters) == 0


# =====================================================================
# Probe
# =====================================================================


def test_probe_file_exists():
    assert PROBE_PATH.is_file()


def test_probe_does_not_import_subprocess():
    tree = ast.parse(_read(PROBE_PATH))
    assert _module_has_no_import(tree, "subprocess")


def test_probe_does_not_use_os_system_or_popen():
    tree = ast.parse(_read(PROBE_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os":
                assert node.attr not in ("system", "popen")


def test_probe_does_not_read_sys_argv():
    tree = ast.parse(_read(PROBE_PATH))
    sys_module_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sys":
                    sys_module_names.add(alias.asname or "sys")

    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "argv":
            v = node.value
            if isinstance(v, ast.Name) and v.id in sys_module_names:
                findings.append(f"{v.id}.argv")
        elif isinstance(node, ast.ImportFrom) and node.module == "sys":
            for alias in node.names:
                if alias.name == "argv":
                    findings.append("from sys import argv")
    assert findings == []


def _load_probe_module(name: str):
    spec = importlib.util.spec_from_file_location(name, PROBE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return mod


def test_probe_main_takes_no_arguments():
    m = _load_probe_module("_probe_for_tests")
    sig = _inspect.signature(m.main)
    assert len(sig.parameters) == 0


def test_probe_collect_takes_no_arguments():
    m = _load_probe_module("_probe_for_tests2")
    sig = _inspect.signature(m.collect)
    assert len(sig.parameters) == 0


def test_probe_collect_returns_expected_keys():
    m = _load_probe_module("_probe_for_tests3")
    info = m.collect()
    assert set(info.keys()) == {
        "username", "userdomain", "computername",
        "sid", "is_elevated", "is_admin_member", "pid",
    }


# =====================================================================
# Probe: fixed hold-open
# =====================================================================


def test_probe_has_fixed_hold_constant():
    tree = ast.parse(_read(PROBE_PATH))
    assign, value = _find_module_constant(tree, "PROBE_HOLD_SECONDS")
    assert assign is not None
    assert isinstance(value, ast.Constant)
    assert value.value == 20


def test_probe_main_sleeps_once_with_fixed_constant():
    tree = ast.parse(_read(PROBE_PATH))
    main_fn = _find_function(tree, "main")
    assert main_fn is not None
    sleep_calls = []
    for node in ast.walk(main_fn):
        if isinstance(node, ast.Call):
            fn = node.func
            if (
                isinstance(fn, ast.Attribute)
                and fn.attr == "sleep"
                and isinstance(fn.value, ast.Name)
                and fn.value.id == "time"
            ):
                sleep_calls.append(node)
    assert len(sleep_calls) == 1


def test_probe_sleep_is_not_configurable():
    src = _read(PROBE_PATH)
    tree = ast.parse(src)
    sys_module_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sys":
                    sys_module_names.add(alias.asname or "sys")
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "argv":
            v = node.value
            if isinstance(v, ast.Name) and v.id in sys_module_names:
                raise AssertionError("probe must not read sys.argv")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == "input":
                raise AssertionError("probe must not call input()")


def test_probe_flushes_stdout_before_sleeping():
    tree = ast.parse(_read(PROBE_PATH))
    main_fn = _find_function(tree, "main")
    assert main_fn is not None
    last_flush_line = -1
    sleep_line = -1
    for node in ast.walk(main_fn):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute):
                if fn.attr == "flush":
                    last_flush_line = max(last_flush_line, node.lineno)
                if (
                    fn.attr == "sleep"
                    and isinstance(fn.value, ast.Name)
                    and fn.value.id == "time"
                ):
                    sleep_line = node.lineno
    assert last_flush_line > 0
    assert sleep_line > 0
    assert last_flush_line < sleep_line


def test_probe_has_fixed_output_path_constant():
    tree = ast.parse(_read(PROBE_PATH))
    assign, value = _find_module_constant(tree, "OUTPUT_PATH")
    assert assign is not None
    assert isinstance(value, ast.Constant)
    assert value.value == EXPECTED_OUTPUT_PATH


def test_probe_has_fixed_output_dir_constant():
    tree = ast.parse(_read(PROBE_PATH))
    assign, value = _find_module_constant(tree, "OUTPUT_DIR")
    assert assign is not None
    assert isinstance(value, ast.Constant)
    assert value.value == EXPECTED_OUTPUT_DIR


def test_probe_output_path_is_not_derived_from_external_input():
    tree = ast.parse(_read(PROBE_PATH))
    for name in ("OUTPUT_PATH", "OUTPUT_DIR"):
        _, value = _find_module_constant(tree, name)
        assert isinstance(value, ast.Constant)
        for node in ast.walk(value):
            if isinstance(node, ast.Attribute) and node.attr in (
                "environ", "argv",
            ):
                raise AssertionError(
                    f"{name} must not read {node.attr}"
                )


def test_probe_has_write_identity_function():
    tree = ast.parse(_read(PROBE_PATH))
    fn = _find_function(tree, "_write_identity")
    assert fn is not None
    args = [a.arg for a in fn.args.args]
    assert args == ["info"]


def test_probe_write_identity_only_uses_fixed_paths():
    tree = ast.parse(_read(PROBE_PATH))
    fn = _find_function(tree, "_write_identity")
    assert fn is not None
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "OUTPUT_PATH" in names
    assert "OUTPUT_DIR" in names
    assert "DIAG_PATH" in names


def test_probe_write_is_atomic_via_replace():
    tree = ast.parse(_read(PROBE_PATH))
    fn = _find_function(tree, "_write_identity")
    assert fn is not None
    has_replace = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            fn2 = node.func
            if (
                isinstance(fn2, ast.Attribute)
                and fn2.attr == "replace"
                and isinstance(fn2.value, ast.Name)
                and fn2.value.id == "os"
            ):
                has_replace = True
    assert has_replace


def test_probe_main_writes_before_sleeping():
    tree = ast.parse(_read(PROBE_PATH))
    main_fn = _find_function(tree, "main")
    assert main_fn is not None
    write_line = -1
    sleep_line = -1
    for node in ast.walk(main_fn):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id == "_write_identity":
                write_line = max(write_line, node.lineno)
            if (
                isinstance(fn, ast.Attribute)
                and fn.attr == "sleep"
                and isinstance(fn.value, ast.Name)
                and fn.value.id == "time"
            ):
                sleep_line = node.lineno
    assert write_line > 0
    assert sleep_line > 0
    assert write_line < sleep_line


def test_probe_has_fixed_diag_path_constant():
    tree = ast.parse(_read(PROBE_PATH))
    assign, value = _find_module_constant(tree, "DIAG_PATH")
    assert assign is not None
    assert isinstance(value, ast.Constant)
    assert value.value == EXPECTED_DIAG_PATH


def test_probe_diag_path_is_not_derived_from_external_input():
    tree = ast.parse(_read(PROBE_PATH))
    _, value = _find_module_constant(tree, "DIAG_PATH")
    assert isinstance(value, ast.Constant)
    for node in ast.walk(value):
        if isinstance(node, ast.Attribute) and node.attr in (
            "environ", "argv",
        ):
            raise AssertionError(
                f"DIAG_PATH must not read {node.attr}"
            )


def test_probe_has_write_diagnostic_function():
    tree = ast.parse(_read(PROBE_PATH))
    fn = _find_function(tree, "_write_diagnostic")
    assert fn is not None
    args = [a.arg for a in fn.args.args]
    assert args == ["exc"]


def test_probe_write_diagnostic_uses_only_fixed_path():
    tree = ast.parse(_read(PROBE_PATH))
    fn = _find_function(tree, "_write_diagnostic")
    assert fn is not None
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "DIAG_PATH" in names


def test_probe_write_identity_clears_stale_diag_before_write():
    tree = ast.parse(_read(PROBE_PATH))
    fn = _find_function(tree, "_write_identity")
    assert fn is not None
    has_remove_call = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            fn2 = node.func
            if (
                isinstance(fn2, ast.Name)
                and fn2.id == "_remove_file_quietly"
            ):
                if node.args and isinstance(node.args[0], ast.Name):
                    if node.args[0].id == "DIAG_PATH":
                        has_remove_call = True
    assert has_remove_call


def test_probe_write_identity_calls_diagnostic_on_failure():
    tree = ast.parse(_read(PROBE_PATH))
    fn = _find_function(tree, "_write_identity")
    assert fn is not None
    diag_calls = 0
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            fn2 = node.func
            if isinstance(fn2, ast.Name) and fn2.id == "_write_diagnostic":
                diag_calls += 1
    assert diag_calls >= 2


# =====================================================================
# Validator
# =====================================================================


def test_validator_has_fixed_output_path_constant():
    tree = ast.parse(_read(VALIDATE_PATH))
    assign, value = _find_module_constant(tree, "OUTPUT_PATH")
    assert assign is not None
    assert isinstance(value, ast.Constant)
    assert value.value == EXPECTED_OUTPUT_PATH


def test_validator_output_path_is_not_derived_from_external_input():
    tree = ast.parse(_read(VALIDATE_PATH))
    _, value = _find_module_constant(tree, "OUTPUT_PATH")
    assert isinstance(value, ast.Constant)
    for node in ast.walk(value):
        if isinstance(node, ast.Attribute) and node.attr in (
            "environ", "argv",
        ):
            raise AssertionError(
                f"OUTPUT_PATH must not read {node.attr}"
            )


def test_validator_has_no_runtime_output_path_constant():
    tree = ast.parse(_read(VALIDATE_PATH))
    assign, _ = _find_module_constant(tree, "RUNTIME_OUTPUT_PATH")
    assert assign is None


def test_validator_has_no_print_runtime_output_function():
    tree = ast.parse(_read(VALIDATE_PATH))
    fn = _find_function(tree, "_print_runtime_output")
    assert fn is None


def test_validator_has_minimal_output_path_constant():
    tree = ast.parse(_read(VALIDATE_PATH))
    assign, value = _find_module_constant(tree, "MINIMAL_OUTPUT_PATH")
    assert assign is not None
    assert isinstance(value, ast.Constant)
    assert value.value == EXPECTED_MINIMAL_OUTPUT_PATH


def test_validator_has_system_minimal_output_path_constant():
    tree = ast.parse(_read(VALIDATE_PATH))
    assign, value = _find_module_constant(tree, "SYSTEM_MINIMAL_OUTPUT_PATH")
    assert assign is not None
    assert isinstance(value, ast.Constant)
    assert value.value == EXPECTED_SYSTEM_MINIMAL_OUTPUT_PATH


def test_validator_calls_minimal_diagnostic():
    tree = ast.parse(_read(VALIDATE_PATH))
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if (
                isinstance(fn, ast.Attribute)
                and fn.attr == "launch_minimal_diagnostic"
            ):
                found = True
    assert found


def test_validator_calls_system_minimal_diagnostic():
    tree = ast.parse(_read(VALIDATE_PATH))
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if (
                isinstance(fn, ast.Attribute)
                and fn.attr == "launch_system_minimal_diagnostic"
            ):
                found = True
    assert found


def test_validator_reports_probe_exit_code():
    src = _read(VALIDATE_PATH)
    assert "Probe exit code" in src


def test_validator_reports_timeout_separately():
    src = _read(VALIDATE_PATH)
    assert "timed_out" in src
    assert "timed out" in src.lower()


def test_validator_uses_exit_code_from_result():
    src = _read(VALIDATE_PATH)
    assert "exit_code" in src


def test_validator_includes_exit_code_in_missing_file_failure():
    src = _read(VALIDATE_PATH)
    idx = src.find("did not write")
    assert idx > 0
    tail = src[idx:idx + 1500]
    assert "exit" in tail.lower()


def test_validator_reports_win32_error_on_cpwl_failure():
    src = _read(VALIDATE_PATH)
    assert "create_ok" in src
    assert "create_last_error" in src
    assert "Win32 error" in src or "win32 error" in src.lower()


def test_validator_removes_previous_file_before_launch():
    src = _read(VALIDATE_PATH)
    assert "os.remove" in src
    assert "OUTPUT_PATH" in src
    tree = ast.parse(src)
    fn = _find_function(tree, "_remove_previous")
    assert fn is not None


def test_validator_reads_fixed_output_path():
    src = _read(VALIDATE_PATH)
    assert "json.load" in src or "json.loads" in src
    tree = ast.parse(src)
    fn = _find_function(tree, "_read_identity")
    assert fn is not None


def test_validator_does_not_accept_user_arguments_beyond_reject():
    src = _read(VALIDATE_PATH)
    assert "len(sys.argv) > 1" in src
    assert "return 2" in src
    assert "launcher.launch_probe()" in src


def test_validator_imports_the_launcher_module():
    src = _read(VALIDATE_PATH)
    assert "import launch_lumi_as_runtime" in src