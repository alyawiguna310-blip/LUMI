"""
Phase 5A regression tests: control-plane classification.

These tests exercise security.control_plane.is_control_plane() only.
They do not exercise the gate; the gate-level check is Phase 5B.

The tests are path-based, not existence-based: a protected path is
classified as control plane whether or not the underlying file exists.
"""
import os
import sys
from pathlib import Path

import pytest

from security import control_plane as cp


ROOT = Path(cp.project_root())


def _p(*parts) -> str:
    return str(ROOT.joinpath(*parts))


# =====================================================================
# Canonical list sanity
# =====================================================================


def test_protected_dirs_includes_security_directory():
    dirs = cp.protected_dirs()
    assert any(d.endswith(os.sep + "security") for d in dirs), dirs


def test_protected_files_contains_expected_entries():
    files = set(cp.protected_files())
    for name in ("main.py", "config.py", ".env",
                 os.path.join("core", "tool_router.py"),
                 os.path.join("tools", "admin_tasks.py"),
                 os.path.join("tools", "terminal_guard.py"),
                 os.path.join("storage", "audit.py")):
        expected = os.path.normcase(
            os.path.normpath(str(ROOT / name))
        )
        assert expected in files, f"missing protected entry: {name}"


# =====================================================================
# Files explicitly listed as control plane
# =====================================================================


EXPLICIT_PROTECTED_FILES = [
    ("main.py",),
    ("config.py",),
    (".env",),
    ("core", "tool_router.py"),
    ("tools", "admin_tasks.py"),
    ("tools", "terminal_guard.py"),
    ("storage", "audit.py"),
]


@pytest.mark.parametrize("parts", EXPLICIT_PROTECTED_FILES,
                         ids=["-".join(p) for p in EXPLICIT_PROTECTED_FILES])
def test_explicit_protected_file_classified(parts):
    assert cp.is_control_plane(_p(*parts)) is True


def test_env_classified_even_if_absent():
    """Classification is path-based, not existence-based."""
    env_path = _p(".env")
    # We do not assert existence; only that classification is True.
    assert cp.is_control_plane(env_path) is True


# =====================================================================
# security/ recursion
# =====================================================================


SECURITY_FILES = [
    ("security", "gate.py"),
    ("security", "permissions.py"),
    ("security", "descriptor.py"),
    ("security", "grants.py"),
    ("security", "confirmation.py"),
    ("security", "tokens.py"),
    ("security", "path_rules.py"),
    ("security", "protected_paths.py"),
    ("security", "sandbox.py"),
    ("security", "system_patterns.py"),
    ("security", "privileged_protocol.py"),
    ("security", "privileged_pipe.py"),
    ("security", "privileged_ops.py"),
    ("security", "privileged_helper.py"),
    ("security", "privileged_client.py"),
    ("security", "__init__.py"),
    ("security", "control_plane.py"),
]


@pytest.mark.parametrize("parts", SECURITY_FILES,
                         ids=["-".join(p) for p in SECURITY_FILES])
def test_security_directory_files_classified(parts):
    assert cp.is_control_plane(_p(*parts)) is True


def test_security_directory_itself_classified():
    assert cp.is_control_plane(_p("security")) is True


def test_deeply_nested_under_security_classified():
    # A file in a subdirectory that may not exist yet.
    assert cp.is_control_plane(
        _p("security", "subdir", "anything.py")
    ) is True
    assert cp.is_control_plane(
        _p("security", "x", "y", "z", "file.txt")
    ) is True


# =====================================================================
# Normal application files must NOT be classified
# =====================================================================


NON_CONTROL_FILES = [
    ("workspace", "app.py"),
    ("workspace", "subdir", "helper.py"),
    ("tools", "filesystem.py"),
    ("tools", "terminal.py"),
    ("tools", "applications.py"),
    ("core", "assistant.py"),
    ("core", "events.py"),
    ("core", "memory.py"),
    ("core", "state.py"),
    ("storage", "logs.py"),
    ("storage", "terminal_log.py"),
    ("ui", "minimal_window.py"),
    ("voice", "recorder.py"),
    ("ai", "provider.py"),
]


@pytest.mark.parametrize("parts", NON_CONTROL_FILES,
                         ids=["-".join(p) for p in NON_CONTROL_FILES])
def test_normal_application_files_not_classified(parts):
    assert cp.is_control_plane(_p(*parts)) is False


def test_sibling_named_security_notes_is_not_control_plane():
    """`D:\\Lumi\\security_notes.txt` is not inside `D:\\Lumi\\security`."""
    assert cp.is_control_plane(_p("security_notes.txt")) is False


def test_dir_named_securityX_is_not_control_plane():
    """A directory whose name begins with `security` but is not the
    `security` directory must not be classified."""
    assert cp.is_control_plane(
        _p("securityX", "gate.py")
    ) is False


# =====================================================================
# Path aliases
# =====================================================================


def test_traversal_alias_does_not_bypass():
    alias = str(ROOT / "workspace" / ".." / "security" / "gate.py")
    assert cp.is_control_plane(alias) is True


def test_traversal_alias_with_multiple_updirs():
    alias = str(ROOT / "workspace" / "sub" / ".." / ".." / "security"
                / "tokens.py")
    assert cp.is_control_plane(alias) is True


def test_forward_slash_variant():
    alias = "/".join([str(ROOT), "security", "gate.py"])
    assert cp.is_control_plane(alias) is True


def test_mixed_separator_variant():
    alias = str(ROOT) + "/security\\gate.py"
    assert cp.is_control_plane(alias) is True


def test_relative_dot_prefix(tmp_path, monkeypatch):
    # Change cwd to ROOT, use a relative path.
    monkeypatch.chdir(ROOT)
    assert cp.is_control_plane(
        os.path.join(".", "security", "gate.py")
    ) is True


@pytest.mark.skipif(sys.platform != "win32",
                    reason="case-insensitive path check on Windows")
def test_case_insensitive_upper():
    alias = str(ROOT / "SECURITY" / "GATE.PY")
    assert cp.is_control_plane(alias) is True


@pytest.mark.skipif(sys.platform != "win32",
                    reason="case-insensitive path check on Windows")
def test_case_insensitive_mixed():
    alias = str(ROOT).upper() + "\\security\\TokeNs.Py"
    assert cp.is_control_plane(alias) is True


# =====================================================================
# Fail-closed behavior
# =====================================================================


def test_none_is_control_plane():
    assert cp.is_control_plane(None) is True


def test_empty_string_is_control_plane():
    assert cp.is_control_plane("") is True


def test_whitespace_only_is_control_plane():
    assert cp.is_control_plane("   ") is True


# =====================================================================
# describe() shape
# =====================================================================


def test_describe_returns_expected_keys():
    d = cp.describe()
    assert set(d.keys()) == {
        "project_root", "protected_dirs", "protected_files",
    }
    assert isinstance(d["project_root"], str)
    assert isinstance(d["protected_dirs"], list)
    assert isinstance(d["protected_files"], list)
    assert len(d["protected_dirs"]) >= 1
    assert len(d["protected_files"]) >= 7