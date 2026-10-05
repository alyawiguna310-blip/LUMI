"""Sandbox boundary tests. These do NOT need F:\\ — they use tmp_path."""
import os
import sys

import pytest

from security.sandbox import check_sandbox, canonicalize


@pytest.fixture
def sandbox_root(tmp_path):
    root = tmp_path / "Sandbox"
    root.mkdir()
    (root / "inside.txt").write_text("hello")
    (root / "sub").mkdir()
    (root / "sub" / "nested.txt").write_text("nested")
    return str(root)


def test_inside_sandbox_allowed(sandbox_root):
    r = check_sandbox(os.path.join(sandbox_root, "inside.txt"),
                      sandbox_root, enabled=True)
    assert r.allowed, r.reason


def test_sandbox_root_itself_allowed(sandbox_root):
    r = check_sandbox(sandbox_root, sandbox_root, enabled=True)
    assert r.allowed, r.reason


def test_subfolder_inside_allowed(sandbox_root):
    r = check_sandbox(os.path.join(sandbox_root, "sub", "nested.txt"),
                      sandbox_root, enabled=True)
    assert r.allowed, r.reason


def test_outside_sandbox_denied(sandbox_root, tmp_path):
    other = tmp_path / "Elsewhere"
    other.mkdir()
    (other / "file.txt").write_text("outside")
    r = check_sandbox(str(other / "file.txt"), sandbox_root, enabled=True)
    assert not r.allowed


def test_parent_of_sandbox_denied(sandbox_root, tmp_path):
    # tmp_path is the parent of sandbox
    r = check_sandbox(str(tmp_path), sandbox_root, enabled=True)
    assert not r.allowed


def test_relative_outside_denied(sandbox_root, monkeypatch, tmp_path):
    # Change cwd to somewhere outside the sandbox; a relative path must fail.
    other = tmp_path / "Elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    r = check_sandbox("somefile.txt", sandbox_root, enabled=True)
    assert not r.allowed


def test_relative_inside_allowed(sandbox_root, monkeypatch):
    monkeypatch.chdir(sandbox_root)
    r = check_sandbox("inside.txt", sandbox_root, enabled=True)
    assert r.allowed, r.reason


def test_disabled_sandbox_allows_everything():
    r = check_sandbox(r"C:\somewhere\file.txt", "F:\\", enabled=False)
    assert r.allowed


def test_empty_root_with_sandbox_enabled_denies():
    r = check_sandbox(r"C:\file.txt", "", enabled=True)
    assert not r.allowed


def test_none_path_denied(sandbox_root):
    r = check_sandbox(None, sandbox_root, enabled=True)
    assert not r.allowed


def test_empty_path_denied(sandbox_root):
    r = check_sandbox("", sandbox_root, enabled=True)
    assert not r.allowed


def test_traversal_outside_denied(sandbox_root, tmp_path):
    # Try to escape via ..
    sneaky = os.path.join(sandbox_root, "..", "Elsewhere", "file.txt")
    (tmp_path / "Elsewhere").mkdir(exist_ok=True)
    (tmp_path / "Elsewhere" / "file.txt").write_text("x")
    r = check_sandbox(sneaky, sandbox_root, enabled=True)
    assert not r.allowed


def test_similar_name_not_inside(sandbox_root, tmp_path):
    # Folder "Sandbox2" is NOT inside "Sandbox"
    sib = tmp_path / "Sandbox2"
    sib.mkdir()
    (sib / "file.txt").write_text("x")
    r = check_sandbox(str(sib / "file.txt"), sandbox_root, enabled=True)
    assert not r.allowed


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
def test_case_insensitive_inside(sandbox_root):
    upper = sandbox_root.upper()
    r = check_sandbox(os.path.join(upper, "inside.txt"),
                      sandbox_root, enabled=True)
    assert r.allowed, r.reason


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
def test_symlink_escape_denied(sandbox_root, tmp_path):
    """A symlink inside the sandbox pointing outside must be denied."""
    outside = tmp_path / "Outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")

    link = os.path.join(sandbox_root, "escape_link")
    try:
        os.symlink(str(outside), link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not permitted (no developer mode)")

    # Canonicalized path follows the symlink to the outside folder
    target = os.path.join(link, "secret.txt")
    r = check_sandbox(target, sandbox_root, enabled=True)
    assert not r.allowed, "symlink escape not caught!"


def test_canonicalize_returns_absolute(sandbox_root):
    c = canonicalize(".")
    assert os.path.isabs(c)