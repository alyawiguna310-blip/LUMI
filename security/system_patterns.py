"""Detect system-looking paths that always require confirmation."""
import os
from pathlib import Path


_SYSTEM_PATH_COMPONENTS = {
    "windows", "system32", "syswow64", "winsxs", "drivers",
    "program files", "program files (x86)", "programdata",
    "boot", "recovery", "efi", "system volume information",
}

_SYSTEM_FILENAMES = {
    "sam", "system", "security", "software", "default",
    "bootmgr", "bootnxt", "boot.ini", "bcd", "ntldr", "ntdetect.com",
    "pagefile.sys", "hiberfil.sys", "swapfile.sys",
}

_SYSTEM_EXTENSIONS = {
    ".dll", ".sys", ".drv", ".ocx", ".cpl", ".msi",
    ".reg", ".inf", ".scr",
}


def is_system_looking(path: str) -> tuple[bool, str]:
    try:
        p = Path(path)
    except Exception:
        return False, ""

    for part in p.parts:
        low = part.lower().strip()
        if low in _SYSTEM_PATH_COMPONENTS:
            return True, f"path contains system folder '{part}'"

    fname = p.name.lower()
    if fname in _SYSTEM_FILENAMES:
        return True, f"filename '{p.name}' is a known system file"

    ext = p.suffix.lower()
    if ext in _SYSTEM_EXTENSIONS:
        return True, f"extension '{p.suffix}' is system-related"

    return False, ""