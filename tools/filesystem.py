"""
Filesystem tools. Every operation routes through the SecurityGate.

Tools:
  filesystem.list_dir   SAFE
  filesystem.read       SAFE
  filesystem.write      DISRUPTIVE
  filesystem.create_dir DISRUPTIVE
  filesystem.rename     DISRUPTIVE
  filesystem.move       DISRUPTIVE
  filesystem.delete     DESTRUCTIVE
"""
import logging
import shutil
from pathlib import Path

from security.descriptor import Origin
from security.gate import SecurityGate, ToolRequest, ToolResult, ToolSpec
from security.permissions import PermissionLevel

logger = logging.getLogger(__name__)


LIST_DIR_SPEC = ToolSpec(
    name="filesystem.list_dir",
    level=PermissionLevel.SAFE,
    path_params=["path"],
    description="List directory contents. Read-only.",
)
READ_SPEC = ToolSpec(
    name="filesystem.read",
    level=PermissionLevel.SAFE,
    path_params=["path"],
    description="Read a text file. Read-only.",
)
WRITE_SPEC = ToolSpec(
    name="filesystem.write",
    level=PermissionLevel.DISRUPTIVE,
    path_params=["path"],
    description="Write text to a file. Overwrites by default.",
)
CREATE_DIR_SPEC = ToolSpec(
    name="filesystem.create_dir",
    level=PermissionLevel.DISRUPTIVE,
    path_params=["path"],
    description="Create a directory (and parents).",
)
RENAME_SPEC = ToolSpec(
    name="filesystem.rename",
    level=PermissionLevel.DISRUPTIVE,
    path_params=["old_path", "new_path"],
    description="Rename a file or directory.",
)
MOVE_SPEC = ToolSpec(
    name="filesystem.move",
    level=PermissionLevel.DISRUPTIVE,
    path_params=["src", "dest"],
    description="Move a file or directory.",
)
DELETE_SPEC = ToolSpec(
    name="filesystem.delete",
    level=PermissionLevel.DESTRUCTIVE,
    path_params=["path"],
    description="Delete a file or folder. Subject to security checks.",
)


def _do_list_dir(args: dict) -> dict:
    path = Path(args["path"])
    if not path.exists():
        return {"path": str(path), "exists": False, "entries": []}
    if not path.is_dir():
        return {"path": str(path), "exists": True, "error": "not a directory",
                "entries": []}
    entries = []
    try:
        for child in sorted(path.iterdir(), key=lambda p: p.name.lower()):
            try:
                st = child.stat()
                kind = "dir" if child.is_dir() else "file"
                entries.append({"name": child.name, "kind": kind, "size": st.st_size})
            except Exception:
                entries.append({"name": child.name, "kind": "unknown", "size": 0})
    except Exception as e:
        return {"path": str(path), "exists": True, "error": str(e), "entries": []}
    return {"path": str(path), "exists": True, "entries": entries}


def _do_read(args: dict) -> dict:
    path = Path(args["path"])
    max_bytes = int(args.get("max_bytes", 4096))
    max_bytes = max(1, min(max_bytes, 65536))

    if not path.exists():
        return {"path": str(path), "exists": False, "error": "file does not exist"}
    if not path.is_file():
        return {"path": str(path), "exists": True, "error": "not a file"}
    try:
        size = path.stat().st_size
    except Exception as e:
        return {"path": str(path), "exists": True, "error": f"stat failed: {e}"}
    truncated = size > max_bytes
    try:
        raw = path.read_bytes()
    except Exception as e:
        return {"path": str(path), "exists": True, "error": f"read failed: {e}"}
    chunk = raw[:max_bytes]
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = chunk.decode("latin-1")
        except Exception:
            return {"path": str(path), "exists": True, "size": size,
                    "binary": True, "error": "file is not text-decodable"}
    return {"path": str(path), "exists": True, "size": size,
            "bytes_read": len(chunk), "truncated": truncated, "content": text}


def _do_write(args: dict) -> dict:
    path = Path(args["path"])
    content = args.get("content", "")
    mode = (args.get("mode") or "overwrite").lower()
    if not isinstance(content, str):
        return {"written": False, "error": "content must be a string"}
    if mode not in ("overwrite", "append"):
        return {"written": False, "error": f"invalid mode: {mode!r}"}

    parent = path.parent
    if not parent.exists():
        return {"written": False, "error": f"parent directory does not exist: {parent}"}

    try:
        if mode == "append":
            with open(path, "a", encoding="utf-8") as f:
                f.write(content)
        else:
            path.write_text(content, encoding="utf-8")
    except Exception as e:
        return {"written": False, "error": f"write failed: {e}"}

    try:
        size = path.stat().st_size
    except Exception:
        size = -1
    return {"written": True, "mode": mode, "path": str(path),
            "bytes": len(content.encode("utf-8")), "size": size}


def _do_create_dir(args: dict) -> dict:
    path = Path(args["path"])
    if path.exists():
        return {"created": False, "reason": "already exists", "path": str(path)}
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return {"created": False, "error": str(e), "path": str(path)}
    return {"created": True, "path": str(path)}


def _do_rename(args: dict) -> dict:
    old = Path(args["old_path"])
    new = Path(args["new_path"])
    if not old.exists():
        return {"renamed": False, "reason": "source does not exist", "old": str(old)}
    if new.exists():
        return {"renamed": False, "reason": "destination already exists", "new": str(new)}
    if not new.parent.exists():
        return {"renamed": False, "reason": "destination parent does not exist"}
    try:
        old.rename(new)
    except Exception as e:
        return {"renamed": False, "error": str(e)}
    return {"renamed": True, "old": str(old), "new": str(new)}


def _do_move(args: dict) -> dict:
    src = Path(args["src"])
    dest = Path(args["dest"])
    if not src.exists():
        return {"moved": False, "reason": "source does not exist", "src": str(src)}
    if dest.exists():
        return {"moved": False, "reason": "destination already exists", "dest": str(dest)}
    if not dest.parent.exists():
        return {"moved": False, "reason": "destination parent does not exist"}
    try:
        shutil.move(str(src), str(dest))
    except Exception as e:
        return {"moved": False, "error": str(e)}
    return {"moved": True, "src": str(src), "dest": str(dest)}


def _do_delete(args: dict) -> dict:
    path = Path(args["path"])
    if not path.exists() and not path.is_symlink():
        return {"deleted": False, "reason": "does not exist", "path": str(path)}
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
        return {"deleted": True, "kind": "dir", "path": str(path)}
    path.unlink()
    return {"deleted": True, "kind": "file", "path": str(path)}


def register(gate: SecurityGate):
    for spec in (LIST_DIR_SPEC, READ_SPEC, WRITE_SPEC, CREATE_DIR_SPEC,
                 RENAME_SPEC, MOVE_SPEC, DELETE_SPEC):
        gate.register_tool(spec)


def list_dir(path, gate, originating_source=Origin.AI_INTERNAL.value):
    return gate.execute(
        ToolRequest(LIST_DIR_SPEC.name, {"path": path},
                    originating_source=originating_source),
        _do_list_dir)


def read(path, gate, max_bytes=4096, originating_source=Origin.AI_INTERNAL.value):
    return gate.execute(
        ToolRequest(READ_SPEC.name, {"path": path, "max_bytes": max_bytes},
                    originating_source=originating_source),
        _do_read)


def write(path, content, gate, mode="overwrite",
          originating_source=Origin.AI_INTERNAL.value):
    return gate.execute(
        ToolRequest(WRITE_SPEC.name,
                    {"path": path, "content": content, "mode": mode},
                    originating_source=originating_source),
        _do_write)


def create_dir(path, gate, originating_source=Origin.AI_INTERNAL.value):
    return gate.execute(
        ToolRequest(CREATE_DIR_SPEC.name, {"path": path},
                    originating_source=originating_source),
        _do_create_dir)


def rename(old_path, new_path, gate,
           originating_source=Origin.AI_INTERNAL.value):
    return gate.execute(
        ToolRequest(RENAME_SPEC.name,
                    {"old_path": old_path, "new_path": new_path},
                    originating_source=originating_source),
        _do_rename)


def move(src, dest, gate, originating_source=Origin.AI_INTERNAL.value):
    return gate.execute(
        ToolRequest(MOVE_SPEC.name, {"src": src, "dest": dest},
                    originating_source=originating_source),
        _do_move)


def delete_file(path, gate, originating_source=Origin.AI_INTERNAL.value):
    return gate.execute(
        ToolRequest(DELETE_SPEC.name, {"path": path},
                    originating_source=originating_source),
        _do_delete)