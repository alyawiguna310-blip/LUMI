"""
Phase 6 test harness — LLM tool calling through the SecurityGate.

Uses a FakeLLMProvider so tests are deterministic and don't call Gemini.
"""
import json
import sys
from pathlib import Path

from ai.provider import ChatMessage, ChatResponse, LLMProvider, ToolCall
from core.tool_router import ToolRouter
from security.confirmation import (
    ConfirmationManager, ConfirmationRequest, ConfirmationResponse,
)
from security.gate import SecurityGate
from security.permissions import PermissionLevel, PermissionPolicy
from tools import filesystem


SANDBOX = "F:\\"
PROTECTED = "D:\\"


# ---------------------------------------------------------------- fake LLM

class FakeLLMProvider(LLMProvider):
    def __init__(self, scripted):
        self._scripted = list(scripted)
        self.calls: list[list[str]] = []

    def is_available(self):
        return True

    def supports_tools(self):
        return True

    def chat(self, messages, max_tokens=300):
        self.calls.append([m.role for m in messages])
        if not self._scripted:
            return ChatResponse(text="(no more scripted responses)")
        return self._scripted.pop(0)


# ---------------------------------------------------------------- helpers

def make_router(auto_approve=False, capture=None):
    policy = PermissionPolicy(auto_approve_max=PermissionLevel.NORMAL)
    mgr = ConfirmationManager()

    def handler(req: ConfirmationRequest):
        if capture is not None:
            capture.append(req)
        return ConfirmationResponse(
            approved=auto_approve,
            note="auto-approved" if auto_approve else "user-denied",
        )

    mgr.set_handler(handler)
    gate = SecurityGate(
        protected_folder=PROTECTED,
        sandbox_root=SANDBOX,
        sandbox_enabled=True,
        policy=policy,
        confirmation=mgr,
    )
    filesystem.register(gate)
    return ToolRouter(gate)


def setup_files():
    targets = {
        r"F:\TestProject\example.txt": "hello from test",
        r"F:\TestProject\junk.txt": "junk",
        r"F:\TestProject\scratch\deep.txt": "nested",
        r"F:\ImportantFiles\important.txt": "important content",
    }
    for p, content in targets.items():
        path = Path(p)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


RESULTS = {"pass": 0, "fail": 0, "skip": 0}


def check(desc, condition, detail=""):
    if condition:
        mark = "PASS"
        RESULTS["pass"] += 1
    else:
        mark = "FAIL"
        RESULTS["fail"] += 1
    print(f"  [{mark}] {desc}")
    if detail and not condition:
        print(f"         {detail}")


def skip(desc):
    RESULTS["skip"] += 1
    print(f"  [SKIP] {desc}")


# ---------------------------------------------------------------- main

def main():
    print("=" * 66)
    print("  PHASE 6 — TOOL CALLING THROUGH THE SECURITY GATE")
    print("=" * 66)
    print()

    setup_files()
    print("Test files prepared under F:\\TestProject and F:\\ImportantFiles.")
    print()

    # ---------------- 1. list_dir ----------------
    print("[1] list_dir F:\\TestProject (allowed, no confirmation)")
    router = make_router(auto_approve=False)
    r = router.route("filesystem.list_dir", {"path": "F:\\TestProject"})
    check("ok=True", r.get("ok") is True, json.dumps(r))
    entries = r.get("output", {}).get("entries", [])
    names = [e["name"] for e in entries]
    check("example.txt listed", "example.txt" in names, f"entries={names}")

    # ---------------- 2. read ----------------
    print("\n[2] read F:\\TestProject\\example.txt (allowed)")
    r = router.route("filesystem.read", {"path": "F:\\TestProject\\example.txt"})
    check("ok=True", r.get("ok") is True, json.dumps(r))
    check("content correct",
          r.get("output", {}).get("content", "").startswith("hello"),
          json.dumps(r))

    # ---------------- 3. delete TestProject (path rule allow) ----------------
    print("\n[3] delete F:\\TestProject\\junk.txt (allow rule → no confirmation)")
    setup_files()
    captured = []
    router_allow = make_router(auto_approve=False, capture=captured)
    r = router_allow.route("filesystem.delete", {"path": "F:\\TestProject\\junk.txt"})
    check("ok=True", r.get("ok") is True, json.dumps(r))
    check("no confirmation requested", len(captured) == 0,
          f"captured={len(captured)}")
    check("file deleted", not Path(r"F:\TestProject\junk.txt").exists())

    # ---------------- 4. delete ImportantFiles → approve ----------------
    print("\n[4] delete F:\\ImportantFiles\\important.txt (confirm → approve)")
    setup_files()
    captured = []
    router_approve = make_router(auto_approve=True, capture=captured)
    r = router_approve.route("filesystem.delete",
                             {"path": "F:\\ImportantFiles\\important.txt"})
    check("ok=True", r.get("ok") is True, json.dumps(r))
    check("confirmation requested", len(captured) == 1,
          f"captured={len(captured)}")
    check("file deleted", not Path(r"F:\ImportantFiles\important.txt").exists())

    # ---------------- 5. delete ImportantFiles → deny ----------------
    print("\n[5] delete F:\\ImportantFiles\\important.txt (confirm → deny)")
    setup_files()
    captured = []
    router_deny = make_router(auto_approve=False, capture=captured)
    r = router_deny.route("filesystem.delete",
                          {"path": "F:\\ImportantFiles\\important.txt"})
    check("ok=False", r.get("ok") is False, json.dumps(r))
    check("status=denied", r.get("status") == "denied", json.dumps(r))
    check("file NOT deleted", Path(r"F:\ImportantFiles\important.txt").exists())

    # ---------------- 6. delete ImportantFiles (confirmation_needed flag) -----
    print("\n[6] confirmation_needed flag set on denial")
    r = router_deny.route("filesystem.delete",
                          {"path": "F:\\ImportantFiles\\important.txt"})
    check("confirmation_needed=True",
          r.get("confirmation_needed") is True, json.dumps(r))

    # ---------------- 7. traversal via .. ----------------
    print("\n[7] traversal F:\\..\\Elsewhere\\file.txt")
    r = router_deny.route("filesystem.delete",
                          {"path": "F:\\..\\Elsewhere\\file.txt"})
    check("ok=False", r.get("ok") is False, json.dumps(r))
    check("status=denied", r.get("status") == "denied", json.dumps(r))

    # ---------------- 8. relative path escaping F:\ ----------------
    print("\n[8] relative ..\\..\\Windows\\notepad.exe (escapes sandbox)")
    r = router_deny.route("filesystem.delete",
                          {"path": "..\\..\\Windows\\notepad.exe"})
    check("ok=False", r.get("ok") is False, json.dumps(r))
    check("status=denied", r.get("status") == "denied", json.dumps(r))

    # ---------------- 9. symlink escape ----------------
    print("\n[9] symlink escape F:\\TestProject\\link_to_C")
    try:
        link = Path(r"F:\TestProject\link_to_C")
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to("C:\\Windows", target_is_directory=True)
        r = router_deny.route("filesystem.list_dir", {"path": str(link)})
        check("ok=False", r.get("ok") is False, json.dumps(r))
        check("status=denied", r.get("status") == "denied", json.dumps(r))
        link.unlink()
    except (OSError, NotImplementedError) as e:
        skip(f"symlink not permitted: {e}")

    # ---------------- 10. similar-name on wrong drive ----------------
    print("\n[10] C:\\Windows\\... looks similar but on wrong drive")
    r = router_deny.route("filesystem.list_dir", {"path": "C:\\Windows\\file.txt"})
    check("ok=False", r.get("ok") is False, json.dumps(r))
    check("status=denied", r.get("status") == "denied", json.dumps(r))

    # ---------------- 11. unknown tool ----------------
    print("\n[11] unknown tool: filesystem.write")
    r = router_deny.route("filesystem.write", {"path": "F:\\TestProject\\x.txt"})
    check("ok=False", r.get("ok") is False, json.dumps(r))
    check("status=invalid or unknown_tool",
          r.get("status") in ("invalid", "unknown_tool"), json.dumps(r))

    # ---------------- 12. malformed args ----------------
    print("\n[12a] missing required arg: read({})")
    r = router_deny.route("filesystem.read", {})
    check("ok=False", r.get("ok") is False, json.dumps(r))
    check("status=invalid", r.get("status") == "invalid", json.dumps(r))

    print("\n[12b] wrong type: read(path=123)")
    r = router_deny.route("filesystem.read", {"path": 123})
    check("ok=False", r.get("ok") is False, json.dumps(r))

    print("\n[12c] unexpected arg: read(path=..., bogus=...)")
    r = router_deny.route("filesystem.read",
                          {"path": "F:\\TestProject\\example.txt", "bogus": "x"})
    check("ok=False", r.get("ok") is False, json.dumps(r))

    print("\n[12d] empty path")
    r = router_deny.route("filesystem.read", {"path": ""})
    check("ok=False", r.get("ok") is False, json.dumps(r))

    # ---------------- 13. fake LLM loop with tool call ----------------
    print("\n[13] Fake LLM: emits read tool call, then final text")
    setup_files()
    scripted = [
        ChatResponse(
            text="",
            tool_calls=[ToolCall(
                name="filesystem.read",
                arguments={"path": "F:\\TestProject\\example.txt"},
            )],
        ),
        ChatResponse(text="The file says 'hello from test'."),
    ]
    provider = FakeLLMProvider(scripted)
    turn = [ChatMessage(role="system", content="test"),
            ChatMessage(role="user", content="what's in example.txt?")]
    tool_rounds = 0
    final = None
    for _ in range(5):
        resp = provider.chat(turn)
        if not resp.tool_calls:
            final = resp.text
            break
        turn.append(ChatMessage(role="assistant",
                                content=resp.text or "",
                                tool_calls=resp.tool_calls))
        for tc in resp.tool_calls:
            result = router_deny.route(tc.name, tc.arguments)
            turn.append(ChatMessage(role="tool",
                                    tool_name=tc.name,
                                    tool_result=result))
        tool_rounds += 1
    check("final text produced", final is not None, f"final={final}")
    check("used exactly 1 tool round", tool_rounds == 1, f"rounds={tool_rounds}")
    check("provider called twice", len(provider.calls) == 2, f"calls={provider.calls}")
    check("second call had 'tool' role in messages",
          len(provider.calls) >= 2 and "tool" in provider.calls[1],
          f"roles={provider.calls}")

    # ---------------- 14. C:\ denied with no leak ----------------
    print("\n[14] C:\\ path denied, no contents leaked")
    r = router_deny.route("filesystem.list_dir", {"path": "C:\\Windows"})
    check("ok=False", r.get("ok") is False, json.dumps(r))
    check("status=denied", r.get("status") == "denied", json.dumps(r))
    check("no output field", "output" not in r, json.dumps(r))

    # ---------------- 15. D:\ denied with no leak ----------------
    print("\n[15] D:\\ path denied, no contents leaked")
    r = router_deny.route("filesystem.list_dir", {"path": "D:\\Lumi"})
    check("ok=False", r.get("ok") is False, json.dumps(r))
    check("status=denied", r.get("status") == "denied", json.dumps(r))
    check("no output field", "output" not in r, json.dumps(r))

    # ---------------- summary ----------------
    print()
    print("=" * 66)
    print(f"  RESULTS: {RESULTS['pass']} passed, {RESULTS['fail']} failed, "
          f"{RESULTS['skip']} skipped")
    print("=" * 66)
    return 0 if RESULTS["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())