"""Test the multi-provider fallback with a fake broken provider.
Does NOT call any real API."""
from ai.provider import ChatMessage, ChatResponse, LLMProvider
from ai.provider_manager import ProviderManager


class BrokenProvider(LLMProvider):
    name = "broken"
    def __init__(self, error_msg):
        self.error_msg = error_msg
        self.calls = 0
    def is_available(self):
        return True
    def chat(self, messages, max_tokens=300):
        self.calls += 1
        raise RuntimeError(self.error_msg)


class GoodProvider(LLMProvider):
    name = "good"
    def __init__(self):
        self.calls = 0
    def is_available(self):
        return True
    def chat(self, messages, max_tokens=300):
        self.calls += 1
        return ChatResponse(text="OK from good provider")


def run_case(desc, error_msg):
    broken = BrokenProvider(error_msg)
    good = GoodProvider()
    mgr = ProviderManager([("broken", broken), ("good", good)])
    msgs = [ChatMessage(role="user", content="hi")]
    print(f"\n[{desc}]")
    try:
        r = mgr.chat(msgs)
        print(f"  → fell back to good: {r.text!r}")
    except Exception as e:
        print(f"  → FAILED: {e}")
        return
    # Second call should skip the broken one due to cooldown
    r2 = mgr.chat(msgs)
    if broken.calls == 1:
        print(f"  → broken provider cooled down (called once, not retried)")
    else:
        print(f"  → FAIL: broken provider was called {broken.calls} times")


def main():
    print("=" * 60)
    print("  PROVIDER FALLBACK TEST (no real API calls)")
    print("=" * 60)

    run_case("429 rate limit", "429 Too Many Requests")
    run_case("request timeout", "Request timeout")
    run_case("connection refused", "Connection refused by host")
    run_case("503 server error", "503 Service Unavailable")

    # Auth error should disable permanently
    print("\n[auth error → permanent disable]")
    broken = BrokenProvider("401 Unauthorized: invalid api key")
    good = GoodProvider()
    mgr = ProviderManager([("broken", broken), ("good", good)])
    msgs = [ChatMessage(role="user", content="hi")]
    for _ in range(3):
        mgr.chat(msgs)
    if broken.calls == 1:
        print(f"  → PASS: auth-failed provider called only once")
    else:
        print(f"  → FAIL: called {broken.calls} times")

    # 400 invalid → must NOT fall back
    print("\n[400 invalid → no fallback, raise]")
    broken = BrokenProvider("400 Invalid argument")
    good = GoodProvider()
    mgr = ProviderManager([("broken", broken), ("good", good)])
    try:
        mgr.chat(msgs)
        print("  → FAIL: should have raised")
    except RuntimeError as e:
        if "400" in str(e):
            print("  → PASS: raised without falling back")
        else:
            print(f"  → FAIL: wrong error: {e}")

    print("\n" + "=" * 60)
    print("  DONE")
    print("=" * 60)


if __name__ == "__main__":
    main()