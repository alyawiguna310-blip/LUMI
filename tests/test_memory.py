import unittest

from ai.provider import ChatMessage
from core.memory import ConversationMemory


class TestConversationMemory(unittest.TestCase):
    def test_add_and_get(self):
        m = ConversationMemory(max_messages=4)
        m.add(ChatMessage(role="user", content="hi"))
        m.add(ChatMessage(role="assistant", content="hey"))
        self.assertEqual(len(m), 2)
        self.assertEqual(m.get_all()[0].content, "hi")

    def test_rolling_window(self):
        m = ConversationMemory(max_messages=3)
        for i in range(5):
            m.add(ChatMessage(role="user", content=f"m{i}"))
        self.assertEqual(len(m), 3)
        self.assertEqual([x.content for x in m.get_all()], ["m2", "m3", "m4"])

    def test_clear(self):
        m = ConversationMemory()
        m.add(ChatMessage(role="user", content="x"))
        m.clear()
        self.assertEqual(len(m), 0)


if __name__ == "__main__":
    unittest.main()