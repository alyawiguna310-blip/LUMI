"""Tests for the state machine."""
import unittest
from core.state import LumiState, StateManager


class TestStateMachine(unittest.TestCase):
    def test_initial_state(self):
        sm = StateManager()
        self.assertEqual(sm.state, LumiState.SLEEPING)

    def test_valid_transition(self):
        sm = StateManager()
        self.assertTrue(sm.transition(LumiState.IDLE))
        self.assertEqual(sm.state, LumiState.IDLE)

    def test_invalid_transition(self):
        sm = StateManager()
        # SLEEPING -> LISTENING is not allowed directly
        self.assertFalse(sm.transition(LumiState.LISTENING))
        self.assertEqual(sm.state, LumiState.SLEEPING)

    def test_observer_notified(self):
        sm = StateManager()
        seen = []
        sm.add_observer(lambda old, new: seen.append((old, new)))
        sm.transition(LumiState.IDLE)
        self.assertEqual(seen, [(LumiState.SLEEPING, LumiState.IDLE)])


if __name__ == "__main__":
    unittest.main()