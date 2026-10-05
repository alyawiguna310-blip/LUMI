"""
Security package. The gate is a singleton — initialize it once at startup.
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from security.gate import SecurityGate

_gate = None


def set_gate(gate):
    global _gate
    _gate = gate


def get_gate():
    if _gate is None:
        raise RuntimeError(
            "SecurityGate not initialized. Call security.set_gate(...) at startup."
        )
    return _gate