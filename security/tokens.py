"""
Single-use authorization tokens.

A token is issued by the SecurityGate AFTER a descriptor has passed all
authorization checks. It is bound to:

    - operation_id
    - descriptor_hash  (covers every security-relevant field)
    - capability
    - target_hash
    - requested_privilege

It has a short TTL and may be consumed exactly once. Consumption
re-validates every binding against the descriptor the executor is about
to run. Any mismatch, reuse, expiry, or unknown id is a hard denial.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

from security.descriptor import OperationDescriptor


@dataclass
class _IssuedToken:
    token_id: str
    operation_id: str
    descriptor_hash: str
    capability: str
    target_hash: str
    requested_privilege: str
    issued_at: float
    expires_at: float
    used: bool = False


class TokenStore:
    """In-memory store for single-use authorization tokens.

    Tokens are never persisted. On restart, all outstanding tokens are
    invalidated. This is intentional: the boundary that matters is a
    single execution that consumes the token in the same process.
    """

    DEFAULT_TTL_SECONDS = 60

    def __init__(self, default_ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self._tokens: dict = {}
        self._lock = threading.Lock()
        self._ttl = max(1, int(default_ttl_seconds))

    def issue(self, descriptor: OperationDescriptor) -> str:
        token_id = secrets.token_hex(32)
        now = time.time()
        entry = _IssuedToken(
            token_id=token_id,
            operation_id=descriptor.operation_id,
            descriptor_hash=descriptor.descriptor_hash(),
            capability=descriptor.capability,
            target_hash=descriptor.target_hash(),
            requested_privilege=descriptor.requested_privilege,
            issued_at=now,
            expires_at=now + self._ttl,
            used=False,
        )
        with self._lock:
            self._tokens[token_id] = entry
        return token_id

    def consume(
        self, token_id: str, descriptor: OperationDescriptor
    ) -> tuple:
        """Returns (ok, reason). On success marks the token used."""
        if not isinstance(token_id, str) or not token_id:
            return False, "malformed_token"

        with self._lock:
            entry = self._tokens.get(token_id)
            if entry is None:
                return False, "unknown_token"
            if entry.used:
                return False, "already_used"
            if time.time() > entry.expires_at:
                return False, "expired"
            if entry.operation_id != descriptor.operation_id:
                return False, "operation_id_mismatch"
            if entry.descriptor_hash != descriptor.descriptor_hash():
                return False, "descriptor_mismatch"
            if entry.capability != descriptor.capability:
                return False, "capability_mismatch"
            if entry.target_hash != descriptor.target_hash():
                return False, "target_mismatch"
            if entry.requested_privilege != descriptor.requested_privilege:
                return False, "privilege_mismatch"
            entry.used = True
            return True, ""

    def is_used(self, token_id: str) -> bool:
        with self._lock:
            entry = self._tokens.get(token_id)
            return entry.used if entry is not None else False

    def purge_expired(self) -> int:
        now = time.time()
        with self._lock:
            stale = [
                tid for tid, e in self._tokens.items()
                if e.used or now > e.expires_at
            ]
            for tid in stale:
                del self._tokens[tid]
        return len(stale)