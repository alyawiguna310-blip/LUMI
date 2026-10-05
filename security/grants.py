"""
Permission grants — foundation only.

A Grant is a scoped authorization for a specific (domain, permission)
pair, with a maximum risk level and an optional set of path scopes.

Phase 2 defines the model and store. It does NOT populate the store
with real grants. The gate consults the store; if no grant covers a
requirement, the decision falls through to Phase 1's confirmation
mechanism. Grants can only ever NARROW what Phase 1 would allow; they
cannot broaden it.

High-risk rule: no grant type except "per_operation" may authorize a
HIGH_RISK operation.

Scope rule: when a Grant declares a non-empty scope, target path values
must lie within it. Malformed scope, malformed target, or unevaluable
paths fail closed (the grant does not cover).
"""
from __future__ import annotations

import json
import ntpath
import os
import threading
import time
from dataclasses import dataclass
from typing import Optional

from security.descriptor import Domain, Permission, Risk


GRANT_TYPES = frozenset({"implicit", "session", "persistent", "per_operation"})

_VALID_DOMAINS = frozenset(d.value for d in Domain)


# ---------------------------------------------------------------- path helpers


def _canonical_path(s: str) -> str:
    """Best-effort canonicalization for scope checks. Windows-style
    separators and case are normalized. Never raises for the caller; on
    failure, returns a lowercased string that will fail subsequent
    comparisons."""
    if not isinstance(s, str) or not s:
        raise ValueError("path must be a non-empty string")
    p = s.replace("/", "\\")
    p = os.path.expanduser(os.path.expandvars(p))
    try:
        p = ntpath.normpath(p)
    except Exception:
        pass
    return ntpath.normcase(p)


def _is_within(candidate: str, root: str) -> bool:
    try:
        c = _canonical_path(candidate)
        r = _canonical_path(root)
    except Exception:
        return False
    if c == r:
        return True
    sep = "\\"
    if not r.endswith(sep):
        r = r + sep
    return c.startswith(r)


def _collect_string_values(obj) -> list:
    out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_collect_string_values(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_collect_string_values(v))
    return out


def _target_matches_scope(target_json: str, scope) -> bool:
    """All string values inside target_json must fall within at least one
    scope entry. Empty target or unparseable target fails closed."""
    if not isinstance(target_json, str) or not target_json:
        return False
    if not isinstance(scope, (tuple, list)) or not scope:
        return False
    try:
        target = json.loads(target_json)
    except Exception:
        return False

    values = _collect_string_values(target)
    if not values:
        return False

    for v in values:
        if not isinstance(v, str):
            return False
        if not any(
            isinstance(s, str) and _is_within(v, s) for s in scope
        ):
            return False
    return True


# ---------------------------------------------------------------- grant


@dataclass(frozen=True)
class Grant:
    grant_id: str
    domain: str
    permission: Permission
    scope: tuple = ()
    grant_type: str = "persistent"
    max_risk: Risk = Risk.CONSEQUENTIAL
    expires_at: float = 0.0  # 0.0 = never

    def validate(self) -> tuple:
        """Return (ok, reason). Used by GrantStore.add."""
        if not isinstance(self.grant_id, str) or not self.grant_id:
            return False, "grant_id must be a non-empty string"
        if not isinstance(self.domain, str) or self.domain not in _VALID_DOMAINS:
            return False, f"invalid domain: {self.domain!r}"
        if not isinstance(self.permission, Permission):
            return False, (
                f"permission must be a Permission enum, "
                f"got {type(self.permission).__name__}"
            )
        if not isinstance(self.max_risk, Risk):
            return False, (
                f"max_risk must be a Risk enum, "
                f"got {type(self.max_risk).__name__}"
            )
        if self.grant_type not in GRANT_TYPES:
            return False, f"invalid grant_type: {self.grant_type!r}"
        if not isinstance(self.scope, (tuple, list)):
            return False, "scope must be a tuple or list"
        for entry in self.scope:
            if not isinstance(entry, str) or not entry:
                return False, "scope entries must be non-empty strings"
        if not isinstance(self.expires_at, (int, float)):
            return False, "expires_at must be numeric"
        if self.expires_at < 0:
            return False, "expires_at must be non-negative"
        return True, ""

    def covers(
        self,
        domain: str,
        permission: Permission,
        risk: Risk,
        target_json: str,
    ) -> bool:
        try:
            if not isinstance(domain, str):
                return False
            if not isinstance(permission, Permission):
                return False
            if not isinstance(risk, Risk):
                return False
            if not isinstance(target_json, str):
                return False
            if self.domain != domain:
                return False
            if int(self.permission) < int(permission):
                return False
            if int(risk) > int(self.max_risk):
                return False
            if risk == Risk.HIGH_RISK and self.grant_type != "per_operation":
                return False
            if self.expires_at and time.time() > self.expires_at:
                return False
            # Scope enforcement (F-3). An empty scope means unscoped.
            if self.scope:
                if not _target_matches_scope(target_json, self.scope):
                    return False
            return True
        except Exception:
            return False


# ---------------------------------------------------------------- store


class GrantStore:
    def __init__(self):
        self._grants: list = []
        self._lock = threading.Lock()

    def add(self, grant: Grant) -> None:
        """Validate before storing (F-5). Raises ValueError on invalid
        grants so callers cannot accidentally install malformed
        authorizations."""
        if not isinstance(grant, Grant):
            raise ValueError(
                f"GrantStore.add expects a Grant, got {type(grant).__name__}"
            )
        ok, reason = grant.validate()
        if not ok:
            raise ValueError(f"invalid grant: {reason}")
        with self._lock:
            self._grants.append(grant)

    def find_covering(
        self,
        domain: str,
        permission: Permission,
        risk: Risk,
        target_json: str,
    ) -> Optional[Grant]:
        with self._lock:
            snapshot = list(self._grants)
        for g in snapshot:
            try:
                if g.covers(domain, permission, risk, target_json):
                    return g
            except Exception:
                # Fail closed: a grant that raises does not cover.
                continue
        return None

    def clear(self) -> None:
        with self._lock:
            self._grants.clear()

    def is_empty(self) -> bool:
        with self._lock:
            return not self._grants