"""
Regression tests for the audit verifier's `audit.chain_broken` recovery
marker handling.

Any `audit.chain_broken` record is a declared segment boundary. Its own
hash is verified against compute(prev_hash, body); its `prev_hash` is
not required to match the current running tail, because historical
markers were written with stale `last_good` values from a transitional
build window. Everything else fails closed.
"""
import json
from pathlib import Path

import pytest

from storage.audit import (
    _AuditSink,
    _ZERO_HASH,
    _hash,
    _RECOVERY_EVENT,
)


# ============================================================ helpers


def _body(event, **fields):
    rec = {"timestamp": "2025-01-01T00:00:00.000", "event": event}
    rec.update(fields)
    return rec


def _write_chained(f, event, prev_hash, **fields):
    """Write a chained record with the given prev_hash. Returns its hash."""
    body = _body(event, **fields)
    h = _hash(prev_hash, body)
    rec = dict(body)
    rec["prev_hash"] = prev_hash
    rec["hash"] = h
    f.write(json.dumps(rec) + "\n")
    return h


def _write_recovery(f, **fields):
    """Write a zero-prev recovery marker."""
    return _write_chained(f, _RECOVERY_EVENT, _ZERO_HASH, **fields)


def _write_stale_recovery(f, stale_prev, **fields):
    """Write a non-zero-prev recovery marker (transitional-era artifact)."""
    return _write_chained(f, _RECOVERY_EVENT, stale_prev, **fields)


def _write_legacy(f, event, **fields):
    rec = _body(event, **fields)
    f.write(json.dumps(rec) + "\n")


# ============================================================ happy path


def test_intact_chain_verifies(tmp_path):
    p = tmp_path / "intact.log"
    s = _AuditSink(p)
    s.write("one", {"k": 1})
    s.write("two", {"k": 2})
    tail = s._prev_hash
    s.close()

    s2 = _AuditSink(p)
    try:
        got, ok = s2._verify_chain()
        assert ok is True
        assert got == tail
        assert s2._breaks_declared == 0
        assert s2._zero_breaks == 0
        assert s2._stale_breaks == 0
    finally:
        s2.close()


def test_zero_prev_marker_as_genesis(tmp_path):
    """The first chained record in the file is a marker. It is the
    genesis; it is not counted as a break."""
    p = tmp_path / "genesis.log"
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        _write_chained(f, "gate.init", h1)

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is True
        assert s._breaks_declared == 0
        assert s._zero_breaks == 0
        assert s._stale_breaks == 0
    finally:
        s.close()


def test_zero_prev_marker_as_later_boundary(tmp_path):
    p = tmp_path / "later_boundary.log"
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        h2 = _write_chained(f, "gate.init", h1)
        h3 = _write_chained(f, "gate.register", h2)
        # A second zero-prev marker mid-file.
        h4 = _write_recovery(f, path="x")
        _write_chained(f, "gate.init2", h4)

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is True
        assert s._breaks_declared == 1
        assert s._zero_breaks == 1
        assert s._stale_breaks == 0
    finally:
        s.close()


def test_stale_prev_marker_is_boundary(tmp_path):
    """A non-zero-prev marker (historical artifact) is accepted as a
    segment boundary. Its own hash must still recompute correctly."""
    p = tmp_path / "stale.log"
    stale = "9dd2beb862fe" + "0" * 52  # arbitrary non-zero
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        h2 = _write_chained(f, "gate.init", h1)
        # Stale marker: does not chain to h2.
        h3 = _write_stale_recovery(f, stale, path="x")
        _write_chained(f, "gate.init2", h3)

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is True
        assert s._breaks_declared == 1
        assert s._zero_breaks == 0
        assert s._stale_breaks == 1
    finally:
        s.close()


def test_consecutive_markers(tmp_path):
    """Two adjacent markers are two separate boundaries."""
    p = tmp_path / "consecutive.log"
    stale = "a" * 64
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        h2 = _write_chained(f, "gate.init", h1)
        h3 = _write_stale_recovery(f, stale, path="first")
        h4 = _write_recovery(f, path="second")
        _write_chained(f, "gate.init2", h4)

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is True
        # Two markers after genesis: one stale, one zero.
        assert s._breaks_declared == 2
        assert s._zero_breaks == 1
        assert s._stale_breaks == 1
    finally:
        s.close()


def test_multiple_stale_markers_same_predecessor(tmp_path):
    """Two non-zero markers with the same stale prev_hash, matching the
    observed 3825 / 3826 pattern."""
    p = tmp_path / "same_stale.log"
    stale = "9dd2beb862fe" + "0" * 52
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        h2 = _write_chained(f, "gate.init", h1)
        h3 = _write_stale_recovery(f, stale, path="a")
        h4 = _write_stale_recovery(f, stale, path="b")
        _write_chained(f, "gate.init2", h4)

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is True
        assert s._breaks_declared == 2
        assert s._zero_breaks == 0
        assert s._stale_breaks == 2
    finally:
        s.close()


def test_chain_continues_after_stale_marker(tmp_path):
    """After accepting a stale marker, the running tail is the marker's
    own hash, and subsequent records must chain from there."""
    p = tmp_path / "continue.log"
    stale = "b" * 64
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        h2 = _write_chained(f, "gate.init", h1)
        h3 = _write_stale_recovery(f, stale, path="a")
        _write_chained(f, "gate.init2", h3)

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is True
        s.write("post", {"k": 1})
        tail_after = s._prev_hash
    finally:
        s.close()

    s2 = _AuditSink(p)
    try:
        got, ok = s2._verify_chain()
        assert ok is True
        assert got == tail_after
    finally:
        s2.close()


def test_restart_after_recovery(tmp_path):
    p = tmp_path / "restart.log"
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        _write_chained(f, "gate.init", h1)

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is True
        s.write("post.recovery", {"k": 1})
        tail_after_write = s._prev_hash
    finally:
        s.close()

    s2 = _AuditSink(p)
    try:
        got, ok = s2._verify_chain()
        assert ok is True
        assert got == tail_after_write
    finally:
        s2.close()


def test_legacy_prefix_then_recovery_marker(tmp_path):
    p = tmp_path / "legacy_recovery.log"
    with open(p, "w", encoding="utf-8") as f:
        for i in range(3):
            _write_legacy(f, f"legacy.{i}", k=i)
        h1 = _write_recovery(f, path="x")
        _write_chained(f, "gate.init", h1)

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is True
        assert s._breaks_declared == 0
    finally:
        s.close()


# ============================================================ failure modes


def test_marker_own_hash_mismatch_fails(tmp_path):
    """Alter a marker's body so its own hash no longer recomputes.
    Must fail closed."""
    p = tmp_path / "bad_marker.log"
    stale = "c" * 64
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        h2 = _write_chained(f, "gate.init", h1)
        h3 = _write_stale_recovery(f, stale, path="a")
        _write_chained(f, "gate.init2", h3)

    lines = p.read_text(encoding="utf-8").splitlines()
    # Tamper with the stale marker's body (line index 2).
    rec = json.loads(lines[2])
    rec["path"] = "tampered"
    lines[2] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is False
    finally:
        s.close()


def test_half_chained_marker_fails(tmp_path):
    p = tmp_path / "half_marker.log"
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        _write_chained(f, "gate.init", h1)

    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    del rec["prev_hash"]
    lines[0] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is False
    finally:
        s.close()


def test_non_marker_prev_hash_mismatch_still_fails(tmp_path):
    """A genuine non-marker record whose prev_hash does not match the
    running tail must still fail closed."""
    p = tmp_path / "non_marker_break.log"
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        h2 = _write_chained(f, "gate.init", h1)
        # Next record claims a wrong prev_hash and is not a marker.
        _write_chained(f, "gate.register", "f" * 64)

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is False
    finally:
        s.close()


def test_tampering_inside_segment_is_detected(tmp_path):
    p = tmp_path / "tamper.log"
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        h2 = _write_chained(f, "gate.init", h1)
        _write_chained(f, "gate.init2", h2)

    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[2])
    rec["k"] = 999
    lines[2] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is False
    finally:
        s.close()


def test_legacy_record_after_chain_start_fails(tmp_path):
    p = tmp_path / "legacy_after.log"
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        _write_chained(f, "gate.init", h1)
        _write_legacy(f, "sneaky.legacy")

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is False
    finally:
        s.close()


def test_malformed_json_fails(tmp_path):
    p = tmp_path / "malformed.log"
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        _write_chained(f, "gate.init", h1)
        f.write("not valid json\n")

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is False
    finally:
        s.close()


def test_non_marker_with_zero_prev_midchain_fails(tmp_path):
    """A non-marker record that claims a fresh genesis mid-file is a
    break and must fail."""
    p = tmp_path / "zero_mid.log"
    with open(p, "w", encoding="utf-8") as f:
        h1 = _write_recovery(f, path="x")
        h2 = _write_chained(f, "gate.init", h1)
        _write_chained(f, "gate.sneaky", _ZERO_HASH)

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is False
    finally:
        s.close()