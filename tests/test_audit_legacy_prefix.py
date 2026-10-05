"""
Regression tests for the audit verifier's legacy-prefix handling.

Covers the transition from pre-hash-chain records (no `hash`, no
`prev_hash`) to the chained format. The verifier must treat the first
record that carries both fields as the effective genesis, and must
skip older records without rehashing them.

These tests do not touch the real audit log; every test uses a file
inside tmp_path.
"""
import json
from pathlib import Path

from storage.audit import _AuditSink, _ZERO_HASH


def _write_legacy_line(f, event, **fields):
    """Write one pre-hash-chain record (no hash / prev_hash)."""
    rec = {"timestamp": "2025-01-01T00:00:00.000", "event": event}
    rec.update(fields)
    f.write(json.dumps(rec) + "\n")


def _make_legacy_file(p: Path, n: int = 3):
    with open(p, "w", encoding="utf-8") as f:
        for i in range(n):
            _write_legacy_line(f, f"legacy.event.{i}", k=i)


# ---------------------------------------------------------------- happy path


def test_verify_empty_file(tmp_path):
    p = tmp_path / "empty.log"
    p.touch()
    s = _AuditSink(p)
    try:
        last, ok = s._verify_chain()
        assert ok is True
        assert last == _ZERO_HASH
    finally:
        s.close()


def test_verify_legacy_only_file(tmp_path):
    p = tmp_path / "legacy.log"
    _make_legacy_file(p, n=5)
    s = _AuditSink(p)
    try:
        last, ok = s._verify_chain()
        assert ok is True, "legacy-only file must verify cleanly"
        assert last == _ZERO_HASH
    finally:
        s.close()


def test_verify_pure_chained_file(tmp_path):
    p = tmp_path / "chained.log"
    s = _AuditSink(p)
    s.write("one", {"k": 1})
    s.write("two", {"k": 2})
    last_hash = s._prev_hash
    s.close()

    s2 = _AuditSink(p)
    try:
        last, ok = s2._verify_chain()
        assert ok is True
        assert last == last_hash
    finally:
        s2.close()


def test_verify_legacy_then_chained(tmp_path):
    """The canonical transition: legacy prefix then chained records.

    The first chained record must be the genesis (prev_hash == _ZERO_HASH),
    and re-verification from a fresh sink must succeed and return the
    tail hash of the chained segment.
    """
    p = tmp_path / "legacy_then_chained.log"
    _make_legacy_file(p, n=4)

    s = _AuditSink(p)
    assert s._usable
    s.write("first.chained", {"k": "a"})
    first_chained_hash = s._prev_hash
    s.write("second.chained", {"k": "b"})
    last_hash = s._prev_hash
    s.close()

    lines = p.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 6

    # Lines 1..4 are legacy; line 5 is the genesis; line 6 links to line 5.
    for i in range(4):
        rec_legacy = json.loads(lines[i])
        assert "hash" not in rec_legacy
        assert "prev_hash" not in rec_legacy

    rec_first = json.loads(lines[4])
    assert rec_first["prev_hash"] == _ZERO_HASH
    assert rec_first["hash"] == first_chained_hash

    rec_second = json.loads(lines[5])
    assert rec_second["prev_hash"] == first_chained_hash
    assert rec_second["hash"] == last_hash

    # Fresh sink verifies the file cleanly.
    s2 = _AuditSink(p)
    try:
        last, ok = s2._verify_chain()
        assert ok is True
        assert last == last_hash
    finally:
        s2.close()


def test_writer_extends_chain_across_legacy_prefix(tmp_path):
    """The writer must continue an existing chained segment rather than
    restarting the chain from _ZERO_HASH after a legacy prefix."""
    p = tmp_path / "extend.log"
    _make_legacy_file(p, n=2)

    s1 = _AuditSink(p)
    s1.write("one", {"k": 1})
    tail_after_first = s1._prev_hash
    s1.close()

    s2 = _AuditSink(p)
    try:
        last, ok = s2._verify_chain()
        assert ok is True
        assert last == tail_after_first
        s2.write("two", {"k": 2})
        tail_after_second = s2._prev_hash
    finally:
        s2.close()

    lines = p.read_text(encoding="utf-8").splitlines()
    rec_two = json.loads(lines[-1])
    assert rec_two["prev_hash"] == tail_after_first
    assert rec_two["hash"] == tail_after_second


# ---------------------------------------------------------------- failure modes


def test_verify_legacy_then_bad_genesis(tmp_path):
    """A non-genesis prev_hash on the first chained record must fail."""
    p = tmp_path / "bad_genesis.log"
    _make_legacy_file(p, n=2)

    s = _AuditSink(p)
    s.write("first", {"k": 1})
    s.close()

    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[2])
    rec["prev_hash"] = "f" * 64
    lines[2] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    s2 = _AuditSink(p)
    try:
        _, ok = s2._verify_chain()
        assert ok is False, (
            "non-genesis prev_hash on first chained record must fail"
        )
    finally:
        s2.close()


def test_verify_legacy_then_broken_midchain(tmp_path):
    """A tampered body inside the chained segment must fail."""
    p = tmp_path / "broken.log"
    _make_legacy_file(p, n=2)

    s = _AuditSink(p)
    s.write("one", {"k": 1})
    s.write("two", {"k": 2})
    s.write("three", {"k": 3})
    s.close()

    lines = p.read_text(encoding="utf-8").splitlines()
    # Tamper with the second chained record (index 3 in the file).
    rec = json.loads(lines[3])
    rec["k"] = 999
    lines[3] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    s2 = _AuditSink(p)
    try:
        _, ok = s2._verify_chain()
        assert ok is False
    finally:
        s2.close()


def test_verify_legacy_record_after_chain_start_fails(tmp_path):
    """A legacy record that appears after the chain has started fails,
    because the verifier must not silently accept mixing of formats."""
    p = tmp_path / "legacy_after.log"
    s = _AuditSink(p)
    s.write("one", {"k": 1})
    s.close()

    with open(p, "a", encoding="utf-8") as f:
        _write_legacy_line(f, "sneaky.legacy")

    s2 = _AuditSink(p)
    try:
        _, ok = s2._verify_chain()
        assert ok is False, (
            "legacy record after chain start must fail verification"
        )
    finally:
        s2.close()


def test_verify_half_chained_record_fails(tmp_path):
    """A record with exactly one of hash/prev_hash fails closed."""
    p = tmp_path / "half.log"
    s = _AuditSink(p)
    s.write("one", {"k": 1})
    s.close()

    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    del rec["prev_hash"]
    lines[0] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    s2 = _AuditSink(p)
    try:
        _, ok = s2._verify_chain()
        assert ok is False
    finally:
        s2.close()


def test_verify_malformed_json_line_fails(tmp_path):
    """A malformed JSON line fails verification even in the legacy
    prefix region, because we cannot tell whether it is a legacy record."""
    p = tmp_path / "malformed.log"
    _make_legacy_file(p, n=1)
    with open(p, "a", encoding="utf-8") as f:
        f.write("this is not json\n")

    s = _AuditSink(p)
    try:
        _, ok = s._verify_chain()
        assert ok is False
    finally:
        s.close()