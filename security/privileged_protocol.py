"""
Message framing and schema for the privileged helper protocol.

The wire format is:

    [4 bytes big-endian uint32 length][UTF-8 JSON payload]

Every message is a JSON object. Maximum sizes are enforced on both sides.
Any framing or schema violation is a hard ProtocolError, never a silent
proceed.
"""
from __future__ import annotations

import json
import struct
from typing import Callable

PROTOCOL_VERSION = 1

MAX_REQUEST_BYTES = 256 * 1024         # 256 KiB
MAX_RESPONSE_BYTES = 4 * 1024 * 1024   # 4 MiB

_LENGTH_STRUCT = struct.Struct(">I")


class ProtocolError(Exception):
    """Raised on malformed protocol data. Always results in denial or
    an error outcome, never a silent proceed."""


def encode_message(obj: dict, max_bytes: int = MAX_RESPONSE_BYTES) -> bytes:
    if not isinstance(obj, dict):
        raise ProtocolError("message must be a dict")
    try:
        payload = json.dumps(
            obj, ensure_ascii=False, separators=(",", ":"), default=str,
        ).encode("utf-8")
    except Exception as e:
        raise ProtocolError(f"encode failed: {e}") from e
    if len(payload) > max_bytes:
        raise ProtocolError(f"message too large: {len(payload)} > {max_bytes}")
    return _LENGTH_STRUCT.pack(len(payload)) + payload


def read_length_prefixed(
    reader: Callable[[int], bytes],
    max_bytes: int,
) -> dict:
    """Read one length-prefixed message using `reader(n) -> bytes`.
    `reader` must block until n bytes are available or raise."""
    header = reader(4)
    if not isinstance(header, (bytes, bytearray)) or len(header) != 4:
        raise ProtocolError("could not read length prefix")
    (length,) = _LENGTH_STRUCT.unpack(bytes(header))
    if length > max_bytes:
        raise ProtocolError(f"declared length {length} exceeds max {max_bytes}")
    body = reader(length) if length > 0 else b""
    if not isinstance(body, (bytes, bytearray)) or len(body) != length:
        raise ProtocolError("truncated body")
    try:
        obj = json.loads(bytes(body).decode("utf-8"))
    except Exception as e:
        raise ProtocolError(f"invalid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ProtocolError("message must be a JSON object")
    return obj


def validate_response_schema(response: dict) -> tuple[bool, str]:
    if not isinstance(response, dict):
        return False, "response must be an object"
    if response.get("protocol_version") != PROTOCOL_VERSION:
        return False, "protocol version mismatch"
    outcome = response.get("outcome")
    if outcome not in ("success", "denied", "error", "timeout", "unknown"):
        return False, f"invalid outcome: {outcome!r}"
    if not isinstance(response.get("operation_id", ""), str):
        return False, "operation_id must be a string"
    return True, ""