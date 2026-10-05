"""Shared provider helpers: error classification for fallback decisions."""
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorKind(str, Enum):
    TRANSIENT = "transient"
    QUOTA = "quota"
    AUTH = "auth"
    INVALID = "invalid"
    UNKNOWN = "unknown"


_TRANSIENT_MARKERS = (
    "timeout", "timed out", "connection reset", "connection refused",
    "connection error", "network", "unreachable", "temporarily unavailable",
    "service unavailable", "bad gateway", "gateway timeout",
)
_QUOTA_MARKERS = (
    "429", "rate limit", "rate_limit", "resource_exhausted", "quota",
    "too many requests", "retrydelay", "retry after",
    # Billing / credit exhaustion is effectively the same as quota
    "credit balance",
    "credit balance is too low",
    "no credits remaining",
    "insufficient_quota",
    "insufficient credits",
    "out of credits",
    "plans & billing",
    "purchase credits",
    "upgrade or purchase",
)
_AUTH_MARKERS = (
    "401", "403", "invalid api key", "invalid_api_key", "unauthorized",
    "authentication", "permission denied", "access denied",
)
_INVALID_MARKERS = (
    "invalid_argument", "invalid request", "invalid_request_error",
    "malformed",
)


def classify_error(exc: BaseException) -> ErrorKind:
    """Map an exception to one of ErrorKind."""
    msg = (str(exc) or "").lower()
    name = type(exc).__name__.lower()

    # Auth first — some SDKs combine "invalid api key" + "401"
    for m in _AUTH_MARKERS:
        if m in msg or m in name:
            return ErrorKind.AUTH

    # Quota / billing — must come before INVALID because some 400s
    # ("credit balance is too low") are actually quota
    for m in _QUOTA_MARKERS:
        if m in msg:
            return ErrorKind.QUOTA

    # 5xx server errors
    for code in ("500", "502", "503", "504"):
        if code in msg:
            return ErrorKind.TRANSIENT

    for m in _TRANSIENT_MARKERS:
        if m in msg or m in name:
            return ErrorKind.TRANSIENT

    # Invalid only if it's a genuine bad-request with none of the above
    for m in _INVALID_MARKERS:
        if m in msg:
            return ErrorKind.INVALID

    return ErrorKind.UNKNOWN


def cooldown_seconds(kind: ErrorKind) -> int:
    """How long to skip this provider after a failure of `kind`."""
    if kind == ErrorKind.QUOTA:
        return 12 * 3600
    if kind == ErrorKind.TRANSIENT:
        return 60
    if kind == ErrorKind.AUTH:
        return 0
    return 30