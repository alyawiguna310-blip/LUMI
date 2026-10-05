"""
Operation Descriptor and Phase 2 supporting enums.

An OperationDescriptor is an immutable snapshot of a proposed operation.
It is created by the SecurityGate BEFORE any authorization decision and
is bound into the single-use authorization token that permits execution.

Any change to a security-relevant field after authorization changes the
descriptor hash and causes token consumption to fail.

Phase 4 additions:

  derived_from
      Provenance of the content that inspired this request. Empty
      string means "not derived from external content". Otherwise one
      of the EXTERNAL_ORIGINS values. It is set at request construction
      time by trusted callers, preserved by the gate into the
      descriptor, and covered by descriptor_hash(). It cannot be
      erased by downstream code in the pipeline.

  authorization_source
      Who authorized the operation. "none" until the gate records a
      successful local-user confirmation. Only the gate transitions
      this value, and only after the confirmation handler returns
      approved=True. It is covered by descriptor_hash().

Enforced invariants:

    POWER != PERMISSION
    CAPABILITY != PERMISSION
    AI REASONING != AUTHORIZATION
    EXTERNAL != AUTHORIZATION
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, replace
from enum import Enum, IntEnum
from typing import Optional


class Origin(str, Enum):
    """Source of a request. LOCAL_USER and AI_INTERNAL may reach
    confirmation for any risk. Truly external origins cannot reach
    confirmation for CONSEQUENTIAL+ operations."""
    LOCAL_USER = "local_user"
    AI_INTERNAL = "ai_internal"
    DISCORD = "discord"
    WHATSAPP = "whatsapp"
    WEB = "web"
    FILE = "file"
    API = "api"
    UNKNOWN = "unknown"


EXTERNAL_ORIGINS = frozenset({
    Origin.DISCORD.value,
    Origin.WHATSAPP.value,
    Origin.WEB.value,
    Origin.FILE.value,
    Origin.API.value,
    Origin.UNKNOWN.value,
})

_VALID_ORIGINS = frozenset(o.value for o in Origin)

# Phase 4: authorization-source values. Only these two are currently
# meaningful. "none" is the initial value; "local_user_confirmation" is
# set by the gate after a trusted confirmation approval. No caller may
# set it directly.
_AUTHORIZATION_SOURCES = frozenset({"none", "local_user_confirmation"})


class Risk(IntEnum):
    LOW = 0
    NORMAL = 1
    CONSEQUENTIAL = 2
    HIGH_RISK = 3


class Permission(IntEnum):
    NONE = 0
    READ = 1
    WRITE = 2
    DELETE = 3
    EXECUTE = 4
    ADMIN = 5


class Domain(str, Enum):
    FS = "fs"
    REGISTRY = "registry"
    SERVICE = "service"
    DRIVER = "driver"
    BOOT = "boot"
    SECURITY_CONFIG = "security_config"
    NETWORK_CONFIG = "network_config"
    PROCESS = "process"
    SHELL = "shell"
    ADB = "adb"
    FASTBOOT = "fastboot"
    ROOT = "root"
    MEMORY = "memory"
    EXTERNAL_DISCORD = "external.discord"
    EXTERNAL_WHATSAPP = "external.whatsapp"
    AUDIT = "audit"


_RISK_NAMES = {
    Risk.LOW: "low",
    Risk.NORMAL: "normal",
    Risk.CONSEQUENTIAL: "consequential",
    Risk.HIGH_RISK: "high_risk",
}

_PERMISSION_NAMES = {
    Permission.NONE: "none",
    Permission.READ: "read",
    Permission.WRITE: "write",
    Permission.DELETE: "delete",
    Permission.EXECUTE: "execute",
    Permission.ADMIN: "admin",
}

_CAPABILITY_TO_PERMISSION = {
    "read": Permission.READ,
    "write": Permission.WRITE,
    "delete": Permission.DELETE,
    "execute": Permission.EXECUTE,
    "admin": Permission.ADMIN,
    "modify": Permission.WRITE,
    "destructive": Permission.DELETE,
    "guide": Permission.READ,
}

_CAPABILITY_PREFIX_TO_DOMAINS = {
    "fs": frozenset({"fs"}),
    "registry": frozenset({"registry"}),
    "service": frozenset({"service"}),
    "driver": frozenset({"driver"}),
    "boot": frozenset({"boot"}),
    "security_config": frozenset({"security_config"}),
    "network_config": frozenset({"network_config"}),
    "process": frozenset({"process"}),
    "shell": frozenset({"shell"}),
    "adb": frozenset({"adb"}),
    "fastboot": frozenset({"fastboot"}),
    "root": frozenset({"root"}),
    "memory": frozenset({"memory"}),
    "external": frozenset({"external.discord", "external.whatsapp"}),
    "audit": frozenset({"audit"}),
}


def risk_name(r: Risk) -> str:
    return _RISK_NAMES.get(r, "unknown")


def permission_name(p: Permission) -> str:
    return _PERMISSION_NAMES.get(p, "unknown")


def permission_from_capability(capability: str) -> Permission:
    if not isinstance(capability, str) or not capability:
        return Permission.NONE
    tail = capability.rsplit(".", 1)[-1].strip().lower()
    return _CAPABILITY_TO_PERMISSION.get(tail, Permission.NONE)


def capability_domain_consistent(capability: str, domain: str) -> tuple:
    if not isinstance(capability, str) or not capability:
        return False, "capability must be a non-empty string"
    if not isinstance(domain, str) or not domain:
        return False, "domain must be a non-empty string"
    if "." not in capability:
        return False, f"capability {capability!r} has no domain prefix"
    prefix = capability.split(".", 1)[0]
    allowed = _CAPABILITY_PREFIX_TO_DOMAINS.get(prefix)
    if allowed is None:
        return False, f"unknown capability prefix {prefix!r}"
    if domain not in allowed:
        return False, (
            f"capability prefix {prefix!r} requires domain in "
            f"{sorted(allowed)}, got {domain!r}"
        )
    return True, ""


def _canonical_json(obj) -> str:
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), default=str,
    )


@dataclass(frozen=True)
class OperationDescriptor:
    operation_id: str
    tool_name: str
    capability: str
    domain: str
    target_json: str
    parameters_json: str
    declared_risk: str
    requested_scope: str
    requested_privilege: str
    reversibility: str
    originating_source: str
    derived_from: str = ""
    authorization_source: str = "none"

    def __post_init__(self):
        if self.derived_from and self.derived_from not in _VALID_ORIGINS:
            raise ValueError(f"invalid derived_from: {self.derived_from!r}")
        if self.authorization_source not in _AUTHORIZATION_SOURCES:
            raise ValueError(
                f"invalid authorization_source: {self.authorization_source!r}"
            )

    @classmethod
    def create(
        cls,
        *,
        tool_name: str,
        capability: str,
        domain: str,
        target,
        parameters,
        declared_risk: Risk,
        requested_scope: str = "",
        requested_privilege: str = "standard",
        reversibility: str = "limited",
        originating_source=Origin.AI_INTERNAL,
        derived_from: str = "",
        authorization_source: str = "none",
        operation_id: Optional[str] = None,
    ) -> "OperationDescriptor":
        origin_value = (
            originating_source.value
            if isinstance(originating_source, Origin)
            else str(originating_source)
        )
        domain_value = (
            domain.value if isinstance(domain, Domain) else str(domain)
        )
        risk_value = _RISK_NAMES.get(declared_risk, "high_risk")
        return cls(
            operation_id=operation_id or secrets.token_hex(16),
            tool_name=tool_name,
            capability=capability,
            domain=domain_value,
            target_json=_canonical_json(target),
            parameters_json=_canonical_json(parameters),
            declared_risk=risk_value,
            requested_scope=requested_scope,
            requested_privilege=requested_privilege,
            reversibility=reversibility,
            originating_source=origin_value,
            derived_from=derived_from or "",
            authorization_source=authorization_source or "none",
        )

    @property
    def target(self):
        return json.loads(self.target_json)

    @property
    def parameters(self):
        return json.loads(self.parameters_json)

    @property
    def risk(self) -> Risk:
        for k, v in _RISK_NAMES.items():
            if v == self.declared_risk:
                return k
        return Risk.HIGH_RISK

    @property
    def origin(self) -> Origin:
        for o in Origin:
            if o.value == self.originating_source:
                return o
        return Origin.UNKNOWN

    @property
    def required_permission(self) -> Permission:
        return permission_from_capability(self.capability)

    def is_externally_derived(self) -> bool:
        """True if the request originated externally or was derived from
        external content. Used by the gate to deny CONSEQUENTIAL+ work
        before confirmation, token issuance, or elevated dispatch."""
        return (
            self.originating_source in EXTERNAL_ORIGINS
            or self.derived_from in EXTERNAL_ORIGINS
        )

    def with_authorization(self, source: str) -> "OperationDescriptor":
        """Return a new immutable descriptor with authorization_source
        changed. The operation_id, tool_name, capability, domain, target,
        parameters and all other security-relevant fields are preserved.
        Only the gate should call this, and only after a trusted
        confirmation approval."""
        if source not in _AUTHORIZATION_SOURCES:
            raise ValueError(f"invalid authorization_source: {source!r}")
        return replace(self, authorization_source=source)

    _HASH_FIELDS = (
        "operation_id", "tool_name", "capability", "domain",
        "target_json", "parameters_json", "declared_risk",
        "requested_scope", "requested_privilege", "reversibility",
        "originating_source", "derived_from", "authorization_source",
    )

    def descriptor_hash(self) -> str:
        h = hashlib.sha256()
        for field in self._HASH_FIELDS:
            h.update(field.encode("utf-8"))
            h.update(b"=")
            h.update(str(getattr(self, field)).encode("utf-8"))
            h.update(b"\n")
        return h.hexdigest()

    def target_hash(self) -> str:
        return hashlib.sha256(self.target_json.encode("utf-8")).hexdigest()