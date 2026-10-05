"""
The Security Gate. Every tool call MUST pass through here.

Order of checks (fail-closed at every step):

  0.   Config sanity.
  1.   Tool registered.
  1.5  Deep-freeze arguments (F-4); build OperationDescriptor.
  1.6  Phase 5B control-plane hard deny. Fires for any tool classified
       as a mutation (see _is_mutation) whose declared path_params
       include a control-plane path. Runs before sandbox, before any
       other policy check, before confirmation, before grants, before
       token issuance, before the executor, and before elevated
       dispatch. Read operations are unaffected.
  1.7  Phase 5C workspace classification. Fires for any mutation;
       UNKNOWN classification of a declared path_param is fail-closed.
  2.   Sandbox boundary (when enabled).
  3.   Protected folder.
  4.   Hard-deny rules.
  5.   Path rules (level-aware; every path_param evaluated).
  6.   System-looking pattern.
  6.5  Tool-declared confirm_if triggers.
  7.   Combine Phase 1 signals (strictest wins).
  7.5  Compute gate-derived risk, effective risk = max(declared, gate).
  7.6  Phase 2/4 permission evaluation. Denies:
         - originating_source in EXTERNAL_ORIGINS for CONSEQUENTIAL+
         - derived_from in EXTERNAL_ORIGINS for CONSEQUENTIAL+
       before confirmation, token issuance, or elevated dispatch.
  7.7  Combine Phase 1 and Phase 2/4 decisions (strictest wins).
  8.   Confirmation if required. On approval, the gate derives a new
       immutable descriptor with authorization_source =
       "local_user_confirmation".
  8.5  Issue single-use token against the authorized descriptor.
       Standard path: consume now. Elevated path: consume after helper.
  9.   Execute with the frozen arguments, or dispatch to the elevated
       helper.
 10.   Audit every step.
"""
import copy
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from security.confirmation import (
    ConfirmationManager, ConfirmationRequest,
)
from security.control_plane import is_control_plane
from security.descriptor import (
    EXTERNAL_ORIGINS,
    OperationDescriptor,
    Origin,
    Risk,
    capability_domain_consistent,
    permission_name,
    risk_name,
)
from security.grants import GrantStore
from security.path_rules import check_hard_deny, check_path_rules
from security.permissions import (
    PermissionLevel, PermissionPolicy, LEVEL_NAMES,
)
from security.protected_paths import is_inside_protected
from security.sandbox import check_sandbox
from security.system_patterns import is_system_looking
from security.tokens import TokenStore
from security import workspace as workspace_policy
from storage.audit import audit

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ dataclasses


@dataclass
class ToolSpec:
    name: str
    level: PermissionLevel
    path_params: list = field(default_factory=list)
    description: str = ""
    confirm_if: Optional[Callable[[dict], tuple]] = None
    capability: Optional[str] = None
    domain: Optional[str] = None
    declared_risk: Optional[Risk] = None
    requested_privilege: Optional[str] = None
    reversibility: Optional[str] = None
    # Phase 5D: explicit mutation classification for tools whose identity
    # is not in the known mutation / read sets. None means "not set"; the
    # known-name sets take priority, and unknown tools with path_params
    # fall back to fail-closed (mutation=True).
    mutating: Optional[bool] = None


@dataclass
class ToolRequest:
    """A request to execute a tool.

    originating_source has no default (F-2). Every caller must declare
    the source of the request.

    derived_from is Phase 4 provenance: empty when the request is not
    derived from external content, otherwise one of the EXTERNAL_ORIGINS
    values. It is set at construction time by trusted callers and is
    preserved into the descriptor. It cannot be erased downstream.
    """
    tool_name: str
    arguments: dict
    originating_source: str
    user_context: str = ""
    derived_from: str = ""


@dataclass
class ToolResult:
    success: bool = False
    output: Any = None
    error: str = ""
    denied: bool = False
    denial_reason: str = ""
    confirmation_needed: bool = False
    level: Optional[str] = None


# ------------------------------------------------------------------ mutation classification (Phase 5D)


# Filesystem mutations. Membership is explicit; a tool that is not listed
# here and not in _KNOWN_READ_TOOLS falls back to the fail-closed rule in
# _is_mutation().
_KNOWN_MUTATION_TOOLS = frozenset({
    "filesystem.write",
    "filesystem.create_dir",
    "filesystem.rename",
    "filesystem.move",
    "filesystem.delete",
})

# Filesystem operations explicitly known to be non-mutating. These are
# allowed to read control-plane paths and are not subject to the Phase
# 5B / 5C write-class checks.
_KNOWN_READ_TOOLS = frozenset({
    "filesystem.read",
    "filesystem.list_dir",
})


def _is_mutation(spec: ToolSpec) -> bool:
    """Phase 5D explicit mutation classification.

    The classification is based on explicit tool identity first, then
    on an explicit per-tool flag, then on a fail-closed fallback. It
    does NOT infer mutation from PermissionLevel.

    Resolution order:
      1. name in _KNOWN_MUTATION_TOOLS   -> True
      2. name in _KNOWN_READ_TOOLS       -> False
      3. spec.mutating is not None       -> bool(spec.mutating)
      4. spec.path_params non-empty      -> True (fail closed)
      5. otherwise                       -> False
    """
    if spec.name in _KNOWN_MUTATION_TOOLS:
        return True
    if spec.name in _KNOWN_READ_TOOLS:
        return False
    if spec.mutating is not None:
        return bool(spec.mutating)
    return bool(spec.path_params)


# ------------------------------------------------------------------ helpers


_RULE_RANK = {"deny": 3, "confirm": 2, "allow": 1}
_DECISION_RANK = {"deny": 3, "confirm": 2, "allow": 1}


def _risk_from_level(level: PermissionLevel) -> Risk:
    try:
        if level <= PermissionLevel.SAFE:
            return Risk.LOW
        if level == PermissionLevel.NORMAL:
            return Risk.NORMAL
        if level == PermissionLevel.DISRUPTIVE:
            return Risk.CONSEQUENTIAL
        if level == PermissionLevel.DESTRUCTIVE:
            return Risk.HIGH_RISK
    except Exception:
        pass
    return Risk.HIGH_RISK


def _derive_capability(spec: ToolSpec) -> str:
    if spec.level <= PermissionLevel.SAFE:
        return "fs.read"
    if spec.level == PermissionLevel.NORMAL:
        return "shell.execute"
    if spec.level == PermissionLevel.DISRUPTIVE:
        return "fs.write"
    if spec.level == PermissionLevel.DESTRUCTIVE:
        return "fs.delete"
    return "unknown.unknown"


def _derive_domain(spec: ToolSpec) -> str:
    return "shell"


def _derive_reversibility(spec: ToolSpec) -> str:
    if spec.level <= PermissionLevel.NORMAL:
        return "reversible"
    if spec.level == PermissionLevel.DISRUPTIVE:
        return "limited"
    return "none"


def _strictest_decision(*decisions: str) -> str:
    best = "allow"
    best_rank = _DECISION_RANK["allow"]
    for d in decisions:
        r = _DECISION_RANK.get(d, 0)
        if r > best_rank:
            best = d
            best_rank = r
    return best


# ------------------------------------------------------------------ gate


class SecurityGate:
    def __init__(
        self,
        protected_folder: str,
        sandbox_root: str = "",
        sandbox_enabled: bool = False,
        policy: Optional[PermissionPolicy] = None,
        confirmation: Optional[ConfirmationManager] = None,
        tokens: Optional[TokenStore] = None,
        grants: Optional[GrantStore] = None,
    ):
        self.protected_folder = protected_folder
        self.sandbox_root = sandbox_root
        self.sandbox_enabled = sandbox_enabled
        self.policy = policy or PermissionPolicy()
        self.confirmation = confirmation or ConfirmationManager()
        self.tokens = tokens or TokenStore()
        self.grants = grants or GrantStore()
        self._tools: dict = {}

        self.config_error: Optional[str] = None
        try:
            from security.protected_paths import canonicalize as canon_prot
            prot_canon = canon_prot(protected_folder)
            logger.info("Security gate active. Protected folder: %s", prot_canon)
        except Exception as e:
            self.config_error = f"cannot canonicalize protected folder: {e}"
            logger.error("SECURITY: %s - gate is CLOSED", self.config_error)
            audit("gate.init", protected_folder=protected_folder,
                  status="error", error=str(e))
            return

        if sandbox_enabled:
            try:
                from security.sandbox import canonicalize as canon_sand
                sand_canon = canon_sand(sandbox_root)
                logger.info("Sandbox mode: ENABLED. Root: %s", sand_canon)
                audit("gate.init", sandbox_root=sand_canon, status="ok")
            except Exception as e:
                self.config_error = f"cannot canonicalize sandbox root: {e}"
                logger.error("SECURITY: %s - gate is CLOSED", self.config_error)
                audit("gate.init", sandbox_root=sandbox_root,
                      status="error", error=str(e))
                return
        else:
            logger.warning("Sandbox mode: DISABLED. Tools can reach every drive.")
            audit("gate.init", sandbox_root=None, status="disabled")

        audit("gate.init", protected_folder=prot_canon, status="ok")

    # ------------------------------------------------------------ register

    def register_tool(self, spec: ToolSpec):
        if spec.name in self._tools:
            raise ValueError(f"tool '{spec.name}' already registered")

        has_cap = spec.capability is not None
        has_dom = spec.domain is not None
        if has_cap or has_dom:
            if not (has_cap and has_dom):
                raise ValueError(
                    f"tool {spec.name!r} declares only one of capability/domain; "
                    f"both must be set together"
                )
            ok, reason = capability_domain_consistent(
                spec.capability, spec.domain
            )
            if not ok:
                raise ValueError(
                    f"tool {spec.name!r} has inconsistent "
                    f"capability/domain: {reason}"
                )

        self._tools[spec.name] = spec
        logger.info("Registered tool: %s (level=%s, mutating=%s)",
                    spec.name, LEVEL_NAMES[spec.level], _is_mutation(spec))
        audit("gate.register", tool=spec.name,
              level=LEVEL_NAMES[spec.level], path_params=spec.path_params)

    # ------------------------------------------------------------ descriptor

    def _build_descriptor(self, spec: ToolSpec, request: ToolRequest,
                          frozen_args: dict) -> OperationDescriptor:
        capability = (spec.capability
                      if spec.capability is not None
                      else _derive_capability(spec))
        domain = (spec.domain
                  if spec.domain is not None
                  else _derive_domain(spec))
        declared_risk = (spec.declared_risk
                         if spec.declared_risk is not None
                         else _risk_from_level(spec.level))
        privilege = (spec.requested_privilege
                     if spec.requested_privilege is not None
                     else "standard")
        reversibility = (spec.reversibility
                         if spec.reversibility is not None
                         else _derive_reversibility(spec))
        target = {
            p: frozen_args[p] for p in spec.path_params if p in frozen_args
        }
        return OperationDescriptor.create(
            tool_name=spec.name,
            capability=capability,
            domain=domain,
            target=target,
            parameters=frozen_args,
            declared_risk=declared_risk,
            requested_scope=spec.name,
            requested_privilege=privilege,
            reversibility=reversibility,
            originating_source=request.originating_source,
            derived_from=request.derived_from or "",
            authorization_source="none",
        )

    def _derive_gate_risk(
        self,
        spec: ToolSpec,
        system_looking: bool,
        path_rule_decision: Optional[str],
        extra_confirms: list,
    ) -> Risk:
        risk = _risk_from_level(spec.level)
        if system_looking:
            risk = max(risk, Risk.CONSEQUENTIAL)
        if path_rule_decision == "confirm":
            risk = max(risk, Risk.CONSEQUENTIAL)
        if extra_confirms:
            risk = max(risk, Risk.CONSEQUENTIAL)
        if spec.declared_risk is not None:
            risk = max(risk, spec.declared_risk)
        return risk

    # ------------------------------------------------------------ phase 5B

    def _control_plane_deny(
        self, spec: ToolSpec, frozen_args: dict, base: dict
    ) -> Optional[ToolResult]:
        """Return a denial ToolResult if the operation is a filesystem
        mutation whose declared path_params include a control-plane
        path. Return None otherwise.

        The mutation classification is explicit (see _is_mutation); it
        does not depend on PermissionLevel. Reads skip this check.
        """
        if not _is_mutation(spec):
            return None
        for param in spec.path_params:
            value = frozen_args.get(param)
            if value is None:
                continue
            # is_control_plane fails closed: None, empty, and
            # uncanonicalizable paths return True.
            if not is_control_plane(value):
                continue
            logger.warning(
                "[SECURITY] Control-plane write blocked: %s.%s(%r)",
                spec.name, param, value,
            )
            audit(
                "gate.deny", **base, reason="control_plane",
                detail=f"path parameter {param!r} is on the control plane",
                param=param,
            )
            return ToolResult(
                success=False, denied=True,
                denial_reason=(
                    f"control-plane path: Lumi cannot modify its own "
                    f"security-control plane ({param})"
                ),
                confirmation_needed=False,
                level=LEVEL_NAMES[spec.level],
            )
        return None

    # ------------------------------------------------------------ phase 5C

    def _workspace_classification_check(
        self, spec: ToolSpec, frozen_args: dict, base: dict
    ) -> Optional[ToolResult]:
        """For filesystem mutations, classify every present path_param.

        A classification of UNKNOWN (None, empty, non-string, or
        canonicalization failure) is fail-closed. WORKSPACE and OTHER
        paths proceed through the normal authorization flow unchanged:
        the workspace scope is a policy boundary, not a grant.
        """
        if not _is_mutation(spec):
            return None
        for param in spec.path_params:
            if param not in frozen_args:
                continue
            value = frozen_args[param]
            cls = workspace_policy.classify_path(value)
            if cls != workspace_policy.PathClass.UNKNOWN:
                continue
            logger.warning(
                "[SECURITY] Unclassifiable path parameter for write: "
                "%s.%s(%r)",
                spec.name, param, value,
            )
            audit(
                "gate.deny", **base, reason="unknown_path_classification",
                detail=(
                    f"cannot classify path parameter {param!r} "
                    f"for a mutation"
                ),
                param=param,
            )
            return ToolResult(
                success=False, denied=True,
                denial_reason=(
                    f"cannot classify path parameter {param!r} "
                    f"(fail-closed for mutations)"
                ),
                confirmation_needed=False,
                level=LEVEL_NAMES[spec.level],
            )
        return None

    # ------------------------------------------------------------ phase 2/4 permission

    def _evaluate_phase2_permission(
        self,
        descriptor: OperationDescriptor,
        effective_risk: Risk,
    ) -> tuple:
        if int(effective_risk) >= int(Risk.CONSEQUENTIAL):
            if descriptor.originating_source in EXTERNAL_ORIGINS:
                return (
                    "deny",
                    f"external origin ({descriptor.originating_source}) "
                    f"cannot authorize {risk_name(effective_risk)} operation",
                )
            if descriptor.derived_from in EXTERNAL_ORIGINS:
                return (
                    "deny",
                    f"externally-derived content ({descriptor.derived_from}) "
                    f"cannot authorize {risk_name(effective_risk)} operation",
                )

        required_perm = descriptor.required_permission
        covering = self.grants.find_covering(
            descriptor.domain,
            required_perm,
            effective_risk,
            descriptor.target_json,
        )
        if covering is not None:
            return "allow", f"grant {covering.grant_id} covers"

        if effective_risk == Risk.HIGH_RISK:
            return "confirm", "no per-operation grant for HIGH_RISK"

        return "allow", "no phase2 rule"

    # ------------------------------------------------------------ token claims

    @staticmethod
    def _token_claims(descriptor: OperationDescriptor) -> dict:
        return {
            "operation_id": descriptor.operation_id,
            "descriptor_hash": descriptor.descriptor_hash(),
            "capability": descriptor.capability,
            "target_hash": descriptor.target_hash(),
            "requested_privilege": descriptor.requested_privilege,
        }

    # ------------------------------------------------------------ execute

    def execute(self, request: ToolRequest,
                executor: Callable[[dict], Any],
                elevated_executor: Optional[
                    Callable[[dict, OperationDescriptor, str, dict], Any]
                ] = None) -> ToolResult:

        base = {"tool": request.tool_name,
                "arguments": {k: str(v) for k, v in request.arguments.items()}}

        if self.config_error:
            audit("gate.deny", **base, reason="config_error",
                  detail=self.config_error)
            return ToolResult(
                success=False, denied=True,
                denial_reason=f"security config error: {self.config_error}",
            )

        spec = self._tools.get(request.tool_name)
        if spec is None:
            audit("gate.deny", **base, reason="unknown_tool")
            return ToolResult(
                success=False, denied=True,
                denial_reason=f"unknown tool: {request.tool_name}",
            )

        # 1.5 deep-freeze arguments
        try:
            frozen_args = copy.deepcopy(request.arguments)
        except Exception as e:
            audit("gate.deny", **base, reason="freeze_failed", detail=str(e))
            return ToolResult(
                success=False, denied=True,
                denial_reason=f"could not freeze arguments: {e}",
                level=LEVEL_NAMES[spec.level],
            )

        descriptor = self._build_descriptor(spec, request, frozen_args)
        audit("gate.descriptor_created", **base,
              operation_id=descriptor.operation_id,
              descriptor_hash=descriptor.descriptor_hash()[:16],
              capability=descriptor.capability,
              domain=descriptor.domain,
              declared_risk=descriptor.declared_risk,
              origin=descriptor.originating_source,
              derived_from=descriptor.derived_from)

        # 1.6 Phase 5B control-plane hard deny.
        cp_denial = self._control_plane_deny(spec, frozen_args, base)
        if cp_denial is not None:
            return cp_denial

        # 1.7 Phase 5C workspace classification.
        ws_denial = self._workspace_classification_check(
            spec, frozen_args, base
        )
        if ws_denial is not None:
            return ws_denial

        # 2. sandbox
        for param in spec.path_params:
            value = frozen_args.get(param)
            if value is None:
                continue
            check = check_sandbox(value, self.sandbox_root, self.sandbox_enabled)
            if not check.allowed:
                logger.warning(
                    "[SECURITY] Sandbox boundary: %s.%s(%r) - %s",
                    spec.name, param, value, check.reason)
                audit("gate.deny", **base, reason="outside_sandbox",
                      detail=check.reason)
                return ToolResult(
                    success=False, denied=True,
                    denial_reason=f"outside sandbox: {check.reason}",
                    level=LEVEL_NAMES[spec.level])

        # 3. protected folder
        for param in spec.path_params:
            value = frozen_args.get(param)
            if value is None:
                continue
            check = is_inside_protected(value, self.protected_folder)
            if not check.allowed:
                logger.warning("[SECURITY] Blocked: %s.%s(%r) - %s",
                               spec.name, param, value, check.reason)
                audit("gate.deny", **base, reason="protected_folder",
                      detail=check.reason)
                return ToolResult(
                    success=False, denied=True,
                    denial_reason=f"protected path: {check.reason}",
                    level=LEVEL_NAMES[spec.level])

        # 4. hard deny
        for param in spec.path_params:
            value = frozen_args.get(param)
            if value is None:
                continue
            hard = check_hard_deny(value, tool_level=spec.level)
            if hard:
                audit("gate.deny", **base, reason="hard_deny",
                      detail=hard.reason, rule=hard.pattern)
                return ToolResult(
                    success=False, denied=True,
                    denial_reason=f"hard-deny rule: {hard.reason}",
                    level=LEVEL_NAMES[spec.level])

        # 5. path rules
        path_rule_decision: Optional[str] = None
        path_rule_reason = ""
        for param in spec.path_params:
            value = frozen_args.get(param)
            if value is None:
                continue
            rule = check_path_rules(value, tool_level=spec.level)
            if rule is None:
                continue
            if rule.action == "deny":
                audit("gate.deny", **base, reason="path_rule_deny",
                      rule=rule.pattern, detail=rule.reason, param=param)
                return ToolResult(
                    success=False, denied=True,
                    denial_reason=f"path rule: {rule.reason}",
                    level=LEVEL_NAMES[spec.level])
            cur_rank = _RULE_RANK.get(path_rule_decision, 0)
            new_rank = _RULE_RANK.get(rule.action, 0)
            if new_rank > cur_rank:
                path_rule_decision = rule.action
                path_rule_reason = rule.reason

        # 6. system-looking
        system_looking = False
        system_reason = ""
        for param in spec.path_params:
            value = frozen_args.get(param)
            if value is None:
                continue
            sl, sl_reason = is_system_looking(value)
            if sl:
                system_looking = True
                system_reason = sl_reason
                break

        # 6.5 confirm_if
        extra_confirms: list = []
        if spec.confirm_if is not None:
            try:
                needs, reason = spec.confirm_if(frozen_args)
                if needs:
                    extra_confirms.append(
                        reason or f"{spec.name} requested confirmation")
            except Exception:
                logger.exception("confirm_if raised for %s; escalating",
                                 spec.name)
                extra_confirms.append(
                    f"confirm_if raised for {spec.name} (fail-closed)")

        # 7. combine Phase 1 signals
        base_decision = self.policy.decision(spec.level)
        final = base_decision
        if system_looking:
            final = _strictest_decision(final, "confirm")
        if path_rule_decision:
            final = _strictest_decision(final, path_rule_decision)
        if extra_confirms:
            final = _strictest_decision(final, "confirm")

        # 7.5 effective risk
        gate_risk = self._derive_gate_risk(
            spec, system_looking, path_rule_decision, extra_confirms
        )
        effective_risk = max(descriptor.risk, gate_risk)

        audit("gate.risk_evaluated", **base,
              descriptor_risk=descriptor.declared_risk,
              gate_risk=risk_name(gate_risk),
              effective_risk=risk_name(effective_risk),
              origin=descriptor.originating_source,
              derived_from=descriptor.derived_from)

        # 7.6 Phase 2/4 permission
        p2_decision, p2_reason = self._evaluate_phase2_permission(
            descriptor, effective_risk
        )
        audit("gate.phase2_permission", **base,
              decision=p2_decision, reason=p2_reason,
              effective_risk=risk_name(effective_risk),
              capability=descriptor.capability,
              domain=descriptor.domain,
              origin=descriptor.originating_source,
              derived_from=descriptor.derived_from)

        if p2_decision == "deny":
            return ToolResult(
                success=False, denied=True,
                denial_reason=p2_reason,
                confirmation_needed=False,
                level=LEVEL_NAMES[spec.level],
            )

        if p2_decision == "confirm":
            final = _strictest_decision(final, "confirm")

        reason_parts = []
        if system_looking:
            reason_parts.append(f"system-looking ({system_reason})")
        if path_rule_reason:
            reason_parts.append(path_rule_reason)
        reason_parts.extend(extra_confirms)
        if p2_decision == "confirm":
            reason_parts.append(p2_reason)
        reason_str = "; ".join(reason_parts) or spec.description

        audit("gate.decision", **base, decision=final,
              level=LEVEL_NAMES[spec.level],
              base_decision=base_decision,
              path_rule=path_rule_decision or "",
              system_looking=system_looking,
              extra_confirms=extra_confirms,
              phase2=p2_decision,
              effective_risk=risk_name(effective_risk),
              origin=descriptor.originating_source,
              derived_from=descriptor.derived_from,
              reason=reason_str)

        if final == "deny":
            return ToolResult(
                success=False, denied=True,
                denial_reason=reason_str,
                level=LEVEL_NAMES[spec.level])

        # 8. confirmation
        authorized_descriptor = descriptor
        if final == "confirm":
            extended = (
                bool(system_looking)
                or bool(extra_confirms)
                or path_rule_decision == "confirm"
                or p2_decision == "confirm"
            )
            conf_req = ConfirmationRequest(
                tool_name=spec.name,
                arguments=frozen_args,
                level_name=LEVEL_NAMES[spec.level],
                reason=reason_str,
                forceable=not extended,
            )
            response = self.confirmation.request(conf_req)
            audit("gate.confirmation", **base,
                  approved=response.approved, note=response.note,
                  forceable=not extended)
            if not response.approved:
                return ToolResult(
                    success=False, denied=True,
                    denial_reason=f"confirmation denied: {response.note}",
                    confirmation_needed=True,
                    level=LEVEL_NAMES[spec.level])

            authorized_descriptor = descriptor.with_authorization(
                "local_user_confirmation"
            )
            audit("gate.authorization_granted", **base,
                  operation_id=authorized_descriptor.operation_id,
                  parent_hash=descriptor.descriptor_hash()[:16],
                  authorized_hash=authorized_descriptor.descriptor_hash()[:16],
                  authorization_source=authorized_descriptor.authorization_source)

        # 8.5 issue token against the authorized descriptor
        token_id = self.tokens.issue(authorized_descriptor)
        audit("gate.token_issued", **base,
              operation_id=authorized_descriptor.operation_id,
              token_id_prefix=token_id[:8],
              effective_risk=risk_name(effective_risk),
              authorization_source=authorized_descriptor.authorization_source)

        is_elevated = (
            authorized_descriptor.requested_privilege == "elevated"
        )
        use_elevated = is_elevated and elevated_executor is not None

        if use_elevated:
            claims = self._token_claims(authorized_descriptor)
            output = None
            outcome = "error"
            try:
                output = elevated_executor(
                    frozen_args, authorized_descriptor, token_id, claims
                )
                if isinstance(output, dict):
                    outcome = output.get("outcome", "error")
                else:
                    outcome = "error"
                    output = {
                        "outcome": "error",
                        "reason": "elevated executor returned non-dict",
                        "operation_id": authorized_descriptor.operation_id,
                    }
            except Exception as e:
                logger.exception(
                    "Elevated executor raised for %s", spec.name
                )
                output = {
                    "outcome": "error",
                    "reason": f"elevated executor raised: {e}",
                    "operation_id": authorized_descriptor.operation_id,
                }
                outcome = "error"
            finally:
                c_ok, c_reason = self.tokens.consume(
                    token_id, authorized_descriptor
                )
                if c_ok:
                    audit("gate.token_consumed", **base,
                          operation_id=authorized_descriptor.operation_id,
                          token_id_prefix=token_id[:8],
                          path="elevated")
                else:
                    audit("gate.token_consume_anomaly", **base,
                          operation_id=authorized_descriptor.operation_id,
                          token_id_prefix=token_id[:8],
                          reason=c_reason, path="elevated")

            if outcome == "success":
                audit("gate.result", **base, success=True, path="elevated")
                return ToolResult(success=True, output=output,
                                  level=LEVEL_NAMES[spec.level])
            if outcome == "denied":
                audit("gate.result", **base, success=False, denied=True,
                      path="elevated",
                      reason=str(output.get("reason", "")))
                return ToolResult(
                    success=False, denied=True,
                    denial_reason=str(output.get("reason", "elevated denied")),
                    confirmation_needed=False,
                    level=LEVEL_NAMES[spec.level],
                )
            audit("gate.result", **base, success=False, path="elevated",
                  outcome=outcome, reason=str(output.get("reason", "")))
            return ToolResult(
                success=False,
                error=str(output.get("reason", outcome)),
                output=output,
                level=LEVEL_NAMES[spec.level],
            )

        # Standard path
        ok, reason = self.tokens.consume(token_id, authorized_descriptor)
        if not ok:
            audit("gate.token_rejected", **base,
                  operation_id=authorized_descriptor.operation_id,
                  token_id_prefix=token_id[:8],
                  reason=reason)
            return ToolResult(
                success=False, denied=True,
                denial_reason=f"authorization token rejected: {reason}",
                level=LEVEL_NAMES[spec.level],
            )
        audit("gate.token_consumed", **base,
              operation_id=authorized_descriptor.operation_id,
              token_id_prefix=token_id[:8], path="standard")

        logger.info("Executing %s (level=%s)", spec.name,
                    LEVEL_NAMES[spec.level])
        try:
            output = executor(frozen_args)
            audit("gate.result", **base, success=True, path="standard")
            return ToolResult(success=True, output=output,
                              level=LEVEL_NAMES[spec.level])
        except Exception as e:
            logger.exception("Tool %s raised", spec.name)
            audit("gate.result", **base, success=False, error=str(e),
                  path="standard")
            return ToolResult(success=False, error=str(e),
                              level=LEVEL_NAMES[spec.level])