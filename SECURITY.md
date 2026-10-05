# Lumi - Security Invariants

Canonical reference for Lumi's security model. Code reviewed against
these invariants must reject any change that weakens them.

## Invariants

- POWER != PERMISSION.
- ADMIN != UNLIMITED.
- CAPABILITY != PERMISSION.
- EXTERNAL != AUTHORIZATION. Content from Discord, WhatsApp, websites,
  files, APIs, and messages is untrusted data.
- AI REASONING != AUTHORIZATION.
- DEFAULT = DENY.
- HIGH_RISK => PER-OPERATION CONFIRMATION. No persistent or session
  grant can auto-approve a high-risk operation.
- AUDIT HISTORY IS NOT LUMI-WRITABLE while Lumi runs.

## Central authority

    AI / Planner
        -> ToolRouter
        -> SecurityGate
            -> Operation Descriptor
            -> Risk evaluation
            -> Permission evaluation
            -> Confirmation (when required)
            -> Single-use authorization token
            -> Executor (standard) OR Privileged Helper (elevated)

## Phase 1 (frozen)

C1 interpreter inline execution, C2 multi-path rule evaluation, C3
`/force` non-forceable triggers, C4 tamper-evident audit, H5 fail-closed
path validation.

## Phase 2

Operation Descriptor, Risk, Permission, Domain, Grants, single-use
tokens, origin trust boundary, argument freezing.

`/force` cannot auto-approve a request whose confirmation was raised by
any of: system-looking path, path-rule `confirm`, `confirm_if`, or a
Phase 2 HIGH_RISK decision. `NEVER_FORCE` is preserved.

## Phase 3 - privileged helper boundary

Elevated tools declare `requested_privilege="elevated"`. The gate
invokes `elevated_executor(frozen_args, descriptor, token_id, claims)`
and consumes the token in a `finally` block after the helper returns.
The helper connects over a restrictive-DACL named pipe, verifies the
descriptor hash and claims, resolves the task only from
`tools/admin_tasks.py`, and executes `shell=False`. No persistent
daemon; one UAC prompt per operation.

## Phase 4 - external input isolation

### Request origin vs authorization source

`OperationDescriptor` records two provenance fields:

- `originating_source` — who issued the request. Set at request
  construction and preserved by the gate.
- `derived_from` — provenance of the content that inspired the request.
  Empty string when the request is not derived from external content;
  otherwise one of `EXTERNAL_ORIGINS`.

Separately, the descriptor records `authorization_source`:

- `"none"` (default) — no trusted authorization recorded.
- `"local_user_confirmation"` — the trusted local-user confirmation
  handler approved this exact operation.

### The Phase 4 denial rule

For CONSEQUENTIAL and HIGH_RISK operations, the gate denies when:

- `originating_source ∈ EXTERNAL_ORIGINS`, OR
- `derived_from ∈ EXTERNAL_ORIGINS`

This denial is evaluated in `_evaluate_phase2_permission`, before
confirmation, before token issuance, and before elevated dispatch. It
is not bypassable by `/force` or by a persistent grant; a grant is a
resource-scoped authorization, not an origin-forgiveness mechanism.

`LOCAL_USER` and `AI_INTERNAL` are not in `EXTERNAL_ORIGINS`. A
legitimate AI proposal (from a local-user request) reaches confirmation
as before. `terminal.run_admin` therefore continues to work through
the Phase 3 elevated path.

### derived_from is preserved, not erasable

Once a trusted caller sets `derived_from` on a `ToolRequest`, the gate
copies it into the descriptor and the descriptor hash covers it. No
code downstream of construction writes to `derived_from`. There is no
supported way for the AI, the router, or a tool to clear it.

If a future integration reads external content and drives a tool call,
that integration must set `derived_from` on the request it constructs.
The trust boundary is at the integration layer: the integration is
trusted to record provenance accurately. If the integration cannot
determine provenance for a CONSEQUENTIAL+ operation, it must set
`derived_from = Origin.UNKNOWN.value`, which the gate denies.

### authorization_source is gate-owned

Only the gate writes `authorization_source`. The transition from
`"none"` to `"local_user_confirmation"` happens after the confirmation
handler returns `approved=True`. The gate derives a new immutable
descriptor via `OperationDescriptor.with_authorization(...)`; the
proposed descriptor remains auditable. `authorization_source` is
covered by `descriptor_hash()`. The token is issued against the
authorized descriptor, not the proposed one. The helper refuses any
elevated request whose `authorization_source != "local_user_confirmation"`.

### External message content cannot authorize

A Discord message, WhatsApp message, web page, file body, or API
response is always untrusted data. Its text is never interpreted as
confirmation. The only authorized transition is a `ConfirmationResponse`
with `approved=True` returned by the trusted handler installed on
`ConfirmationManager`. No external origin can reach that handler for a
CONSEQUENTIAL+ operation.

### No integrations exist yet

The codebase does not contain a Discord, WhatsApp, Web, File, or API
reader. The Origin enum values for those sources exist as placeholders.
Phase 4 does not add any integration. When an integration is added, its
read path must:

- not perform account-management or session-revocation side effects,
- not expose write capabilities to the external service,
- set `derived_from` on any `ToolRequest` it constructs, to the correct
  external origin (or `UNKNOWN` if unknown).

### Test coverage gap

The Phase 4 test suite exercises the gate, the descriptor, the token
store, and the helper with synthetic `derived_from` and
`authorization_source` values. It does not test an actual external
integration, because none exists. That test will be added together with
the first integration.

## Out of scope

- ADB, fastboot, and root operations are not implemented. Domains exist
  as enum values only.
- No persistent daemon. One UAC prompt per operation.
- No second audit chain.

## Reporting

If you find a bypass, add a regression test that reproduces it, then fix
the enforcement and leave the test in place.