# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, so `0.x` minor bumps may
change the public surface.

## [Unreleased]

Phase 1 of the development plan: the vocabulary, the registry, the executor's fixed refusal order,
path containment and the record. **Nothing is published yet** — `toolyard 0.1.0` ships at the end of
Phase 3, with the built-in tools.

### Added

* **Vocabulary** (`types.py`, `containment.py`) — `ToolSpec`, `ToolContext`, `ToolCallRequest`,
  `ToolOutput`, `ToolResult`, `ToolCallRecord`, `RegisteredTool`, `RiskClass`, `EgressClass`,
  `ToolStatus`, `Reason`, `PathAccess`, `SandboxPaths`, `IsolationTier`, `SubprocessResult`, and
  the `ToolHandler`, `Sandbox` and `ToolCallStore` protocols. `RiskClass` and `EgressClass` are
  ordered ceilings rather than flat enums, so a policy filter is a comparison and a third class
  needs no call site changed.
* **`ToolSpec.wire_definition()`** — provider-neutral and byte-stable, with a committed golden
  (`tests/goldens/wire_definitions.json`). Fixed key set, deep-copied schema, and a sorted export
  order from `ToolRegistry.wire_definitions()`, because PromptCadence hashes these into turn
  records and callers pass sets.
* **`ToolRegistry`** — registration in code at startup, duplicate names raise, exact-name lookup,
  policy-filtered listing sorted by name. No unregister, no dynamic loading, and no seam that could
  grow one.
* **`ToolExecutor`** — the fixed refusal order registry → allowlist → schema → egress →
  containment, walked as a declared sequence of positioned checks rather than a chain of `if`
  statements; the package refuses to import if the positions are not a complete sequence.
* **`PathContainment`** — real resolution-then-check path containment over separate read and write
  roots, comparing by path ancestry so `/data` and `/database` are two roots. Reports
  `IsolationTier.UNAVAILABLE`, honestly, because Phase 1 has no isolation tier.
* **`ToolCallStore`** protocol and `InMemoryToolCallStore` (tests only).
* **Errors** — `ToolYardError`, `DuplicateTool`, `InvalidToolSpec`, `StoreFailure`; caller bugs
  only. `StoreFailure` carries the result and the record it could not write, so a broken store does
  not cost an application the audit trail of a side effect that already happened.

### Decided

Four shapes spec §7 left under-determined were settled this phase and are recorded in
`C2_HANDOFF.md` for the phases that follow:

* **The allowlist narrows and never widens.** The trajectory allowlist is the executor's; a turn's
  `ExecutionIntent` narrows it through `ToolContext.approved_tools`, and the effective set is the
  intersection. A new refusal reason, `not_in_intent`, distinguishes the re-approvable drift from
  `not_allowlisted`, which never is.
* **Egress is a per-invocation ceiling** — `ToolContext.max_egress`, defaulting to
  `EgressClass.NONE`. Closed, like every default here.
* **The sandbox is a port the executor depends on**, with an honest Phase-1 implementation:
  containment real, isolation absent and reported as absent. `path_escape` and
  `isolation_unavailable` are both reachable and tested through `execute()` in this phase, before
  any code exists that could run a command.
* **Caps and timeouts are constructor arguments only.** `ToolContext.timeout_seconds` is
  `float | None`, where `None` means the executor's default and never "no timeout"; an infinite or
  non-positive value is refused at construction.

Two further strictnesses, both stricter than the specification requires:

* **Argument schemas must be closed** — `additionalProperties: false` at every object-typed
  subschema, checked when a `ToolSpec` is constructed. JSON Schema admits unknown properties by
  default, which makes an open schema a tool a model can pass unreviewed arguments to.
* **The `$ref` family is refused in a tool schema.** A reference is a URI, and a validator handed
  an unresolved one attempts to *retrieve* it — an outbound fetch from a tool declaration, in the
  package whose purpose is that egress passes one door.
