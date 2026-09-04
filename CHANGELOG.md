# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, so `0.x` minor bumps may
change the public surface.

## [Unreleased]

Phases 1 and 2 of the development plan: the vocabulary, the registry, the executor's fixed refusal
order, path containment, the record, and the tiered isolation ladder. **Nothing is published yet** —
`toolyard 0.1.0` ships at the end of Phase 3, with the built-in tools.

### Fixed

* **`install-check` imported the wrong package.** `.github/workflows/ci.yml` ran
  `python -c "import cutctx"` — the toolchain was copied from CutCtx and this one line was never
  adapted, so the job that proves the built wheel imports has never once proved it for this
  package, and it has been failing since the workflow was written. It now imports `toolyard`. It
  was the only leftover: nothing else under `.github/`, `pyproject.toml`, `requirements/`,
  `README.md`, `CONTRIBUTING.md` or `SECURITY.md` named CutCtx.

### Added — Phase 2, sandbox

* **`TieredSandbox`** (`sandbox.py`) — the ADR-0018 ladder applied to tools: container (`podman`
  preferred, then `docker`) → `bwrap` → refuse, with no rung below refusal and no flag that adds
  one. It **composes** `PathContainment` for the path half rather than re-deriving it, so both
  implementations of the `Sandbox` port run the same containment contract.
* **The tier probe executes a canary.** Each rung is proven by running the exact argv
  `run_isolated` would build — same flags, same limits, a temporary workspace bound the same way —
  around `/bin/true`, never by trusting a version string. Installed is not functional: a `bwrap`
  that cannot create namespaces, a container daemon that is down, or an image that was never
  pulled each fail their canary and are reported, with the reason, in `TierReport`. The container
  rung probes and runs with `--pull=never`, so a probe never reaches the network. The probe runs
  once per sandbox and is cached; `report()` exposes it for an application's `doctor`.
* **`run_isolated`** — argv only, never a shell; `env=None` is the **empty** allowlist and the
  sandbox binary itself is launched with `PATH` alone, so the process environment has no route
  into a tool; the workspace is bound in place (write root read-write, read roots read-only,
  nearest root winning on both rungs) and is the working directory; a wall-clock timeout kills the
  whole process tree (a new session and process group, a pid namespace under bwrap, and the
  container removed by name under a runtime whose CLI dying would not stop it); an output bomb is
  capped per stream and killed, with the truncation label on the text. Nothing about the argv
  raises: an argv that cannot be launched comes back as a result with exit code 127 and a
  `stderr` naming why.
* **`ResourceLimits`** — CPU seconds, memory bytes, file-size bytes and process count, applied as
  rlimits **inside** the bwrap sandbox by `prlimit`, and as cgroup limits plus rlimits under a
  container. A limit a rung cannot apply is named in the result's `limits_unenforced`
  (ADR-0016): every rlimit when `prlimit` is absent, the cgroup limits when the container runtime
  warns it discarded them.
* **`tests/integration/test_isolation.py`**, marked `isolation` — both rungs for real, each test
  twice: pid and network namespaces, the filesystem view (a file outside the roots does not exist,
  a planted symlink reaches nothing, a read root is not writable, `/tmp` is private, the runtime
  is read-only), the environment allowlist, the process-tree kill, the output bomb, a fork
  attempt, and the file-size and memory limits. The bwrap rung is **forced** by handing the probe
  an executable lookup that cannot see `podman` or `docker`, so the middle rung is exercised
  rather than masked by the top one. Skipped, loudly, where a rung is not available.
* **`tests/unit/test_boundaries.py`** now also pins the package to exactly one process-launch site.
* **`SandboxPaths` is validated at construction** (spec §7, amended at D1): every root absolute, no
  root equal to or containing another. A relative root would resolve against the process working
  directory; overlapping roots would make the path half and the subprocess half disagree.
* **`SubprocessResult.output_truncated`** (spec §7, amended at D1) — a stream hit the cap, reading
  stopped and the tree was killed. Distinct from `timed_out`; defaults to `False`.
* **`run_isolated(network=True)` is refused** as a caller bug (spec §14, amended at D1): no
  shipped tool runs a subprocess with network. Both rungs' argv builders carry no network branch
  at all; the flag stays on the port so naming a consumer is a one-line change.

### Added — Phase 1

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

### Decided — Phase 2

Recorded in `D1_HANDOFF.md`, for E2 and E4:

* **rlimits go through `prlimit`, inside the sandbox, not through `resource` in a `preexec_fn`.**
  `preexec_fn` is documented unsafe in a threaded process, and the consumer is a threaded server;
  and `RLIMIT_NPROC` is checked against the user's task count at every level of the user-namespace
  hierarchy, so a fork-bomb-sized limit applied *before* `bwrap` creates its namespace makes that
  creation fail on a busy desktop. Applied inside, it bounds the sandbox and nothing else.
* **Both rungs bind the workspace in place**, at the resolved host paths, so an argv means the same
  thing under either, and the resolved path a handler received from containment is the path the
  command sees.
* **The bwrap rung binds six named `/etc` entries, never `/etc` whole.** Widening that tuple is a
  security review item.
* **A decided rung is never re-decided.** A runtime that vanishes after the probe raises
  `ToolYardError`; it is never quietly replaced by a weaker rung.
* **Non-Linux platforms have no tier** (spec §16) and are not probed.
* **The launcher gets `PATH` only.** A rootless Docker reachable only through `DOCKER_HOST` is
  not discoverable; the probe reports docker's failed canary and lands on bwrap. Left until a
  deployment asks, rather than reading the environment against spec §12.
* **Podman stays first in the ladder, unverified on the reference machine**; an operator step
  before E2 publishes 0.1.0.
* **`run_command_tool` takes the executor's sandbox** (spec §7, amended at D1): E2's handler
  receives the same `TieredSandbox` instance the executor holds, so the tier the executor checked
  is the tier the command runs under.
* **The `isolation` marker runs where a rung exists and skips, visibly, where none does.** It is
  not excluded by `addopts`; a skip is not a pass.

### Decided — Phase 1

Four shapes spec §7 left under-determined were settled in Phase 1 and are recorded in
`C2_HANDOFF.md` for the phases that follow:

* **The allowlist narrows and never widens.** The trajectory allowlist is the executor's; a
  per-invocation set narrows it through `ToolContext.approved_tools`, and the effective set is the
  intersection. A new refusal reason, `not_approved`, distinguishes the re-approvable drift from
  `not_allowlisted`, which never is. A consumer that mints an approved set per turn supplies it
  from there (PromptCadence from its `ExecutionIntent`), but the field is a set of names and the
  reason names no consumer's concept.
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
