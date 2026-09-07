# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — pre-1.0, so `0.x` minor bumps may
change the public surface.

## [Unreleased]

## [0.1.1] — 2026-09-06

### Added
- **`json_sanitize` is exported from the package root.** It was reachable only as
  `toolyard._safe.json_sanitize`, and a caller needed it: `args_sha256` on a `ToolCallRecord` is
  the digest of the *sanitized* arguments, so anything that emits its own event about the same
  tool call has to be able to compute the same number. The alternative is a second copy of a
  hardening routine that must agree byte for byte with this one, which is how two digests of the
  same call drift apart — PromptCadence 1.0.1 fixes exactly that defect and needs this export to
  fix it without duplicating the walk. The function itself is unchanged; only its visibility moves.

### Fixed
- **The package docstring no longer claims nothing is on PyPI.** `toolyard 0.1.0` was published;
  the status paragraph still said publication had not happened.

## [0.1.0] — 2026-09-03

The first release. Phases 1 to 3 of the development plan: the vocabulary, the registry, the
executor's fixed refusal order, path containment, the record, the tiered isolation ladder, and the
five built-in tools.

### Added — Phase 3, the built-in tools

* **The five built-ins**, each returning the `(ToolSpec, ToolHandler)` pair the registry takes, so
  registration reads `registry.register(*read_file_tool())` and nothing registers implicitly.
  * `read_file`, `write_file`, `list_dir` (`tools/files.py`). **No handler resolves a path** — each
    declares its path argument in `path_args`, the executor resolves it and substitutes the result
    before the handler runs (spec §11.3), and a second resolution would reopen the window the first
    one closed. A consequence worth stating: the handler never sees the model's own string, so
    every message a model reads is rendered *relative to the root that holds it* and the absolute
    path goes only to the record.
  * `run_command` (`tools/command.py`), holding the **same sandbox instance the executor holds**
    (spec §7 as amended at D1, decision A) so the tier the executor checked is the tier the command
    runs under. Argv only, no shell, no network, an explicit `PATH`-only environment that is the
    caller's with no argument through which a model could reach it, and both the exit code and
    `output_truncated` rendered so a truncated success is distinguishable from a clean one.
  * `http_fetch` (`tools/fetch.py`), performing every ADR-0026 §3 check at the socket and
    re-checking **in full** on every redirect hop.
* **`ToolRefusal`** — a handler returns one instead of output when its own check says no. Without
  it, spec §13's *"REFUSED / the specific ADR-0026 check"* was unexpressible: a handler could only
  succeed or raise, and a raise is `FAILED` / `handler_error`, which names an exception class
  rather than a check. Its `reason` is a `Reason`, so the closed set stays closed for handlers too.
  `ToolHandler.execute` now returns `ToolOutput | ToolRefusal`; widening a return type is backwards
  compatible and an existing handler still satisfies the protocol.
* **Fifteen new `Reason` members** — nine ADR-0026 §3 checks, the two ways an origin fails, and
  four ways a file argument names something unusable. Adding a reason is a **minor** change
  consumers must be told about (spec §19), and doing it before the first publish is free exactly
  once. The fetch strings mirror LoadCoach's exactly, so a reviewer comparing the two
  implementations is not also translating.
* **One ADR-0026 §3 vector set, byte-shared with LoadCoach.**
  `tests/fixtures/fetch/adr0026_vectors.json` is authored here and copied into LoadCoach
  byte-for-byte; its sha256 is asserted in both repositories, so an edit on one side alone fails a
  test rather than becoming a divergence found later in production. Twenty-four cases drive this
  package's tool here and `FreeWeightClient` there. **LoadCoach passed every one unchanged** — no
  behaviour change and nothing touched under its `src/`. Sizes are expressed relative to the
  configured cap, because it is 8 MiB here and 128 MiB there.
* **`httpx>=0.27,<1`**, declared in the same commit that first imports it, as
  `requirements/README.md` promised. It is the second and last non-suite runtime dependency gold
  standards §1.1 allows, and the budget is now spent. `.importlinter` is unchanged: the
  `toolyard.tools.fetch -> httpx` exemption was written two phases before the import.
* **`acceptance/register_and_execute.py`** — spec §20 criterion 2 as a runnable check rather than a
  demonstration. It registers a custom tool and executes it with only `toolyard` and its declared
  dependencies installed, and exits non-zero when a claim fails.
* **The five built-ins' wire definitions are golden-locked** (`tests/goldens/`). They are what a
  model reads and what PromptCadence hashes into its turn records, so a description change is a
  change to every recorded turn.

### Decided — Phase 3

* **`http_fetch`'s `resolve` is required and has no default.** Spec §11.5 requires the link-local
  comparison to happen after resolution; `.importlinter` forbids `socket` in every module of this
  package, forever. So ToolYard opens no resolver socket of its own and the application injects
  one. Required rather than defaulted because every default available is either that boundary
  violation or a resolver that answers nothing — and one that answers nothing makes the check
  vacuous without saying so. A literal IP is never passed to the resolver: it already is the
  answer, and letting an application-supplied callable erase a link-local literal is the one case
  that must not depend on anything injectable.
* **Where the REFUSED/FAILED line falls.** `REFUSED` is this package declining under a rule of its
  own, where the identical call will be declined again for the same reason. `FAILED` is the work
  attempted and the world answering badly, where a different argument or a later attempt may
  succeed. So `too_large` is a refusal and `file_not_found` is a failure — assigned by that test
  and not by how serious the outcome sounds. The `FAILED` rows are refinements of `handler_error`,
  existing so a model is told what was wrong with its argument instead of an exception's name.
* **`read_file` refuses an oversized file rather than returning a prefix**, while `list_dir`
  truncates and says how many it omitted. The difference follows from the record: `result_sha256`
  digests the handler's whole output, so a prefix would make the recorded digest a digest of the
  prefix; nothing hashes a listing against an original.
* **`write_file` creates parents one level at a time**, refusing any component that is a symbolic
  link. The development plan named this phase's failure mode as *"creating parents outside the root
  via a symlinked intermediate directory"*, and `mkdir(parents=True)` is exactly how it happens. A
  link that existed at resolution time was already resolved through, so the check exists for the
  case where one is planted between check 5 and the write. **The race itself is not closed** —
  that needs `openat`/`O_NOFOLLOW` and therefore `os`, and `.importlinter` gives this module
  `pathlib` alone, deliberately. The window is narrowed to one component and the residual is
  written down.
* **The content-type allowlist is closed, small and text.** LoadCoach admits JSON because it parses
  JSON; this tool returns a string to a model, and a model handed a decoded PNG has been handed
  noise. A `+json` structured suffix is admitted, as it is there, so a shared vector holds in both.
* **`_next_hop` does not guard its own `join`.** httpx parses the `Location` header while it builds
  the response, so a header that is not a URL arrives as a transport error before the redirect
  logic runs; a guard would be a branch no input could take. A test pins that behaviour, so if
  httpx ever stops pre-parsing, a test says so rather than a model receiving an exception.
* **The DNS residual is stated, not implied away.** `http_fetch` resolves and then connects, and
  those are two operations. A name whose answer changes between them — rebinding against an
  allowlisted host — is outside what this design addresses; closing it needs the connection pinned
  to the address that was checked, and httpx exposes no seam for that. The allowlist stands in its
  place and no docstring claims otherwise.

### Fixed

* **`install-check` imported the wrong package.** `.github/workflows/ci.yml` ran
  `python -c "import cutctx"` — the toolchain was copied from CutCtx and this one line was never
  adapted, so the job that proves the built wheel imports has never once proved it for this
  package, and it has been failing since the workflow was written. It now imports `toolyard`. It
  was the only leftover: nothing else under `.github/`, `pyproject.toml`, `requirements/`,
  `README.md`, `CONTRIBUTING.md` or `SECURITY.md` named CutCtx.

* **An unresolvable symlink cycle is refused, on every supported interpreter.** Containment
  delegated the question to `Path.resolve()`, which answers it differently by version: 3.13 and
  later give up on a cycle and hand back the path unresolved, so it was admitted; 3.12 raises
  `RuntimeError("Symlink loop from …")`, so it was refused. The blocking CI matrix covers both, so
  the containment suite was red on 3.12 alone — and a containment answer that depends on which
  interpreter is running is itself the defect. `containment.fully_resolve()` settles it once and
  settles it **closed**: `os.path.realpath(strict=True)` raises `ELOOP` for a cycle on every
  interpreter from 3.10, and anything that is not a cycle falls back to the ordinary non-strict
  resolution that a not-yet-created path needs. Refusing costs no reachable file — the kernel
  answers `ELOOP` to every attempt to open a cycle — and it matches the refusal containment
  already gave a path the operating system will not parse.

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

Recorded in `docs/history/D1_HANDOFF.md`, for E2 and E4:

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
`docs/history/C2_HANDOFF.md` for the phases that follow:

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
