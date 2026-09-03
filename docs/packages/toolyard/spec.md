# ToolYard — Specification

**Type:** Python package · **Import/distribution name:** `toolyard` · **Layer:** 3 (capability package)
**Status:** Specified, not implemented. Part of the PromptCadence arc
([roadmap](../../roadmap/promptcadence-roadmap.md)); decision record D-9 (tool execution discipline),
extending [ADR-0018](../../adr/0018-external-benchmark-isolation.md) (tiered sandboxing) and
[ADR-0026 §3](../../adr/0026-local-http-hardening.md) (outbound fetch) to model-directed tools.

---

## 1. Purpose

Be the one place in the suite that executes a real, side-effecting tool call on a model's behalf —
and therefore the one place the associated risk concentrates and the associated discipline lives:
schema validation, allowlisting, path containment, tiered subprocess isolation, egress-checked
fetching, structured refusals and a persisted record of every call. LoadCoach deliberately never
executes tools ([LoadCoach spec §3](../../apps/loadcoach/spec.md)); FreeWeight's benchmark loops
execute only scorer-owned fakes. PromptCadence needs real execution now, and IdeaPress's specified but
unshipped `research` stage ([Workflows §2](../../apps/ideapress/workflows.md)) will need exactly
this fetch/execute/allowlist discipline when it lands.

## 2. Scope

* `ToolSpec`: a tool's declaration — name, JSON Schema for arguments and result, risk class,
  egress class, redaction flag.
* `ToolRegistry`: registration, lookup, policy-filtered listing, wire-definition export.
* `Sandbox`: per-invocation containment — resolved-path checks against separate read/write roots,
  and tiered subprocess isolation (container → bwrap → refuse) for command execution.
* `ToolExecutor`: validate → authorize → execute → record; converts every refusal into a
  structured `ToolResult`, never an exception.
* Built-in tools: `read_file`, `write_file`, `list_dir`, `run_command`, `http_fetch`.
* `ToolCallRecord` and the `ToolCallStore` protocol (persistence is the application's).

## 3. Explicit non-goals

* **No agent loop.** ToolYard executes one call; deciding to call is the application's loop.
* **No model access and no provider JSON.** `ToolSpec.wire_definition()` exports the neutral shape
  callers hand to LoadCoach/ModelRack; ToolYard itself never talks to a model.
* **No persistence.** It defines the record and the store protocol; the application owns tables
  and retention.
* No tool marketplace, no dynamic loading of tool code from configuration or from model output —
  handlers are Python objects registered by the application at startup, full stop.
* No retry policy — a failed tool call is a structured result; the caller decides.
* No privilege escalation helpers: nothing in ToolYard runs as another user or relaxes the
  sandbox from inside it.

## 4. Responsibilities

| Responsibility | Detail |
|---|---|
| Declaration | `ToolSpec` with argument/result JSON Schemas, `risk_class`, `egress`, `redact_args` |
| Registry | Register at startup; `get()` by exact name only; `list_for_policy()` filtered by risk/egress; export wire definitions |
| Validation | Model-supplied arguments validated against the schema before any handler sees them |
| Containment | Symlink-resolved path checks against separate read roots and a single write root |
| Isolation | `run_command` under container → bwrap → refuse, reusing the ADR-0018 tier order |
| Fetching | `http_fetch` under ADR-0026 §3: scheme, host allowlist, literal-IP, redirect, size rules |
| Refusal | Every refusal is a `ToolResult` with `status=REFUSED` and a reason — visible to the model and to the record |
| Record | `ToolCallRecord` per call: name, args (or hash when redacted), result summary, status, duration, risk/egress class |

## 5. Dependencies

`baseaicore`, `jsonschema>=4,<5`, `httpx>=0.27,<1`. Nothing else — in particular not `setspec`
(records are in-process values; applications serialize them) and no sibling capability package.

## 6. Consumers

PromptCadence (the agent loop's executor), IdeaPress `research` stage (future, at its own ADR), and any
external harness wanting the same discipline.

## 7. Public API

```python
class RiskClass(StrEnum):   READ_ONLY = "read_only";  MUTATING = "mutating"
class EgressClass(StrEnum): NONE = "none";            NETWORK = "network"
class PathAccess(StrEnum):  READ = "read";            WRITE = "write"
# RiskClass and EgressClass are ordered ceilings, not flat sets: a caller states a maximum and a
# rank comparison admits everything at or below it, so a third class changes no call site.
# EgressClass.permits(required) answers "does this ceiling admit a tool declaring `required`".

@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str                          # ^[a-z][a-z0-9_]{1,63}$
    description: str
    args_schema: Mapping[str, Any]     # JSON Schema (draft 2020-12)
    result_schema: Mapping[str, Any] | None
    risk_class: RiskClass
    egress: EgressClass
    redact_args: bool = False          # record stores sha256 only
    path_args: Mapping[str, PathAccess] = {}   # top-level string args that are paths, and the
                                       # root each is checked against (§11.3)
    requires_isolation: bool = False   # handler must run under Sandbox.run_isolated (§11.4)
    def wire_definition(self) -> Mapping[str, Any]: ...   # name+description+args schema, neutral
    # Validated on construction rather than at registration, so a half-checked spec cannot be
    # passed around. `args_schema` must be closed at every object-typed subschema carrying
    # `properties`, and must not use the `$ref` family (§14); either failure raises
    # InvalidToolSpec naming the failing path.

class ToolHandler(Protocol):
    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput: ...

@dataclass(frozen=True, slots=True)
class ToolContext:                     # injected per invocation by the application
    invocation_id: str                 # the application's, never the model's
    workspace: SandboxPaths            # write_root + read_roots for this trajectory/stage
    timeout_seconds: float | None      # None ⇒ the executor's default (§11.8)
    clock: Clock                       # injected, for determinism in tests
    approved_tools: frozenset[str] | None = None   # this invocation's approved set; None ⇒ the
                                       # trajectory allowlist stands alone (§11.2)
    max_egress: EgressClass = EgressClass.NONE     # per-invocation ceiling; defaults closed

class ToolRegistry:
    def register(self, spec: ToolSpec, handler: ToolHandler) -> None: ...   # duplicate name raises
    def get(self, name: str) -> RegisteredTool | None: ...
    def list_for_policy(self, *, max_risk: RiskClass | None = None,
                        allow_egress: bool = True) -> Sequence[ToolSpec]: ...
    def wire_definitions(self, names: Sequence[str]) -> Sequence[Mapping[str, Any]]: ...

@dataclass(frozen=True, slots=True)
class SandboxPaths:
    write_root: Path
    read_roots: tuple[Path, ...] = ()
    # Validated on construction: every root is absolute (a relative root would make containment
    # resolve against the process working directory, which §11.3 forbids), and no root is equal to
    # or an ancestor of another (the path half and the subprocess half would otherwise disagree
    # about a read root inside the write root). Either failure raises ValidationError.

class Sandbox(Protocol):               # a port: the executor depends on it, a phase supplies it
    def resolve_read(self, candidate: str, paths: SandboxPaths) -> Path: ...    # or PathEscape
    def resolve_write(self, candidate: str, paths: SandboxPaths) -> Path: ...
    def isolation_tier(self) -> IsolationTier: ...    # CONTAINER | BWRAP | UNAVAILABLE
    def run_isolated(self, argv: Sequence[str], *, paths: SandboxPaths,
                     timeout_seconds: float, env: Mapping[str, str] | None = None,
                     network: bool = False) -> SubprocessResult: ...
    # tier UNAVAILABLE ⇒ refusal, never an unisolated run (ADR-0018's rule, verbatim)
    # env None ⇒ the EMPTY allowlist, never os.environ (§14)
    # network True ⇒ refused as a caller bug in v1: no shipped tool runs a subprocess with
    # network, and a door with no consumer stays shut (§14)

@dataclass(frozen=True, slots=True)
class SubprocessResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    tier: IsolationTier                # which rung of the ladder actually ran it
    timed_out: bool                    # the process tree was killed for exceeding its limit
    limits_unenforced: tuple[str, ...] = ()   # limits this platform could not apply (ADR-0016)
    output_truncated: bool = False     # a stream hit the cap; reading stopped, the tree was killed,
                                       # and the text carries the truncation label

class ToolExecutor:
    def __init__(self, registry: ToolRegistry, sandbox: Sandbox, *,
                 allowlist: frozenset[str], store: ToolCallStore | None = None) -> None: ...
    def execute(self, call: ToolCallRequest, context: ToolContext) -> ToolResult: ...
    # order: name in registry → name in allowlist → args validate → egress permitted for this
    # spec → handler inside containment → result summarized + recorded. The first failure
    # produces a REFUSED result naming the check; a handler exception produces FAILED with the
    # error class, never a raise. The allowlist rung has two outcomes (§11.2); containment
    # checks isolation before paths (§11.4).

@dataclass(frozen=True, slots=True)
class ToolResult:
    invocation_id: str
    status: ToolStatus                 # OK | REFUSED | FAILED | TIMEOUT
    content: str                       # what the model sees (size-capped, labelled if truncated)
    reason: str | None                 # for REFUSED/FAILED, machine-readable; a Reason value
    reason_detail: str | None = None   # the detail §13's rows require: root and target, validator
                                       # paths, exception class, elapsed against the limit
    duration_ms: int

@dataclass(frozen=True, slots=True)
class ToolCallRecord:                  # what the store persists
    invocation_id: str
    tool_name: str
    args_json: str | None              # None when redact_args; args_sha256 always present
    args_sha256: str
    status: ToolStatus
    reason: str | None                 # §11.2: a refusal is diagnosable from the record alone
    reason_detail: str | None
    result_summary: str                # capped; full oversize output is the app's artifact
    result_sha256: str
    duration_ms: int
    risk_class: RiskClass
    egress: EgressClass
    started_at: datetime

class ToolCallStore(Protocol):
    def append(self, record: ToolCallRecord) -> None: ...

# Built-ins (each a ToolSpec + handler pair, registered explicitly, never implicitly)
read_file_tool()      # READ_ONLY, NONE  — read within read_roots ∪ write_root, size-capped
write_file_tool()     # MUTATING,  NONE  — write within write_root only; parents created inside it
list_dir_tool()       # READ_ONLY, NONE
run_command_tool(sandbox: Sandbox)
                      # MUTATING,  NONE  — argv form only (never a shell string), isolated per
                      # tier; takes the SAME sandbox instance the executor holds, so the tier the
                      # executor checked is the tier the command runs under
http_fetch_tool(allowed_hosts: Sequence[str], *, max_bytes: int = 8_388_608)
                      # READ_ONLY, NETWORK — ADR-0026 §3 checks before and during the fetch

# The closed set of machine-readable reasons a non-OK result carries (§13). A consumer maps each
# onto its own deviation category, so a reason nobody enumerated has no defined disposition:
# adding one is a MINOR change (§19) and a change consumers must be told about.
class Reason(StrEnum): ...   # exactly the reason values named in §13
REFUSAL_REASONS: Final[frozenset[str]]

# Errors (subclass baseaicore.SuiteError; raised only for CALLER bugs, never for model input)
ToolYardError            TOOLYARD_ERROR
├── DuplicateTool        TOOL_DUPLICATE
├── InvalidToolSpec      TOOL_SPEC_INVALID
└── StoreFailure         TOOL_STORE_FAILURE
```

## 8. Inputs

Tool registrations from the application at startup; per-call `ToolCallRequest`s whose name and
arguments originate from a model; the per-invocation `ToolContext`.

## 9. Outputs

`ToolResult`s (including structured refusals), `ToolCallRecord`s, wire definitions, typed errors
for caller bugs only.

## 10. Data ownership

None. The application persists records through its own `ToolCallStore` implementation and owns
retention; oversize outputs go to the application's artifact directory, referenced by hash.

## 11. Public contracts

1. **Model input never raises.** Everything a model can influence — name, arguments, output size,
   runtime — resolves to a `ToolResult`; exceptions are reserved for caller bugs
   (bad registration, broken store). A test drives every refusal path through `execute()` and
   asserts no exception escapes.
2. **Refusal order is fixed and recorded**: registry → allowlist → schema → egress → containment.
   The reason names the first failed check, so a refusal is diagnosable from the record alone.
   The allowlist rung has **two outcomes**: `not_allowlisted` for a name outside the trajectory
   allowlist, never re-approvable because that allowlist is the caller's; and `not_approved` for a
   name inside it but outside this invocation's `approved_tools`, which the application can
   resolve by approving a superseding set and retrying. The trajectory refusal is reported first —
   telling a model its call merely needs approval, when no approval could ever grant it, invites a
   re-approval that can only fail. The effective set is the **intersection** of the two and can
   therefore only narrow: an intersection has no widening case to get wrong. A call outside the
   turn's set is refused rather than allowed and reported afterwards, so the side effect has not
   happened and a scoped re-approval can still grant it.
3. **Containment is resolution-then-check**: every path is fully resolved (symlinks, `..`,
   relative components) before comparison against the roots; write containment and read
   containment are separate checks against separate roots. Comparison is by **path ancestry**,
   never by string prefix, so `/data` and `/database` are two roots; a relative candidate resolves
   against `write_root` and never the process working directory, which is wherever the application
   happened to start. The executor resolves every argument a spec declares in `path_args` **before
   the handler runs, and substitutes the resolved path into the arguments the handler receives**,
   so a handler operates on a resolved path and never re-resolves a candidate — resolution-then-
   check and the TOCTOU mitigation in one move. Only top-level arguments the schema types as
   `string` may be declared; a nested path argument is deliberately not expressible, because an
   argument the executor cannot see is one it cannot contain.
4. **Isolation never degrades silently**: any tool declaring `requires_isolation` — `run_command`
   among them — refuses with `isolation_unavailable` on a host with no container and no bwrap,
   rather than running unisolated. That is the ADR-0018 rule applied to tools, and it is a property
   of the executor rather than of one built-in. Containment checks isolation **before** paths, so a
   tool that cannot run at all on this host is refused before its arguments are resolved and a
   model is told the unfixable fact first. `requires_isolation` is a declaration, and it is
   **load-bearing**: ToolYard cannot detect a handler that reaches a subprocess without declaring
   it, and the no-`shell=True` test greps this package's own source, not application-supplied
   handlers.
5. **`http_fetch` performs the ADR-0026 §3 checks itself** — scheme http/https, host in the
   caller's allowlist (loopback only when empty), literal-IP comparison after DNS resolution,
   re-checking on every redirect hop, size cap enforced during streaming — so no consumer can
   forget them.
6. **Every call is recorded**, refused and failed calls included, with `redact_args` honoured
   (hash stored, plaintext never).
7. Wire definitions are provider-neutral and byte-stable for a given spec — they are hashed into
   PromptCadence's turn records.
8. Timeouts are mandatory; `None` means the default, never "no timeout".

## 12. Configuration

Constructor arguments only — roots, allowlists, caps, timeouts. ToolYard reads no environment and
no files (the isolation-tier probe inspects the host for container/bwrap availability; it is a
probe, not configuration). Every cap is validated at construction, so a misconfigured executor
fails at startup rather than on the one call that overflowed.

| Constant | Default | Meaning |
|---|---|---|
| `DEFAULT_TIMEOUT_SECONDS` | `30.0` | Applied when `ToolContext.timeout_seconds` is `None` |
| `DEFAULT_MAX_CONTENT_BYTES` | `65_536` | What the model sees, UTF-8 bytes |
| `DEFAULT_MAX_SUMMARY_BYTES` | `4_096` | What the record holds — a row, not an artifact |
| `DEFAULT_MAX_ARGS_JSON_BYTES` | `16_384` | Above this, `args_json` becomes a size-and-digest object |
| `MIN_CONTENT_BYTES` | `256` | Floor for any configured cap, so a truncation label always fits |

`TRUNCATION_LABEL_TEMPLATE` is part of the contract rather than a formatting detail. The guarantee
is on the **returned** string — never larger than the cap, label included — truncation cuts on a
character boundary, and the label states both byte figures, because a model that assumes a result
*ended* rather than *stopped* will answer from half a file.

## 13. Error behaviour

| Condition | `ToolResult.status` / reason |
|---|---|
| Tool not in registry | `REFUSED` / `unknown_tool` |
| Tool outside the trajectory allowlist | `REFUSED` / `not_allowlisted` — never re-approvable |
| Tool inside it, outside this invocation's `approved_tools` | `REFUSED` / `not_approved` — the application may approve a superseding set and retry |
| Arguments fail schema validation | `REFUSED` / `args_invalid`, with the validator's paths |
| Path escapes containment (after resolution) | `REFUSED` / `path_escape`, naming root and target |
| Egress tool where egress is not permitted | `REFUSED` / `egress_not_permitted` |
| No isolation tier for a tool declaring `requires_isolation` | `REFUSED` / `isolation_unavailable` |
| Fetch host/scheme/redirect/size violation | `REFUSED` / the specific ADR-0026 check |
| Handler exception | `FAILED` / exception class name (message capped, no traceback to the model) |
| Timeout | `TIMEOUT` / elapsed and limit |
| Output over the size cap | `OK` with truncated, labelled content; full output hash recorded |

`reason` is a value from the closed `Reason` set. The detail several rows above call for — the
validator's paths, the root and target of an escape, the exception class, elapsed against the limit
— travels in `reason_detail`, on the result **and** on the record: a closed reason set cannot carry
it, and §11.2 requires a refusal to be diagnosable from the record alone. A `TIMEOUT` discards the
handler's output rather than returning it, because a result the executor has declared timed out
must not reach the model as though it had not.

## 14. Security considerations

* Threat model: the arguments are attacker-controlled (prompt injection is assumed); tool results
  fed back to the model are attacker-influencing. ToolYard's job is that neither can reach the
  filesystem outside containment, the network outside the allowlist, or a shell.
* **Tool argument schemas may not use the `$ref` family** — `$ref`, `$dynamicRef`, `$id`,
  `$anchor`, `$dynamicAnchor`, `$defs`, `definitions` — refused when a `ToolSpec` is constructed.
  A `$ref` is a URI, and a validator handed an unresolved one attempts to **retrieve** it: an
  outbound fetch originating in a tool declaration, inside the package whose whole purpose is that
  egress passes one checked door. Refusing the keyword removes the door rather than guarding it.
  Format checking is left off for the same reason — a `format: "uri"` checker is another parser
  running on model-influenced input, and the checks that matter for a URL belong at the socket
  ([ADR-0026 §3](../../adr/0026-local-http-hardening.md)). Schemas must also be closed
  at every object-typed subschema carrying `properties`, so an argument nobody declared is refused
  rather than passed to a handler.
* `run_command` takes argv, never a shell string; no `shell=True` anywhere in the package (a test
  greps for it); environment passed to the child is an explicit allowlist, never `os.environ`.
* The bwrap tier unshares user/pid/net namespaces, binds `write_root` read-write, `read_roots`
  read-only, the minimal runtime read-only (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64` and a short
  named list of `/etc` entries — never `/etc` whole), and nothing else from the host.
  `run_isolated`'s `network` flag is refused in v1: no shipped tool runs a subprocess with network,
  and a door with no consumer stays shut until one is named.
* Secrets: handlers receive only `ToolContext`; nothing in ToolYard reads or forwards application
  configuration, so an API key cannot leak through a tool by construction.
* Resource limits on subprocesses — CPU time, memory, file size, process count — are rlimits
  applied **inside** the sandbox (`prlimit` under bwrap; cgroup limits plus `--ulimit` under a
  container), never by a `preexec_fn` in the application's process, which is unsafe under threads
  and, for `RLIMIT_NPROC`, is checked against the host user's task count before the namespace
  exists. A limit a rung cannot apply is named in `limits_unenforced`
  ([ADR-0016](../../adr/0016-unavailable-is-not-zero.md): an unenforceable limit is reported, not
  assumed).

## 15. Performance

| Measure | Target |
|---|---|
| Dispatch overhead (validate + authorize + record), excluding handler | ≤ 10 ms |
| Path resolution + containment check | ≤ 1 ms |
| bwrap process spin-up | ≤ 150 ms |
| Memory per invocation | O(size caps), flat |

## 16. Cross-platform

Linux tier 1: both isolation tiers available. macOS/Windows: filesystem tools and `http_fetch`
work; `run_command` refuses (`isolation_unavailable`) until a platform sandbox tier is
implemented — a refusal, never an unisolated run.

## 17. Observability

No INFO logging (library rule). DEBUG under `toolyard.*` logs call names and statuses, never
arguments or content. The `ToolCallRecord` is the observability surface; applications emit events
from it.

## 18. Test strategy

| Area | Tests |
|---|---|
| Refusal paths | Every §13 row via `execute()`, asserting result-not-exception and the recorded reason |
| Containment | Symlink escape, `..` traversal, absolute paths, prefix-collision roots (`/data` vs `/database`), write-into-read-root |
| Isolation | Tier detection; refusal with neither tier; bwrap run isolates network and filesystem (marked test on the reference machine); timeout kills the process tree |
| Fetch | Allowlisted/non-allowlisted hosts, literal IPs, redirect to a forbidden host, size cap mid-stream, non-http scheme — recorded transport, no live network |
| Schema validation | Valid, invalid, extra fields, wrong types, `additionalProperties` handling |
| Records | Redaction honoured; hashes stable; refused and failed calls recorded |
| Security | No `shell=True` (grep test); child env allowlist; no secret-shaped content in DEBUG logs |
| Determinism | Injected clock; stable wire definitions (golden) |

Coverage floor: **95 %**. The default suite passes with no container runtime and no bwrap
installed (isolation tests marked).

## 19. Compatibility and versioning

Semver, pre-1.0 `0.x`. Adding a built-in tool or a refusal reason is minor; changing the
`ToolHandler` or `ToolResult` shape is major. Wire-definition stability is golden-tested per
release.

## 20. Acceptance criteria

1. PromptCadence executes a planned trajectory whose tool calls include a refused unlisted tool, a path
   escape attempt and a successful sandboxed `run_command` — every call recorded, no exception
   reaching the loop.
2. A standalone script registers a custom tool and executes it with only `toolyard` +
   `baseaicore` installed.
3. On a host with neither container nor bwrap, `run_command` refuses and the record says why.
4. The fetch discipline passes the same test vectors LoadCoach's evidence-import fetch passes
   (shared ADR-0026 §3 cases).
5. `mypy --strict`, `ruff`, `lint-imports` clean; coverage ≥ 95 %.

## 21. Future extensions

* A macOS sandbox tier (`sandbox-exec` successor APIs) and a Windows tier (AppContainer) — new
  tiers in the same order, refusal preserved as the floor.
* Result-schema validation of tool outputs (declared but unenforced in v1 beyond size caps).
* IdeaPress `research` adoption: `http_fetch` + a citation-capturing wrapper, at that stage's ADR.
* Per-tool rate limits and quotas, when a consumer demonstrates the need.
